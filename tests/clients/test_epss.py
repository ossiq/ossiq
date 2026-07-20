"""
Tests for EpssBatchStrategy (ossiq.clients.client_epss) and
EpssApiClient (ossiq.adapters.api_epss).
"""

from unittest.mock import MagicMock, patch

from ossiq.adapters.api_epss import EpssApiClient
from ossiq.clients.batch import BatchClient, ChunkResult
from ossiq.clients.client_epss import EpssBatchStrategy


def make_chunk_result(data: list[dict]) -> ChunkResult:
    return ChunkResult(data=[{"data": data}], success=True)


class TestPrepareItem:
    def test_cve_prefixed_id_returned_unchanged(self):
        strategy = EpssBatchStrategy(MagicMock())
        assert strategy.prepare_item("CVE-2022-26332") == "CVE-2022-26332"

    def test_non_cve_id_is_dropped(self):
        """first.org doesn't understand GHSA ids - prepare_item signals drop with None."""
        strategy = EpssBatchStrategy(MagicMock())
        assert strategy.prepare_item("GHSA-xxxx-0001") is None


class TestPerformRequest:
    def test_gets_epss_endpoint_with_comma_joined_cve_param(self):
        session = MagicMock()
        strategy = EpssBatchStrategy(session)

        strategy.perform_request(["CVE-2022-26332", "CVE-2023-0001"])

        call_args = session.get.call_args
        assert call_args[0][0] == strategy.BASE_URL
        assert call_args[1]["params"] == {"cve": "CVE-2022-26332,CVE-2023-0001"}

    def test_uses_configured_timeout(self):
        session = MagicMock()
        strategy = EpssBatchStrategy(session)

        strategy.perform_request(["CVE-2022-26332"])

        assert session.get.call_args[1]["timeout"] == strategy.config.request_timeout


class TestProcessResponse:
    def test_maps_cve_to_float_epss(self):
        strategy = EpssBatchStrategy(MagicMock())
        response = make_chunk_result([{"cve": "CVE-2022-26332", "epss": "0.006820000", "percentile": "0.48431"}])

        result = strategy.process_response(["CVE-2022-26332"], response)

        assert result == {"CVE-2022-26332": 0.006820000}
        assert isinstance(result["CVE-2022-26332"], float)

    def test_cve_missing_from_response_is_absent_not_error(self):
        """first.org omits CVEs it has no score for - that's not an error condition."""
        strategy = EpssBatchStrategy(MagicMock())
        response = make_chunk_result([{"cve": "CVE-2022-26332", "epss": "0.5", "percentile": "0.9"}])

        result = strategy.process_response(["CVE-2022-26332", "CVE-2099-9999"], response)

        assert result == {"CVE-2022-26332": 0.5}


class TestEpssApiClient:
    def test_empty_input_returns_empty_dict(self):
        client = EpssApiClient(MagicMock())

        with patch.object(BatchClient, "run_batch") as mock_run:
            result = client.get_epss_batch([])

        assert result == {}
        mock_run.assert_not_called()

    def test_dedupes_and_sorts_before_batching(self):
        """Stable chunk composition maximizes requests_cache hits across scans."""
        client = EpssApiClient(MagicMock())

        with patch.object(BatchClient, "run_batch", return_value=iter([])) as mock_run:
            client.get_epss_batch(["CVE-2023-0002", "CVE-2023-0001", "CVE-2023-0002"])

        mock_run.assert_called_once_with(["CVE-2023-0001", "CVE-2023-0002"])

    def test_merges_results_across_chunks(self):
        client = EpssApiClient(MagicMock())
        chunk_a = {"CVE-2023-0001": 0.1}
        chunk_b = {"CVE-2023-0002": 0.2}

        with patch.object(BatchClient, "run_batch", return_value=iter([chunk_a, chunk_b])):
            result = client.get_epss_batch(["CVE-2023-0001", "CVE-2023-0002"])

        assert result == {"CVE-2023-0001": 0.1, "CVE-2023-0002": 0.2}
