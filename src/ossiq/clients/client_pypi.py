"""
Pre-configured HTTP session and batch strategy for the PyPI registry API.
"""

from html.parser import HTMLParser

import requests
from packaging.utils import canonicalize_name

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult

PYPI_REGISTRY = "https://pypi.org/pypi"
PYPI_SIMPLE = "https://pypi.org/simple"

PROJECT_STATUS_HEAD_BYTES = 2048
"""How much of a Simple API page the PEP 792 status request reads. The status lives in `<head>`,
a few hundred bytes in, while a whole page lists every file of the project (numpy's is 2 MB)."""


class PypiBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for the PyPI registry.

    Since PyPI has no bulk info endpoint, chunk_size=1 fetches packages
    individually but in parallel across max_workers threads.

    prepare_item  : package name string (identity — used as key in process_response)
    perform_request: GET /{name}/json
    process_response: returns {name: raw_registry_json}
    """

    BASE_URL = PYPI_REGISTRY

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: str) -> str:
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        name = chunk[0]
        return self.session.get(f"{self.BASE_URL}/{name}/json", timeout=self.config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, dict]:  # noqa: ARG002
        return {source_items[0]: response.data[0]}


class PypiVersionBatchStrategy(BatchStrategy):
    """Fetches requires_dist for specific (name, version) pairs from PyPI."""

    BASE_URL = PYPI_REGISTRY

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: tuple[str, str]) -> tuple[str, str]:
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        name, version = chunk[0]
        return self.session.get(
            f"{self.BASE_URL}/{name}/{version}/json",
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list, response: ChunkResult) -> dict:
        name, version = source_items[0]
        info = response.data[0].get("info", {}) if response.data else {}
        return {(name, version): info.get("requires_dist") or []}


class ProjectStatusParser(HTMLParser):
    """Collects PEP 792's `pypi:project-status` meta tags from the head of a Simple API page."""

    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, str] = {}
        self.head_closed = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta" or self.head_closed:
            return
        values = dict(attrs)
        content = values.get("content")
        if content is None:
            return
        if values.get("name") == "pypi:project-status":
            self.fields["status"] = content
        elif values.get("name") == "pypi:project-status-reason":
            self.fields["reason"] = content

    def handle_endtag(self, tag: str) -> None:
        if tag == "head":
            self.head_closed = True


def parse_project_status(head: str) -> dict[str, str]:
    """Read the PEP 792 project status out of a Simple API page head.

    Args:
        head: The start of a `application/vnd.pypi.simple.v1+html` project page.

    Returns:
        `{"status": ..., "reason": ...}` with `reason` only when given, shaped like the JSON
        form's `project-status` object. Empty when the page declares no status, which PEP 792
        allows for an active project.
    """
    parser = ProjectStatusParser()
    parser.feed(head)
    return parser.fields


class PypiProjectStatusBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for PEP 792 project status.

    The legacy JSON API the other strategies use carries no project status; only the Simple API
    does. That page also lists every file of the project, so only its head is requested.

    prepare_item   : package name string (identity — used as key in process_response)
    perform_request: ranged GET /simple/{name}/
    process_response: returns {name: {"status": ..., "reason"?: ...}}
    """

    BASE_URL = PYPI_SIMPLE

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            # Each response is about a kilobyte, so a wider fan-out than the JSON strategies costs nothing.
            max_workers=10,
            request_timeout=15.0,
        )

    def prepare_item(self, item: str) -> str:
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        name = canonicalize_name(chunk[0])
        return self.session.get(
            f"{self.BASE_URL}/{name}/",
            headers={
                "Accept": "application/vnd.pypi.simple.v1+html",
                "Range": f"bytes=0-{PROJECT_STATUS_HEAD_BYTES - 1}",
                # A byte range applies to the encoded body, and a gzip fragment cannot be parsed.
                "Accept-Encoding": "identity",
            },
            timeout=self.config.request_timeout,
        )

    def decode_response(self, resp: requests.Response) -> str:
        # Slice rather than trust the 206: a server that ignores Range sends the whole page.
        return resp.content[:PROJECT_STATUS_HEAD_BYTES].decode("utf-8", "replace")

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, dict[str, str]]:  # noqa: ARG002
        return {source_items[0]: parse_project_status(response.data[0])}


__all__ = ("BatchClient", "PypiBatchStrategy", "PypiVersionBatchStrategy")
