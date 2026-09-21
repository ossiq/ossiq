"""Tests for CVSS base-score computation.

Expected scores are published CVE scores or the specifications' own worked examples rather than
values read back off this implementation, so a wrong formula fails here, not just a changed one.
"""

from ossiq.risk.cvss import parse_cvss_base_score


class TestCvssV3BaseScore:
    def test_max_severity_network_vector_scope_unchanged(self) -> None:
        # The canonical "worst case, scope unchanged" pattern: AV:N/AC:L/PR:N/UI:N with full C/I/A.
        assert parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8

    def test_log4shell_cve_2021_44228_scope_changed(self) -> None:
        # CVE-2021-44228 (Log4Shell), published as 10.0, and the only case here that reaches the
        # scope-changed impact branch with its 7.52/3.25/^15 term.
        assert parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0

    def test_availability_only_impact_network_dos(self) -> None:
        # CVE-2021-41773-shaped Apache path traversal / DoS-only pattern, published score 7.5.
        assert parse_cvss_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5

    def test_reflected_scope_changed_partial_impact(self) -> None:
        # A reflected-XSS-shaped pattern (scope changed, partial C/I impact), published score 6.1.
        assert parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1

    def test_low_severity_local_vector(self) -> None:
        # No published CVE carries this exact vector; derived from the spec formula instead:
        # ISCbase=0.22, Impact=1.4124, Exploitability=0.33299862, sum=1.74539862, rounded up to 1.8.
        assert parse_cvss_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L") == 1.8

    def test_zero_impact_is_zero_not_none(self) -> None:
        assert parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0

    def test_missing_required_metric_is_unparseable(self) -> None:
        assert parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/S:U/C:H/I:H/A:H") is None  # no UI

    def test_unrecognised_metric_value_is_unparseable(self) -> None:
        assert parse_cvss_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None

    def test_leading_trailing_whitespace_is_tolerated(self) -> None:
        assert parse_cvss_base_score("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ") == 9.8


class TestCvssV2BaseScore:
    def test_spec_worked_example_full_compromise(self) -> None:
        # The CVSS v2 guide's own canonical "complete compromise" worked example -> 10.0.
        assert parse_cvss_base_score("AV:N/AC:L/Au:N/C:C/I:C/A:C") == 10.0

    def test_spec_worked_example_availability_only(self) -> None:
        # The CVSS v2 guide's own worked example (CVE-2002-0392-shaped) -> 7.8.
        assert parse_cvss_base_score("AV:N/AC:L/Au:N/C:N/I:N/A:C") == 7.8

    def test_zero_impact_is_zero(self) -> None:
        assert parse_cvss_base_score("AV:N/AC:L/Au:N/C:N/I:N/A:N") == 0.0

    def test_missing_required_metric_is_unparseable(self) -> None:
        assert parse_cvss_base_score("AV:N/AC:L/C:N/I:N/A:N") is None  # no Au


class TestUnsupportedOrInvalidInput:
    def test_cvss_v4_is_unsupported(self) -> None:
        v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert parse_cvss_base_score(v4) is None

    def test_unrecognised_future_cvss_version_is_unparseable_not_a_crash(self) -> None:
        assert parse_cvss_base_score("CVSS:5.0/AV:N/AC:L") is None

    def test_plain_garbage_string(self) -> None:
        assert parse_cvss_base_score("not a cvss vector at all") is None

    def test_empty_string(self) -> None:
        assert parse_cvss_base_score("") is None

    def test_bare_number_is_not_treated_as_a_vector(self) -> None:
        # Callers try float() before reaching here (see CveApiOsv.map_cve_severity), so a bare
        # number needs no special case of its own.
        assert parse_cvss_base_score("9.8") is None
