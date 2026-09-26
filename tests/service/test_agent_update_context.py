"""Unit tests for service.agent.build_update_context.

Mirrors tests/service/test_breaking_changes.py: real PackageRegistryApiPypi/PackageRegistryApiNpm
instances as the registry (their constructors do no I/O), plain PackageVersion/ScanRecord fixtures,
no mocking of the registries themselves.
"""

from __future__ import annotations

import dataclasses
import json

from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.domain.common import (
    ConstraintType,
    EngineContext,
    EngineContextSource,
    ModuleSystem,
    RejectedCandidate,
)
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.agent import build_update_context
from ossiq.service.package import PackageDetailResult
from ossiq.service.project.models import ScanRecord
from ossiq.settings import Settings

PYPI = PackageRegistryApiPypi(Settings())
NPM = PackageRegistryApiNpm(Settings())

NO_DIFF = VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST")
CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json")


def pv(
    version: str,
    module_system: ModuleSystem | None = None,
    runtime_requirements: dict[str, str] | None = None,
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso="2024-01-01T00:00:00Z",
        module_system=module_system,
        runtime_requirements=runtime_requirements,
    )


# The ladder/module-system/engine cluster is a nested value object; keeping the call sites' flat
# kwargs means this split happens once here rather than in every test.
COMPATIBILITY_FIELDS = {f.name for f in dataclasses.fields(CompatibilityFacts)}


def make_record(name: str = "pkg", installed: str = "1.0.0", **flags) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version=None,
        versions_diff_index=NO_DIFF,
        time_lag_days=None,
        releases_lag=0,
        cve=[],
        constraint_info=CONSTRAINT_SOURCE,
        compatibility=CompatibilityFacts(**{k: flags.pop(k) for k in list(flags) if k in COMPATIBILITY_FIELDS}),
        **flags,
    )


def make_installed_detail(record: ScanRecord) -> PackageDetailResult:
    return PackageDetailResult(
        records=[record],
        transitive_cve_groups=[],
        project_name="proj",
        packages_registry="NPM",
        is_prospective=False,
    )


def make_prospective_detail(name: str = "newpkg") -> PackageDetailResult:
    return PackageDetailResult(
        records=[],
        transitive_cve_groups=[],
        project_name="proj",
        packages_registry="NPM",
        is_prospective=True,
        prospective_name=name,
    )


def test_returns_error_when_no_target_and_no_recommendation():
    record = make_record(name="pkg", installed="1.0.0", recommended_version=None)
    detail = make_installed_detail(record)

    payload = build_update_context(
        detail,
        target_version=None,
        releases=[],
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload == {"package": "pkg", "error": "no recommendation available; pass target_version explicitly"}


def test_falls_back_to_recommended_version_when_target_omitted():
    record = make_record(name="pkg", installed="1.0.0", recommended_version="1.1.0")
    detail = make_installed_detail(record)

    payload = build_update_context(
        detail,
        target_version=None,
        releases=[pv("1.1.0")],
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload["to_version"] == "1.1.0"
    assert payload["from_version"] == "1.0.0"


def test_chalk_shaped_breaking_change_and_module_system():
    record = make_record(name="chalk", installed="4.1.2", module_system=ModuleSystem.CJS)
    detail = make_installed_detail(record)
    releases = [
        pv("4.1.2", module_system=ModuleSystem.CJS),
        pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
        pv("6.0.0", module_system=ModuleSystem.ESM_ONLY),
    ]

    payload = build_update_context(
        detail,
        target_version="6.0.0",
        releases=releases,
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload["module_system"] == {"from": "cjs", "to": "esm-only", "project_declares_esm": False}
    assert payload["breaking_change"] == "ESM-only from 6.0.0"


def test_project_declares_esm_suppresses_breaking_change():
    record = make_record(name="chalk", installed="4.1.2", module_system=ModuleSystem.CJS)
    detail = make_installed_detail(record)
    releases = [pv("4.1.2", module_system=ModuleSystem.CJS), pv("6.0.0", module_system=ModuleSystem.ESM_ONLY)]

    payload = build_update_context(
        detail,
        target_version="6.0.0",
        releases=releases,
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=True,
    )

    assert payload["breaking_change"] is None
    assert payload["module_system"]["project_declares_esm"] is True


def test_target_not_found_still_computes_breaking_change_from_major_bucket():
    record = make_record(name="chalk", installed="4.1.2", module_system=ModuleSystem.CJS)
    detail = make_installed_detail(record)
    # 6.0.5 is never published, but major 6 is still flagged breaking via 6.0.0.
    releases = [pv("4.1.2", module_system=ModuleSystem.CJS), pv("6.0.0", module_system=ModuleSystem.ESM_ONLY)]

    payload = build_update_context(
        detail,
        target_version="6.0.5",
        releases=releases,
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload["module_system"]["to"] is None
    assert payload["breaking_change"] == "ESM-only from 6.0.0"
    assert payload["engine"]["requirement"] is None


def test_engine_incompatible_when_target_requires_newer_node():
    record = make_record(name="some-pkg", installed="1.0.0")
    detail = make_installed_detail(record)
    releases = [pv("1.1.0", runtime_requirements={"node": ">=20.19.0"})]

    payload = build_update_context(
        detail,
        target_version="1.1.0",
        releases=releases,
        registry=NPM,
        engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED),
        project_declares_esm=False,
    )

    assert payload["engine"] == {
        "requirement": {"node": ">=20.19.0"},
        "context_version": "20.11.0",
        "context_source": "detected",
        "compatible": False,
    }


def test_engine_key_selection_ignores_unrelated_registry_key():
    """A mixed-toolchain engine_context (both node and python) should only surface the key
    relevant to the queried package's own registry."""
    record = make_record(name="some-pkg", installed="1.0.0")
    detail = make_installed_detail(record)
    releases = [pv("1.1.0", runtime_requirements={"node": ">=18.0.0"})]

    payload = build_update_context(
        detail,
        target_version="1.1.0",
        releases=releases,
        registry=NPM,
        engine_context=EngineContext({"node": "20.11.0", "python": "3.11.4"}, EngineContextSource.DETECTED),
        project_declares_esm=False,
    )

    assert payload["engine"]["context_version"] == "20.11.0"


def test_pypi_registry_uses_python_engine_key():
    record = make_record(name="pydantic", installed="1.10.13")
    detail = make_installed_detail(record)
    releases = [pv("2.13.5", runtime_requirements={"python": ">=3.9"})]

    payload = build_update_context(
        detail,
        target_version="2.13.5",
        releases=releases,
        registry=PYPI,
        engine_context=EngineContext({"node": "20.11.0", "python": "3.11.4"}, EngineContextSource.DETECTED),
        project_declares_esm=False,
    )

    assert payload["engine"]["context_version"] == "3.11.4"


def test_rejected_candidates_filtered_up_to_target():
    record = make_record(
        name="pkg",
        installed="1.0.0",
        rejected_candidates=[
            RejectedCandidate(version="3.0.0", reason="reason a"),
            RejectedCandidate(version="7.0.0", reason="reason b"),
        ],
    )
    detail = make_installed_detail(record)

    payload = build_update_context(
        detail,
        target_version="5.0.0",
        releases=[pv("5.0.0")],
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload["rejected_candidates"] == [{"version": "3.0.0", "reason": "reason a"}]


def test_prospective_package_from_version_null_and_latest_compatible_major_recomputed():
    detail = make_prospective_detail(name="newpkg")
    releases = [pv("1.0.0", module_system=ModuleSystem.CJS), pv("2.0.0", module_system=ModuleSystem.CJS)]

    payload = build_update_context(
        detail,
        target_version="2.0.0",
        releases=releases,
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload["from_version"] is None
    assert payload["rejected_candidates"] == []
    assert payload["latest_compatible_major"] == "2.0.0"


def test_rollback_target_older_than_installed_is_not_rejected_by_construction():
    """releases is the full, unfiltered list (not floored at installed) - a rollback target must
    resolve without special-casing."""
    record = make_record(name="pkg", installed="2.0.0", module_system=ModuleSystem.CJS)
    detail = make_installed_detail(record)
    releases = [pv("1.0.0", module_system=ModuleSystem.CJS), pv("2.0.0", module_system=ModuleSystem.CJS)]

    payload = build_update_context(
        detail,
        target_version="1.0.0",
        releases=releases,
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload["to_version"] == "1.0.0"
    assert payload["breaking_change"] is None


def test_inferior_deprecated_target_is_compared_against_the_recommendation():
    """D2 reproduction: an agent proposed uuid 9.0.1 (npm-deprecated) and got back
    `breaking_change: null, rejected_candidates: []`, which reads as approval, while OSS IQ's own
    recommendation was a different version."""
    record = make_record(
        name="uuid",
        installed="8.3.2",
        recommended_version="11.1.1",
        latest_compatible_major="14.0.2",
        module_system=ModuleSystem.DUAL,
    )
    deprecated_target = dataclasses.replace(pv("9.0.1", module_system=ModuleSystem.DUAL), is_deprecated=True)

    payload = build_update_context(
        make_installed_detail(record),
        target_version="9.0.1",
        releases=[pv("8.3.2", ModuleSystem.DUAL), deprecated_target, pv("11.1.1", ModuleSystem.DUAL)],
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    # Field names are a Milestone 2 decision; only require that the payload says so somewhere.
    rendered = json.dumps(payload).lower()
    assert "11.1.1" in rendered
    assert "deprecated" in rendered


def test_the_recommendation_is_judged_recommended():
    record = make_record(name="uuid", installed="8.3.2", recommended_version="11.1.1", module_system=ModuleSystem.DUAL)

    payload = build_update_context(
        make_installed_detail(record),
        target_version=None,
        releases=[pv("8.3.2", ModuleSystem.DUAL), pv("11.1.1", ModuleSystem.DUAL)],
        registry=NPM,
        engine_context=EngineContext({}, EngineContextSource.NONE),
        project_declares_esm=False,
    )

    assert payload["comparison"] == {
        "verdict": "recommended",
        "reasons": [],
        "recommended_version": "11.1.1",
        "better_available": None,
    }


def test_an_esm_only_target_carries_the_runtime_note():
    record = make_record(name="chalk", installed="4.1.2", recommended_version=None, module_system=ModuleSystem.CJS)

    payload = build_update_context(
        make_installed_detail(record),
        target_version="6.0.0",
        releases=[pv("4.1.2", ModuleSystem.CJS), pv("6.0.0", ModuleSystem.ESM_ONLY)],
        registry=NPM,
        engine_context=EngineContext({"node": "26.8.1"}, EngineContextSource.PROVIDED),
        project_declares_esm=False,
    )

    assert payload["comparison"]["verdict"] == "breaking"
    assert payload["breaking_change"] == "ESM-only from 6.0.0"
    assert "named exports" in payload["module_system_note"]
