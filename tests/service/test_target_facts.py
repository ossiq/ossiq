"""Tests for service/project/target_facts.py — the single writer of the compatibility cluster.

Also asserts the second call site (apply_recommendations, the transitive path) goes through it,
since "one writer per derived field" only holds if both callers actually share the function.
"""

from unittest.mock import MagicMock

from ossiq.domain.common import (
    ConstraintType,
    EngineContext,
    EngineContextSource,
    ModuleSystem,
    ProjectPackagesRegistry,
    RecommendationRung,
)
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.recommendations import apply_recommendations
from ossiq.service.project.target_facts import annotate_target_facts, clear_target_facts
from ossiq.solver.dependencies_solver import SolverOutput

NPM = ProjectPackagesRegistry.NPM
CONSTRAINT_SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json")
NO_DIFF = VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST")


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


def make_record(name: str = "pkg", installed: str = "4.0.0") -> ScanRecord:
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
    )


class TestAnnotateTargetFacts:
    def test_writes_the_whole_cluster(self) -> None:
        record = make_record()
        releases = [pv("5.0.0", ModuleSystem.ESM_ONLY, {"node": ">=22.0.0"})]

        annotate_target_facts(
            record,
            "5.0.0",
            releases,
            NPM,
            engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED),
            project_declares_esm=False,
        )

        assert record.compatibility.recommended_module_system == ModuleSystem.ESM_ONLY
        assert record.compatibility.breaking_change == "ESM-only from 5.0.0"
        assert record.compatibility.engine_requirement == {"node": ">=22.0.0"}
        assert record.compatibility.engine_compatible is False

    def test_the_context_source_is_not_copied_onto_the_record(self) -> None:
        """Provenance is one fact about the scan, so ScanResult owns it. It used to be written here
        onto every record too, and the copies drifted - one scan reported "detected" on actionable
        records and "none" on the rest."""
        record = make_record()

        annotate_target_facts(
            record,
            "5.0.0",
            [pv("5.0.0")],
            NPM,
            engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED),
            project_declares_esm=False,
        )

        assert not hasattr(record, "engine_context_source")

    def test_no_break_when_the_project_itself_declares_esm(self) -> None:
        record = make_record()
        releases = [pv("5.0.0", ModuleSystem.ESM_ONLY)]

        annotate_target_facts(
            record,
            "5.0.0",
            releases,
            NPM,
            engine_context=EngineContext({}, EngineContextSource.NONE),
            project_declares_esm=True,
        )

        assert record.compatibility.recommended_module_system == ModuleSystem.ESM_ONLY
        assert record.compatibility.breaking_change is None

    def test_empty_engine_context_is_no_evidence_either_way(self) -> None:
        record = make_record()

        annotate_target_facts(
            record,
            "5.0.0",
            [pv("5.0.0", runtime_requirements={"node": ">=22.0.0"})],
            NPM,
            engine_context=EngineContext({}, EngineContextSource.NONE),
            project_declares_esm=False,
        )

        assert record.compatibility.engine_compatible is None

    def test_target_absent_from_releases_leaves_no_engine_requirement(self) -> None:
        record = make_record()

        annotate_target_facts(
            record,
            "9.9.9",
            [pv("5.0.0", runtime_requirements={"node": ">=22.0.0"})],
            NPM,
            engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED),
            project_declares_esm=False,
        )

        assert record.compatibility.engine_requirement is None
        assert record.compatibility.engine_compatible is None


class TestClearTargetFacts:
    def test_resets_every_field(self) -> None:
        record = make_record()
        record.compatibility.recommended_module_system = ModuleSystem.ESM_ONLY
        record.compatibility.breaking_change = "ESM-only from 5.0.0"
        record.compatibility.engine_requirement = {"node": ">=22.0.0"}
        record.compatibility.engine_compatible = False

        clear_target_facts(record)

        assert record.compatibility.recommended_module_system is None
        assert record.compatibility.breaking_change is None
        assert record.compatibility.engine_requirement is None
        assert record.compatibility.engine_compatible is None


class TestApplyRecommendationsUsesTheSameWriter:
    """The transitive path: apply_recommendations must produce the same cluster
    apply_update_strategy produces for a direct record on the same evidence."""

    def test_transitive_record_gets_the_cluster(self) -> None:
        record = make_record()
        registry = MagicMock()
        registry.package_registry = NPM
        registry.package_versions.return_value = [pv("5.0.0", ModuleSystem.ESM_ONLY, {"node": ">=22.0.0"})]

        apply_recommendations(
            [record],
            SolverOutput(recommendations={"pkg": "5.0.0"}, reasons={}),
            registry=registry,
            project_declares_esm=False,
            engine_context=EngineContext({"node": "20.11.0"}, EngineContextSource.DETECTED),
        )

        assert record.recommended_version == "5.0.0"
        assert record.recommended_from_rung == RecommendationRung.SOLVER
        assert record.compatibility.recommended_module_system == ModuleSystem.ESM_ONLY
        assert record.compatibility.breaking_change == "ESM-only from 5.0.0"
        assert record.compatibility.engine_requirement == {"node": ">=22.0.0"}
        assert record.compatibility.engine_compatible is False

    def test_no_registry_means_no_cluster(self) -> None:
        """Direct records are annotated by apply_update_strategy afterwards; doing it here too
        would just be redone work."""
        record = make_record()

        apply_recommendations([record], SolverOutput(recommendations={"pkg": "5.0.0"}, reasons={}))

        assert record.recommended_version == "5.0.0"
        assert record.compatibility.recommended_module_system is None
        assert record.compatibility.engine_requirement is None
