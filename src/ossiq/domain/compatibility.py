"""Where a scan record sits on the version ladder, and what is true about the version it picked."""

from dataclasses import dataclass

from ossiq.domain.common import ModuleSystem


@dataclass
class CompatibilityFacts:
    """The ladder + module-system + engine cluster, lifted off ScanRecord.

    ScanRecord had grown to ~50 flat fields and become the bottleneck for every new surface. These
    eight answer one question together - how far can this package move, and what breaks if it does -
    so they travel as one value.

    Deliberately **not** frozen: `service.project.target_facts` rewrites the target half in place
    whenever a recommendation is re-decided, exactly as it did on ScanRecord. Two writers, each
    owning disjoint fields: `service.project.records.scan_record` builds the ladder half at
    construction, `target_facts` owns the target half. One writer per field still holds.

    The JSON export keeps these flat (see `ui.renderers.export.models.LadderFields` /
    `CompatibilityFields`), so nesting here does not move anything on the wire. The domain model
    and the published contract are allowed to differ in shape; only one of them has consumers
    outside this repo.
    """

    latest_in_range: str | None = None
    """Newest installable version satisfying version_constraint. None only when undeterminable.
    Computed in service.project.ladder.compute_version_ladder; a plain registry fact, not
    solver-guarded."""

    latest_in_major: str | None = None
    """Newest installable version sharing installed_version's major line (PEP 440 epoch + first
    release segment on PyPI; semver major on npm). None only when undeterminable."""

    latest_compatible_major: str | None = None
    """Newest installable release among majors >= installed_version's major that carries no known
    break (module-system or curated API break). Diverges from latest_in_major when a clean major
    sits between installed_version and a known break."""

    module_system: ModuleSystem | None = None
    """installed_version's own module format (npm only, from `type`/`exports`). Always None on
    PyPI."""

    recommended_module_system: ModuleSystem | None = None
    """recommended_version's own module format. None whenever recommended_version is None or the
    package is on PyPI."""

    breaking_change: str | None = None
    """Human-readable reason recommended_version is flagged as a known API/module-system break,
    e.g. "ESM-only from 5.0.0"; None when no known break applies. Never blanks recommended_version
    on its own - see service.project.strategy.build_candidates's structural_gates."""

    engine_requirement: dict[str, str] | None = None
    """recommended_version's own runtime_requirements (e.g. {"node": ">=20.19.0"}). None when
    recommended_version is None or the picked release declares no engine requirement."""

    engine_compatible: bool | None = None
    """False when engine_requirement conflicts with the scan's engine context. None = no evidence
    either way (no requirement, or no context to compare against) - never implies compatibility was
    actually checked and passed just because it isn't False.

    Which source that context came from is a scan-level fact: see ScanResult.engine_context."""
