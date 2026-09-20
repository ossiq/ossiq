"""Which runtime the scanned project will actually run on.

Wires `adapters.runtime_environment`'s probes onto a project's declared engine constraints. Lives
here rather than inline in `scan()` so "a PyPI project spawns no node probe" is directly testable
without running a whole scan.
"""

from ossiq.adapters.runtime_environment import (
    detect_actual_node_version,
    detect_actual_npm_cli_version,
    detect_actual_python_version,
)
from ossiq.domain.common import (
    ENGINE_CONTEXT_KEY_BY_REGISTRY,
    EngineContext,
    EngineContextSource,
    ProjectPackagesRegistry,
)
from ossiq.domain.project import Project
from ossiq.solver.version_matchers import stricter_engine_floor


def detect_engine_context(
    project_info: Project,
    project_path: str,
    *,
    probe_runtime: bool,
) -> tuple[EngineContext, str | None]:
    """Resolve the runtime versions to check engine requirements against.

    Probe and manifest floor are not alternatives: an engine requirement has to hold for *every*
    version the project claims to support, so each engine is held to the stricter of the two. A
    probe that replaced the floor outright hid the common case — a developer on Python 3.13 whose
    package still promises 3.11 — until `uv` refused to resolve the update it had recommended.

    Probes are gated on the project's registry. `probe_runtime` used to spawn the Python probe,
    `node --version` and `npm --version` on every scan regardless - up to three subprocesses at
    PROBE_TIMEOUT each on a pure-PyPI project, for two answers nothing could use.
    `Project.engine_constraints` is already registry-specific, so the probes now match it.

    Args:
        project_info: The scanned project, for its declared engine constraints and registry.
        project_path: Used by the Python probe to find this project's own virtualenv.
        probe_runtime: Whether to shell out at all (--probe-runtime / --no-probe-runtime).

    Returns:
        The engine context, and the detected npm CLI version (display-only, npm projects only).
    """
    registry = project_info.package_registry
    detected: dict[str, str] = {}
    npm_cli_version: str | None = None

    if probe_runtime:
        if registry == ProjectPackagesRegistry.PYPI:
            if version := detect_actual_python_version(project_path):
                detected[ENGINE_CONTEXT_KEY_BY_REGISTRY[ProjectPackagesRegistry.PYPI]] = version
        elif registry == ProjectPackagesRegistry.NPM:
            npm_cli_version = detect_actual_npm_cli_version()
            if npm_cli_version:
                detected["npm"] = npm_cli_version
            if version := detect_actual_node_version():
                detected[ENGINE_CONTEXT_KEY_BY_REGISTRY[ProjectPackagesRegistry.NPM]] = version

    enforced = dict(detected)
    floor_binds = False
    for engine_key, floor in (project_info.engine_constraints or {}).items():
        probed = enforced.get(engine_key)
        binding = floor if probed is None else stricter_engine_floor(engine_key, probed, floor)
        enforced[engine_key] = binding
        floor_binds = floor_binds or binding != probed

    if not enforced:
        return EngineContext(), npm_cli_version
    source = EngineContextSource.DECLARED if floor_binds else EngineContextSource.DETECTED
    return EngineContext(versions=enforced, source=source), npm_cli_version
