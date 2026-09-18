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


def detect_engine_context(
    project_info: Project,
    project_path: str,
    *,
    probe_runtime: bool,
) -> tuple[EngineContext, str | None]:
    """Resolve the runtime versions to check engine requirements against.

    An actually-installed runtime beats the manifest's declared floor: the floor says what the
    project claims to support, the probe says what it will really run on, and the gap between them
    is the thing worth reporting.

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
            if version := detect_actual_node_version():
                detected[ENGINE_CONTEXT_KEY_BY_REGISTRY[ProjectPackagesRegistry.NPM]] = version
            npm_cli_version = detect_actual_npm_cli_version()

    declared = project_info.engine_constraints or {}
    if detected:
        return EngineContext(versions=detected, source=EngineContextSource.DETECTED), npm_cli_version
    if declared:
        return EngineContext(versions=dict(declared), source=EngineContextSource.DECLARED), npm_cli_version
    return EngineContext(), npm_cli_version
