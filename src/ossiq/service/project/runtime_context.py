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
    ProvidedRuntime,
    RuntimeMismatch,
)
from ossiq.domain.exceptions import InvalidRuntime, RuntimeNotProvided
from ossiq.domain.project import Project
from ossiq.settings import Settings
from ossiq.solver.version_matchers import stricter_engine_floor
from ossiq.sources.runtime_pins import pin_matches, read_runtime_pin


def detect_engine_context(
    project_info: Project,
    project_path: str,
    *,
    probe_runtime: bool,
    provided: ProvidedRuntime | None = None,
) -> tuple[EngineContext, str | None]:
    """Resolve the runtime versions to check engine requirements against.

    Runtime and manifest floor are not alternatives: an engine requirement has to hold for *every*
    version the project claims to support, so each engine is held to the stricter of the two. A
    runtime that replaced the floor outright hid the common case — a developer on Python 3.13 whose
    package still promises 3.11 — until `uv` refused to resolve the update it had recommended.

    The runtime comes from the caller when it states one (`provided`), and from a probe otherwise.
    A stated runtime replaces the probe entirely rather than joining it: the probe answers for
    whatever PATH this process inherited, which for an MCP server is not the shell the project's
    tests run in, and that difference alone flipped recommendations between identical requests.

    Probes are gated on the project's registry. `probe_runtime` used to spawn the Python probe,
    `node --version` and `npm --version` on every scan regardless - up to three subprocesses at
    PROBE_TIMEOUT each on a pure-PyPI project, for two answers nothing could use.
    `Project.engine_constraints` is already registry-specific, so the probes now match it.

    Args:
        project_info: The scanned project, for its declared engine constraints and registry.
        project_path: Used by the Python probe to find this project's own virtualenv.
        probe_runtime: Whether to shell out at all (--probe-runtime / --no-probe-runtime). Ignored
            when `provided` is given.
        provided: The runtime the caller states the project runs on, or an explicit "unknown".

    Returns:
        The engine context, and the detected npm CLI version (display-only, npm projects only).

    Raises:
        InvalidRuntime: `provided` names an engine this project's registry doesn't use.
    """
    registry = project_info.package_registry
    runtime: dict[str, str] = {}
    npm_cli_version: str | None = None
    runtime_source = EngineContextSource.DETECTED

    if provided is not None:
        runtime_source = EngineContextSource.PROVIDED
        runtime = provided_versions(provided, registry)
    elif probe_runtime:
        if registry == ProjectPackagesRegistry.PYPI:
            if version := detect_actual_python_version(project_path):
                runtime[ENGINE_CONTEXT_KEY_BY_REGISTRY[ProjectPackagesRegistry.PYPI]] = version
        elif registry == ProjectPackagesRegistry.NPM:
            npm_cli_version = detect_actual_npm_cli_version()
            if npm_cli_version:
                runtime["npm"] = npm_cli_version
            if version := detect_actual_node_version():
                runtime[ENGINE_CONTEXT_KEY_BY_REGISTRY[ProjectPackagesRegistry.NPM]] = version

    enforced = dict(runtime)
    floor_binds = False
    for engine_key, floor in (project_info.engine_constraints or {}).items():
        stated = enforced.get(engine_key)
        binding = floor if stated is None else stricter_engine_floor(engine_key, stated, floor)
        enforced[engine_key] = binding
        floor_binds = floor_binds or binding != stated

    if not enforced:
        return EngineContext(), npm_cli_version
    source = EngineContextSource.DECLARED if floor_binds else runtime_source
    return EngineContext(versions=enforced, source=source), npm_cli_version


def provided_versions(provided: ProvidedRuntime, registry: ProjectPackagesRegistry) -> dict[str, str]:
    """Validate a caller-stated runtime against the project's registry and return its versions.

    `npm` rides along with `node` on npm projects, as the probe does. An explicit "unknown"
    contributes nothing, leaving only the manifest floor.

    Raises:
        InvalidRuntime: A key the registry doesn't use (`python` on an npm project), or an empty
            version.
    """
    if provided.unknown:
        return {}
    allowed = {"node", "npm"} if registry == ProjectPackagesRegistry.NPM else {"python"}
    unexpected = sorted(set(provided.versions) - allowed)
    if unexpected:
        raise InvalidRuntime(
            f"runtime key(s) {', '.join(unexpected)} don't apply to a {registry.value.lower()} project"
        )
    empty = sorted(key for key, version in provided.versions.items() if not str(version).strip())
    if empty:
        raise InvalidRuntime(f"runtime version for {', '.join(empty)} is empty")
    return {key: str(version).strip().removeprefix("v") for key, version in provided.versions.items()}


def runtime_pin_mismatch(
    project_path: str, registry: ProjectPackagesRegistry, engine_context: EngineContext
) -> RuntimeMismatch | None:
    """Compare the project's own runtime pin with the runtime the scan ran against.

    Only a provided or probed runtime is compared: when the manifest floor binds, the context holds
    the oldest version the project supports, which is meant to differ from what its developers run.
    """
    if engine_context.source not in (EngineContextSource.PROVIDED, EngineContextSource.DETECTED):
        return None
    pin = read_runtime_pin(project_path, registry)
    if pin is None:
        return None
    runtime = engine_context.versions.get(pin.engine)
    if runtime is None or pin_matches(pin.version, runtime):
        return None
    return RuntimeMismatch(
        engine=pin.engine,
        pinned=pin.version,
        pin_file=pin.pin_file,
        runtime=runtime,
        runtime_source=engine_context.source,
    )


def provided_runtime_from_settings(settings: Settings) -> ProvidedRuntime | None:
    """The caller-stated runtime carried on Settings (`--engine`, MCP `runtime`), or None to probe."""
    if settings.runtime_unknown:
        return ProvidedRuntime(unknown=True)
    if settings.engine_versions:
        return ProvidedRuntime(versions=dict(settings.engine_versions))
    return None


def settings_with_stated_runtime(settings: Settings, runtime: object) -> Settings:
    """Return *settings* carrying a caller-stated runtime, with the PATH probe switched off.

    The MCP front door requires a runtime rather than probing: a probe from the server's own
    process answers for the wrong shell, and a silent fallback to it is exactly what made two
    identical requests disagree. Asking costs an agent one round-trip it can answer from memory.

    Args:
        settings: The server's settings.
        runtime: The tool argument: an object such as `{"node": "22.12.0"}`, or `"unknown"`.

    Returns:
        A copy of *settings* with `probe_runtime` off and the stated runtime set.

    Raises:
        RuntimeNotProvided: `runtime` is missing or not an object / `"unknown"`.
    """
    if isinstance(runtime, str) and runtime.strip().lower() == "unknown":
        return settings.model_copy(update={"probe_runtime": False, "runtime_unknown": True, "engine_versions": {}})
    if isinstance(runtime, dict) and runtime:
        versions = {str(key): str(value) for key, value in runtime.items()}
        return settings.model_copy(
            update={"probe_runtime": False, "runtime_unknown": False, "engine_versions": versions}
        )
    raise RuntimeNotProvided("`runtime` is required")
