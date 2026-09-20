"""The runtime probes are ecosystem-gated: a pure-PyPI scan must never shell out to node/npm.

Before this, --probe-runtime (on by default) spawned the Python probe, `node --version` and
`npm --version` on every scan regardless of registry - up to three subprocesses at PROBE_TIMEOUT
each, two of which nothing could use.
"""

from unittest.mock import patch

import pytest

from ossiq.domain.common import EngineContextSource, ProjectPackagesRegistry
from ossiq.domain.packages_manager import NPM, UV
from ossiq.domain.project import Dependency, Project
from ossiq.service.project.runtime_context import detect_engine_context


def make_project(registry: ProjectPackagesRegistry, engine_constraints: dict[str, str] | None = None) -> Project:
    return Project(
        package_manager_type=UV if registry == ProjectPackagesRegistry.PYPI else NPM,
        name="demo",
        project_path=".",
        dependency_tree=Dependency(name="demo", canonical_name="demo", version_installed=""),
        engine_constraints=engine_constraints,
    )


@pytest.fixture
def probes():
    """Patch all three probes at their point of use, so a call is observable without a subprocess."""
    with (
        patch("ossiq.service.project.runtime_context.detect_actual_python_version") as python_probe,
        patch("ossiq.service.project.runtime_context.detect_actual_node_version") as node_probe,
        patch("ossiq.service.project.runtime_context.detect_actual_npm_cli_version") as npm_probe,
    ):
        python_probe.return_value = "3.12.1"
        node_probe.return_value = "20.11.0"
        npm_probe.return_value = "10.2.4"
        yield python_probe, node_probe, npm_probe


class TestProbeGating:
    def test_pypi_project_spawns_no_node_or_npm_probe(self, probes):
        python_probe, node_probe, npm_probe = probes

        context, npm_cli_version = detect_engine_context(
            make_project(ProjectPackagesRegistry.PYPI), ".", probe_runtime=True
        )

        python_probe.assert_called_once_with(".")
        node_probe.assert_not_called()
        npm_probe.assert_not_called()
        assert context.versions == {"python": "3.12.1"}
        assert context.source == EngineContextSource.DETECTED
        assert npm_cli_version is None

    def test_npm_project_spawns_no_python_probe(self, probes):
        python_probe, node_probe, npm_probe = probes

        context, npm_cli_version = detect_engine_context(
            make_project(ProjectPackagesRegistry.NPM), ".", probe_runtime=True
        )

        python_probe.assert_not_called()
        node_probe.assert_called_once()
        npm_probe.assert_called_once()
        # The npm CLI version rides along in the context so `engines.npm` is checkable at all.
        assert context.versions == {"node": "20.11.0", "npm": "10.2.4"}
        assert npm_cli_version == "10.2.4"

    def test_probe_runtime_disabled_spawns_nothing(self, probes):
        python_probe, node_probe, npm_probe = probes

        context, npm_cli_version = detect_engine_context(
            make_project(ProjectPackagesRegistry.NPM), ".", probe_runtime=False
        )

        python_probe.assert_not_called()
        node_probe.assert_not_called()
        npm_probe.assert_not_called()
        assert context.versions == {}
        assert context.source == EngineContextSource.NONE
        assert npm_cli_version is None


class TestContextSource:
    """Floors are bare versions here because that is what the adapters produce:
    `declared_engine_floors` and `extract_min_python_version` both reduce a declared range to its
    lowest concrete version before it ever reaches a Project."""

    def test_the_declared_floor_binds_over_a_newer_detected_runtime(self, probes):
        """What the project promises outranks what this machine happens to run: a release needing
        node 20 breaks the project's declared node 18 users whatever is on this PATH."""
        project = make_project(ProjectPackagesRegistry.NPM, {"node": "18.0.0"})

        context, _ = detect_engine_context(project, ".", probe_runtime=True)

        assert context.versions == {"node": "18.0.0", "npm": "10.2.4"}
        assert context.source == EngineContextSource.DECLARED

    def test_the_python_floor_binds_over_a_newer_interpreter(self, probes):
        """The reported bug: a 3.13 virtualenv admitted a release requiring >=3.12 into a project
        declaring `requires-python = ">=3.11"`, and uv then refused to resolve the 3.11 split."""
        python_probe, _, _ = probes
        python_probe.return_value = "3.13.2"
        project = make_project(ProjectPackagesRegistry.PYPI, {"python": "3.11"})

        context, _ = detect_engine_context(project, ".", probe_runtime=True)

        assert context.versions == {"python": "3.11"}
        assert context.source == EngineContextSource.DECLARED

    def test_a_runtime_older_than_the_floor_binds_instead(self, probes):
        """Stricter wins in both directions — a stale virtualenv is the binding constraint even
        when the manifest claims a higher floor."""
        project = make_project(ProjectPackagesRegistry.NPM, {"node": "22.0.0"})

        context, _ = detect_engine_context(project, ".", probe_runtime=True)

        assert context.versions == {"node": "20.11.0", "npm": "10.2.4"}
        assert context.source == EngineContextSource.DETECTED

    def test_the_floor_is_all_there_is_when_no_probe_succeeds(self, probes):
        _, node_probe, _ = probes
        node_probe.return_value = None
        project = make_project(ProjectPackagesRegistry.NPM, {"node": "18.0.0"})

        context, _ = detect_engine_context(project, ".", probe_runtime=True)

        assert context.versions == {"node": "18.0.0", "npm": "10.2.4"}
        assert context.source == EngineContextSource.DECLARED

    def test_nothing_declared_and_nothing_detected_is_none(self, probes):
        _, node_probe, npm_probe = probes
        node_probe.return_value = None
        npm_probe.return_value = None

        context, npm_cli_version = detect_engine_context(
            make_project(ProjectPackagesRegistry.NPM), ".", probe_runtime=True
        )

        assert context.versions == {}
        assert context.source == EngineContextSource.NONE
        assert npm_cli_version is None

    def test_declared_constraints_are_copied_not_aliased(self, probes):
        """A mutation of the context must not reach back into Project.engine_constraints."""
        _, node_probe, _ = probes
        node_probe.return_value = None
        declared = {"node": "18.0.0"}
        project = make_project(ProjectPackagesRegistry.NPM, declared)

        context, _ = detect_engine_context(project, ".", probe_runtime=True)
        context.versions["node"] = "tampered"

        assert declared == {"node": "18.0.0"}


class TestNpmEngineKey:
    """A package's `engines.npm` requirement was unreachable by two independent routes: no context
    ever carried an npm key, and the matcher returned True for every key but python and node."""

    def test_a_failed_node_probe_does_not_strand_the_declared_floors(self, probes):
        _, node_probe, _ = probes
        node_probe.return_value = None
        project = make_project(ProjectPackagesRegistry.NPM, {"node": "18.0.0", "npm": "9.0.0"})

        context, npm_cli_version = detect_engine_context(project, ".", probe_runtime=True)

        # node has only the floor left to go on; npm has both, and the floor is the lower.
        assert context.versions == {"node": "18.0.0", "npm": "9.0.0"}
        assert context.source == EngineContextSource.DECLARED
        assert npm_cli_version == "10.2.4"

    def test_a_probed_npm_stands_on_its_own_when_the_node_probe_fails(self, probes):
        """The npm probe used to be discarded unless Node answered too, because an npm-only
        context would have replaced the declared node floor. Floors are merged now, not replaced,
        so there is nothing left to protect against."""
        _, node_probe, _ = probes
        node_probe.return_value = None

        context, _ = detect_engine_context(make_project(ProjectPackagesRegistry.NPM), ".", probe_runtime=True)

        assert context.versions == {"npm": "10.2.4"}
        assert context.source == EngineContextSource.DETECTED

    def test_no_npm_probe_result_leaves_the_node_context_intact(self, probes):
        _, _, npm_probe = probes
        npm_probe.return_value = None

        context, _ = detect_engine_context(make_project(ProjectPackagesRegistry.NPM), ".", probe_runtime=True)

        assert context.versions == {"node": "20.11.0"}
        assert context.source == EngineContextSource.DETECTED
