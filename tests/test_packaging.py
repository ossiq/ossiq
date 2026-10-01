"""Tests for the distribution contract: entry point, metadata and packaged data.

None of this was covered before, which is how the console script name, the
optional-CLI-extra split and the undeclared python-dotenv dependency all drifted
away from what the docs promised. These assertions also stand in for the
PyInstaller build: a frozen binary reads exactly the same resources, so a failure
here predicts a broken standalone binary.
"""

import importlib.metadata
import os
import re
import subprocess
import sys
import tomllib
from importlib.resources import files
from pathlib import Path

import pytest

from ossiq.ui.auth import BACKEND_LABELS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCKER_ENTRYPOINT = PROJECT_ROOT / "docker-entrypoint.sh"
BINARY_BUILD_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "reusable-build-binaries.yml"

# Every non-Python file the package reads at runtime through importlib.resources.
PACKAGED_DATA = [
    ("ossiq.data", "SKILL.md"),
    ("ossiq.ui.html_templates", "spa_app.html"),
    ("ossiq.ui.html_templates", "filter_format_highlight_days.html"),
    ("ossiq.ui.html_templates", "tag_versions_difference.html"),
    ("ossiq.ui.renderers.export.schemas", "export_schema_v1.5.json"),
]


@pytest.fixture(scope="module")
def pyproject() -> dict:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_console_script_is_named_ossiq():
    """The command must match the distribution name so `uvx ossiq` resolves it."""
    scripts = [ep for ep in importlib.metadata.entry_points(group="console_scripts") if ep.name == "ossiq"]
    assert scripts, "no `ossiq` console script is registered"
    assert scripts[0].value == "ossiq.cli:app"


def test_console_script_loads():
    """Guards against the entry point being registered without its dependencies."""
    (entry_point,) = [ep for ep in importlib.metadata.entry_points(group="console_scripts") if ep.name == "ossiq"]
    assert entry_point.load() is not None


def test_version_metadata_resolves():
    """`ossiq --version` and the MCP serverInfo both depend on this."""
    assert importlib.metadata.version("ossiq")


def test_declared_version_matches_installed(pyproject):
    assert importlib.metadata.version("ossiq") == pyproject["project"]["version"]


@pytest.mark.parametrize(("package", "name"), PACKAGED_DATA)
def test_packaged_data_is_readable(package: str, name: str):
    """Data files must ship in the wheel, not just exist in the source tree."""
    resource = files(package).joinpath(name)
    assert resource.is_file(), f"{package}/{name} is missing from the installed package"
    assert resource.read_bytes(), f"{package}/{name} is empty"


def test_cli_dependencies_are_not_optional(pyproject):
    """typer/rich/termcolor/keyring are imported unconditionally by ossiq.cli."""
    dependencies = " ".join(pyproject["project"]["dependencies"])
    for package in ("typer", "rich", "termcolor", "keyring"):
        assert package in dependencies, f"{package} must be a core dependency, not an extra"


def test_cli_extra_still_resolves(pyproject):
    """Kept as an empty extra so `pip install 'ossiq[cli]'` in older docs works."""
    assert pyproject["project"]["optional-dependencies"]["cli"] == []


def test_every_imported_third_party_top_level_is_declared(pyproject):
    """Catches undeclared dependencies that only arrive transitively today."""
    declared = " ".join(pyproject["project"]["dependencies"])
    # python-dotenv is imported as `dotenv` by commands/install.py and used to
    # arrive only via pydantic-settings.
    assert "python-dotenv" in declared


def test_hatch_is_not_a_runtime_dependency(pyproject):
    """`hatch` is a dev tool; as a runtime dep it pulled in ~25 packages including uv."""
    dependencies = pyproject["project"]["dependencies"]
    assert not [d for d in dependencies if d.split(">")[0].split("=")[0].strip() == "hatch"]


# --- the SPA template as a committed source artifact -------------------------------------

SPA_TEMPLATE = PROJECT_ROOT / "src" / "ossiq" / "ui" / "html_templates" / "spa_app.html"

# Strings that would mean the template captured something about the machine that built it
# rather than the sources it came from.
BUILD_HOST_MARKERS = ("/Users/", "/home/runner", "localhost", "127.0.0.1", "sourceMappingURL")


def test_build_backend_requirement_is_bounded(pyproject: dict):
    """An unbounded build requirement is resolved fresh from PyPI at build time.

    PEP 517 `requires` has no hash mechanism, so a range is the only constraint available
    here; the release build additionally takes hatchling from uv.lock via
    `uv build --no-build-isolation`.
    """
    requires = pyproject["build-system"]["requires"]

    unbounded = [spec for spec in requires if not any(op in spec for op in ("==", ">=", "<", "~="))]
    assert not unbounded, f"build-system.requires entries need a version specifier: {unbounded}"

    hatchling = next(spec for spec in requires if spec.startswith("hatchling"))
    assert "<" in hatchling, f"hatchling needs an upper bound so a major release cannot break the build: {hatchling}"


def test_spa_template_is_committed_and_substantial():
    """Packaging reads this file rather than rebuilding it, so it has to be real.

    The build hook falls back to it whenever frontend/ is absent, which is every install
    from an sdist -- an empty or truncated template would ship a blank HTML report.
    """
    assert SPA_TEMPLATE.is_file(), f"{SPA_TEMPLATE} must be committed; run `just frontend-build`"
    assert SPA_TEMPLATE.stat().st_size > 100_000, "the built SPA is ~650 KB; anything this small is not a real build"

    body = SPA_TEMPLATE.read_text(encoding="utf-8")
    assert body.count("__OSSIQ_REPORT_DATA__") == 1, (
        "the template needs exactly one data placeholder; a populated report would have none"
    )


def test_spa_template_carries_no_build_host_traces():
    """The template is source, so it must not record where it happened to be built."""
    body = SPA_TEMPLATE.read_text(encoding="utf-8")

    found = [marker for marker in BUILD_HOST_MARKERS if marker in body]
    assert not found, f"{SPA_TEMPLATE.name} leaks build-host details: {found}"


# --- the keyring in the standalone binaries and the Docker image ------------------------


def test_pyinstaller_ships_a_keyring_hook():
    """The spec adds no keyring hints because PyInstaller's own hook collects the backends.

    If a release drops the hook, the frozen binary loses its keyring backends and the spec needs them.
    """
    pytest.importorskip("PyInstaller")  # a dev-group tool, absent from a runtime-only install

    hook = files("PyInstaller").joinpath("hooks", "hook-keyring.py")

    assert hook.is_file(), "PyInstaller no longer ships hook-keyring.py; hand-list the keyring backends in the spec"


def test_binary_keyring_smoke_test_expects_labels_the_cli_prints():
    """The workflow greps `auth status` output for these labels, so a rename must fail here, not a release build."""
    per_os = re.findall(r'EXPECT="([^"]+)"', BINARY_BUILD_WORKFLOW.read_text(encoding="utf-8"))

    assert len(per_os) == 3, f"expected one entry per OS (macOS, Windows, Linux) in the keyring smoke test: {per_os}"
    expected = [label for entry in per_os for label in entry.split("|")]  # Linux accepts several
    unknown = [label for label in expected if not any(known.startswith(label) for known in BACKEND_LABELS.values())]
    assert not unknown, f"the smoke test expects labels `auth status` never prints: {unknown}"


@pytest.mark.skipif(sys.platform == "win32", reason="the entrypoint is a bash script for the Linux image")
class TestDockerEntrypoint:
    @pytest.fixture
    def run(self, tmp_path: Path):
        """Run the entrypoint with a stand-in `ossiq` first on PATH that reports its arguments."""
        stand_in = tmp_path / "ossiq"
        stand_in.write_text('#!/bin/sh\necho "ossiq-ran: $*"\n')
        stand_in.chmod(0o755)

        def invoke(*args: str, token: str | None = None) -> subprocess.CompletedProcess[str]:
            # A minimal environment, so a token in the developer's shell cannot leak into the case.
            env = {"PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path)}
            if token is not None:
                env["OSSIQ_GITHUB_TOKEN"] = token
            return subprocess.run(
                ["bash", str(DOCKER_ENTRYPOINT), *args], env=env, capture_output=True, text=True, timeout=30
            )

        return invoke

    def test_export_without_a_token_says_why_login_is_not_offered(self, run):
        result = run("export", "/project")

        output = result.stdout + result.stderr
        assert result.returncode == 1
        assert "ossiq-ran" not in output
        assert "OSSIQ_GITHUB_TOKEN" in output
        assert "keyring" in output
        assert "ossiq auth login" in output

    def test_export_with_a_token_runs_the_cli(self, run):
        result = run("export", "/project", token="ghp_" + "x" * 36)

        assert result.returncode == 0
        assert "ossiq-ran: export /project" in result.stdout

    @pytest.mark.parametrize("args", [("--help",), ("status", "/project")])
    def test_other_commands_run_without_a_token(self, run, args):
        """The README's `status` example keeps working tokenless: the CLI itself warns about the limit."""
        result = run(*args)

        assert result.returncode == 0
        assert f"ossiq-ran: {' '.join(args)}" in result.stdout

    def test_a_token_that_is_too_short_is_warned_about(self, run):
        result = run("--help", token="short")

        assert result.returncode == 0
        assert "too short" in result.stderr

    def test_the_usage_text_names_the_keyring_and_commands_that_exist(self, run):
        result = run("help")

        assert result.returncode == 0
        assert "keyring" in result.stdout
        assert "ossiq-cli status" in result.stdout
        assert "ossiq-cli scan" not in result.stdout
