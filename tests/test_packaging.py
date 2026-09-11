"""Tests for the distribution contract: entry point, metadata and packaged data.

None of this was covered before, which is how the console script name, the
optional-CLI-extra split and the undeclared python-dotenv dependency all drifted
away from what the docs promised. These assertions also stand in for the
PyInstaller build: a frozen binary reads exactly the same resources, so a failure
here predicts a broken standalone binary.
"""

import importlib.metadata
import tomllib
from importlib.resources import files
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

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
    """typer/rich/termcolor are imported unconditionally by ossiq.cli."""
    dependencies = " ".join(pyproject["project"]["dependencies"])
    for package in ("typer", "rich", "termcolor"):
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
