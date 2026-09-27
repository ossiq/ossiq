"""Runtime pins are a cross-check on the runtime, read from the files version managers honour."""

import pytest

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.sources.runtime_pins import RuntimePin, pin_matches, read_runtime_pin


@pytest.mark.parametrize(
    ("file_name", "content", "expected"),
    [
        (".nvmrc", "v20.11.0\n", "20.11.0"),
        (".node-version", "# pinned\n22\n", "22"),
        (".tool-versions", "python 3.12.1\nnodejs 20.19.0 18.20.8\n", "20.19.0"),
        ("mise.toml", '[tools]\nnode = ["22.12", "20"]\n', "22.12"),
        ("package.json", '{"volta": {"node": "20.11.1"}}', "20.11.1"),
    ],
)
def test_node_pins(tmp_path, file_name, content, expected):
    (tmp_path / file_name).write_text(content)

    assert read_runtime_pin(str(tmp_path), ProjectPackagesRegistry.NPM) == RuntimePin("node", expected, file_name)


@pytest.mark.parametrize(
    ("file_name", "content", "expected"),
    [
        (".python-version", "3.11\n", "3.11"),
        (".tool-versions", "python 3.12.1\n", "3.12.1"),
        ("mise.toml", '[tools]\npython = "3.13"\n', "3.13"),
        (".venv/pyvenv.cfg", "home = /usr/bin\nversion_info = 3.11.9.final.0\n", "3.11.9"),
    ],
)
def test_python_pins(tmp_path, file_name, content, expected):
    (tmp_path / file_name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / file_name).write_text(content)

    assert read_runtime_pin(str(tmp_path), ProjectPackagesRegistry.PYPI) == RuntimePin("python", expected, file_name)


def test_an_alias_is_not_a_pin(tmp_path):
    (tmp_path / ".nvmrc").write_text("lts/*\n")

    assert read_runtime_pin(str(tmp_path), ProjectPackagesRegistry.NPM) is None


def test_the_engine_file_wins_over_the_multi_tool_manager(tmp_path):
    (tmp_path / ".nvmrc").write_text("20\n")
    (tmp_path / ".tool-versions").write_text("nodejs 22.12.0\n")

    assert read_runtime_pin(str(tmp_path), ProjectPackagesRegistry.NPM) == RuntimePin("node", "20", ".nvmrc")


def test_a_malformed_file_is_skipped_not_fatal(tmp_path):
    (tmp_path / "mise.toml").write_text("[tools\n")
    (tmp_path / "package.json").write_text('{"volta": {"node": "20.11.1"}}')

    assert read_runtime_pin(str(tmp_path), ProjectPackagesRegistry.NPM) == RuntimePin("node", "20.11.1", "package.json")


def test_the_python_engine_ignores_node_only_files(tmp_path):
    (tmp_path / "package.json").write_text('{"volta": {"node": "20.11.1"}}')

    assert read_runtime_pin(str(tmp_path), ProjectPackagesRegistry.PYPI) is None


@pytest.mark.parametrize(
    ("pinned", "runtime", "matches"),
    [("20", "20.11.0", True), ("20.11", "20.12.0", False), ("3.11", "3.11.9", True), ("22", "26.8.1", False)],
)
def test_pin_matches(pinned, runtime, matches):
    assert pin_matches(pinned, runtime) is matches
