"""Tests for qa/smoke_matrix.py.

The script is loaded by path: `qa/` is not an importable package. Only the offline core is
covered - the case catalogue and its projects, the checks, the docker command and the guards every
step gets. The runs themselves need Docker and the network.
"""

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

QA_DIR = Path(__file__).resolve().parent.parent / "qa"
SCRIPT = QA_DIR / "smoke_matrix.py"


def load_script() -> ModuleType:
    """Import smoke_matrix.py from its file path.

    Returns:
        The loaded module.
    """
    # The script imports its sibling update_strategies_regression by name.
    sys.path.insert(0, str(QA_DIR))
    try:
        spec = importlib.util.spec_from_file_location("smoke_matrix", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # @dataclass resolves its module through sys.modules, so registering it is not optional.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(QA_DIR))
    return module


smoke = load_script()
RunResult = sys.modules["update_strategies_regression"].RunResult
NPM = next(eco for eco in smoke.ECOSYSTEMS if eco.name == "npm")
PYPI = next(eco for eco in smoke.ECOSYSTEMS if eco.name == "pypi")


def make_case(*steps: dict[str, Any], project: str = "npm-semver", **extra: Any) -> Any:
    """Build a case over a real project from step tables."""
    raw = {"id": "t", "project": project, "why": "w", "steps": list(steps), **extra}
    return smoke.parse_case(raw, smoke.PROJECTS_DIR)


def fake_docker(monkeypatch: pytest.MonkeyPatch, effect: Any = None, rc: int = 0, stdout: str = "") -> None:
    """Replace the docker call with one that runs *effect* (to edit the workspace) and returns *rc*."""

    def fake(command: list[str], *, env: Any, log_path: Path, timeout: int, stdin: str | None = None) -> Any:
        if effect:
            effect()
        return RunResult(
            cmd=tuple(command), rc=rc, stdout=stdout, stderr="", elapsed=0.0, log_path=log_path, timed_out=False
        )

    monkeypatch.setattr(smoke, "run_logged", fake)


# ---------------------------------------------------------------------------
# The catalogue
# ---------------------------------------------------------------------------


def test_catalogue_parses_with_unique_ids_and_documented_cases() -> None:
    cases = smoke.parse_cases(smoke.tomllib.loads(smoke.CASES_FILE.read_text(encoding="utf-8")))

    assert len(cases) > 20
    assert all(case.why for case in cases)
    assert all(ref.startswith(("TC-", "GH-")) for case in cases for ref in case.covers)


@pytest.mark.parametrize("project", sorted(path.name for path in smoke.PROJECTS_DIR.iterdir()))
def test_every_project_lockfile_agrees_with_its_manifest(project: str) -> None:
    # A project edited without relocking would make every case on it fail for the wrong reason.
    workspace = smoke.PROJECTS_DIR / project
    for ecosystem in smoke.ECOSYSTEMS:
        if (workspace / smoke.MANIFESTS[ecosystem.name]).is_file():
            assert smoke.lock_agrees_with_manifest(ecosystem, workspace) == []


@pytest.mark.parametrize(
    "raw",
    [
        {"cases": [], "extra": 1},
        {"cases": [{"id": "a", "project": "empty", "why": "w", "steps": [{"run": ["x"]}], "extra": 1}]},
        {"cases": [{"id": "a", "project": "empty", "why": "w", "steps": [{"run": ["x"], "extra": 1}]}]},
        {"cases": [{"id": "a", "project": "empty", "why": "w", "steps": [{"run": ["x"], "stdout": {"hass": ["a"]}}]}]},
        {
            "cases": [
                {
                    "id": "a",
                    "project": "npm-semver",
                    "why": "w",
                    "steps": [{"run": ["x"], "locked": {"a": {"atleast": "1"}}}],
                }
            ]
        },
        {"cases": [{"id": "a", "project": "npm-semver", "why": "w", "steps": [{"run": ["x"], "locked": {"a": {}}}]}]},
        {
            "cases": [
                {
                    "id": "a",
                    "project": "npm-semver",
                    "why": "w",
                    "steps": [{"run": ["x"], "locked": {"a": {"missing": True, "equals": "1"}}}],
                }
            ]
        },
        {"cases": [{"id": "a", "project": "npm-semver", "why": "w", "steps": [{"run": ["x"], "packages": {"a": {}}}]}]},
        {
            "cases": [
                {"id": "a", "project": "empty", "why": "w", "steps": [{"run": ["x"], "locked": {"a": {"equals": "1"}}}]}
            ]
        },
        {"cases": [{"id": "a", "project": "no-such-project", "why": "w", "steps": [{"run": ["x"]}]}]},
        {"cases": [{"id": "a", "project": "empty", "steps": [{"run": ["x"]}]}]},
        {"cases": [{"id": "a", "project": "empty", "why": "w", "steps": [{"run": ["x"], "rc": "sometimes"}]}]},
        {"cases": [{"id": "a", "project": "empty", "why": "w", "steps": [{"run": []}]}]},
    ],
)
def test_invalid_cases_are_rejected(raw: dict[str, Any]) -> None:
    with pytest.raises(smoke.FixtureError):
        smoke.parse_cases(raw)


def test_duplicate_case_ids_are_rejected() -> None:
    entry = {"id": "a", "project": "empty", "why": "w", "steps": [{"run": ["x"]}]}

    with pytest.raises(smoke.FixtureError, match="duplicate"):
        smoke.parse_cases({"cases": [entry, entry]})


def test_select_cases_keeps_the_order_asked_for_and_rejects_unknown_ids() -> None:
    cases = [
        smoke.parse_case({"id": name, "project": "empty", "why": "w", "steps": [{"run": ["x"]}]}, smoke.PROJECTS_DIR)
        for name in ("a", "b", "c")
    ]

    assert [case.id for case in smoke.select_cases(cases, "c, a")] == ["c", "a"]
    assert [case.id for case in smoke.select_cases(cases, None)] == ["a", "b", "c"]
    with pytest.raises(smoke.FixtureError, match="unknown case"):
        smoke.select_cases(cases, "zzz")


def test_ecosystem_is_detected_from_the_manifest_unless_ambiguous() -> None:
    assert smoke.detect_ecosystem(smoke.PROJECTS_DIR / "npm-semver") is NPM
    assert smoke.detect_ecosystem(smoke.PROJECTS_DIR / "uv-ranges") is PYPI
    assert smoke.detect_ecosystem(smoke.PROJECTS_DIR / "mixed") is None
    assert smoke.detect_ecosystem(smoke.PROJECTS_DIR / "empty") is None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ecosystem", "actual", "rule", "ok"),
    [
        (NPM, "5.7.3", {"at_least": "5.7.2"}, True),
        (NPM, "5.7.1", {"at_least": "5.7.2"}, False),
        (NPM, "10.0.0", {"at_least": "9.9.9"}, True),  # compared as versions, not strings
        (NPM, "5.7.3", {"at_least": "5.7.2", "below": "6.0.0"}, True),
        (NPM, "7.0.0", {"below": "6.0.0"}, False),
        (PYPI, "3.10", {"at_least": "3.9"}, True),  # 3.10 sorts after 3.9, unlike as text
        (PYPI, "3.4", {"at_least": "3.10"}, False),
        (PYPI, "3.7", {"equals": "3.7.0"}, True),  # the same release, spelled differently
        (PYPI, "3.7", {"equals": "3.8"}, False),
    ],
)
def test_version_rules(ecosystem: Any, actual: str, rule: dict[str, Any], ok: bool) -> None:
    assert (smoke.check_value(ecosystem, "x", actual, rule, "version") == []) is ok


def test_missing_rule_wants_an_absent_value_and_every_other_rule_wants_a_present_one() -> None:
    assert smoke.check_value(NPM, "x", None, {"missing": True}, "version") == []
    assert smoke.check_value(NPM, "x", "1.0.0", {"missing": True}, "version")
    assert smoke.check_value(NPM, "x", None, {"at_least": "1.0.0"}, "version") == ["x not found"]


def test_spec_rules_compare_specs_not_strings() -> None:
    assert smoke.check_value(PYPI, "x", "<4,>=3.0", {"equals": ">=3.0,<4"}, "spec") == []
    assert smoke.check_value(PYPI, "x", ">=3.0", {"changed": True}, "spec", before=">=3.0")
    assert smoke.check_value(PYPI, "x", "~=2.8.0", {"changed": True}, "spec", before="~=1.26.5") == []
    assert smoke.check_value(PYPI, "x", "==3.7", {"pinned": True}, "spec") == []
    assert smoke.check_value(PYPI, "x", ">=3.7", {"pinned": True}, "spec")
    assert smoke.check_value(NPM, "x", "5.7.3", {"pinned": True}, "spec") == []
    assert smoke.check_value(NPM, "x", "^5.7.3", {"pinned": True}, "spec")
    assert smoke.check_value(NPM, "x", "^5.7.3", {"pinned": False}, "spec") == []


def test_value_rules_compare_booleans_exactly() -> None:
    assert smoke.check_value(NPM, "x", True, {"equals": True}, "value") == []
    assert smoke.check_value(NPM, "x", False, {"equals": True}, "value")


def test_text_rules() -> None:
    text = "alpha beta beta"

    assert smoke.text_problems("out", text, {"has": ["alpha"], "lacks": ["gamma"], "once": ["alpha"]}) == []
    assert smoke.text_problems("out", text, {"has": ["gamma"]}) == ["out lacks 'gamma'"]
    assert smoke.text_problems("out", text, {"lacks": ["beta"]}) == ["out has 'beta'"]
    assert smoke.text_problems("out", text, {"once": ["beta"]})
    assert smoke.text_problems("out", '{"a": 1}', {"json": True}) == []
    assert smoke.text_problems("out", "[1]", {"json": True})
    assert smoke.text_problems("out", "progress...", {"json": True})


def test_classify_reports_known_issues_separately() -> None:
    plain, known = make_case({"run": ["x"]}), make_case({"run": ["x"]}, known_issue="GH-1")

    assert smoke.classify(plain, []) == smoke.Status.PASS
    assert smoke.classify(plain, ["x"]) == smoke.Status.FAIL
    assert smoke.classify(known, ["x"]) == smoke.Status.XFAIL
    assert smoke.classify(known, []) == smoke.Status.XPASS


# ---------------------------------------------------------------------------
# The docker command
# ---------------------------------------------------------------------------


def test_the_token_is_passed_by_name_and_its_value_stays_out_of_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(smoke.GITHUB_TOKEN_ENV, "ghp_secret_value")
    case = make_case({"run": ["ossiq", "status", "."]})

    command = smoke.docker_command(case, case.steps[0], 1, Path("/runs/t"), "img", "r1")

    assert smoke.GITHUB_TOKEN_ENV in command
    assert "ghp_secret_value" not in " ".join(command)


def test_a_case_without_a_token_does_not_ask_docker_for_it() -> None:
    case = make_case({"run": ["ossiq", "auth", "status"]}, token=False)

    assert smoke.GITHUB_TOKEN_ENV not in smoke.docker_command(case, case.steps[0], 1, Path("/runs/t"), "img", "r1")


def test_the_command_mounts_workspace_home_and_cache_and_runs_ossiq_under_timeout() -> None:
    case = make_case({"run": ["ossiq", "status", "."], "timeout": 77, "env": {"OSSIQ_COOLDOWN_PERIOD": "3"}})

    command = smoke.docker_command(case, case.steps[0], 2, Path("/runs/t"), "img", "r1")

    assert "/runs/t/workspace:/work" in command
    assert "/runs/t/home:/home/qarunner" in command
    assert "ossiq-qa-cache:/cache" in command
    assert "OSSIQ_COOLDOWN_PERIOD=3" in command
    assert command[command.index("img") :] == ["img", "timeout", "-k", "10", "77", "ossiq", "status", "."]
    assert "-i" not in command
    # A global UV_PROJECT_ENVIRONMENT would aim `uv sync` at ossiq's own venv.
    assert not any(arg.startswith("UV_PROJECT_ENVIRONMENT") for arg in command)


def test_stdin_opens_the_container_input() -> None:
    case = make_case({"run": ["ossiq", "mcp"], "stdin": "{}\n"})

    assert "-i" in smoke.docker_command(case, case.steps[0], 1, Path("/runs/t"), "img", "r1")


# ---------------------------------------------------------------------------
# The guards every step gets
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace_dir(tmp_path: Path) -> Path:
    shutil.copytree(smoke.PROJECTS_DIR / "npm-semver", tmp_path / "workspace")
    (tmp_path / "home").mkdir()
    return tmp_path


def test_a_read_only_step_that_rewrites_the_manifest_fails(
    workspace_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = make_case({"run": ["ossiq", "plan", "."]})
    fake_docker(monkeypatch, lambda: (workspace_dir / "workspace" / "package.json").write_text("{}"))

    problems = smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1")

    assert any("only reads" in problem for problem in problems)


def test_a_read_only_step_that_changes_nothing_passes(workspace_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = make_case({"run": ["ossiq", "plan", "."]})
    fake_docker(monkeypatch)

    assert smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1") == []


def test_apply_that_leaves_a_lock_its_manifest_does_not_admit_fails(
    workspace_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = make_case({"run": ["ossiq", "apply", "--yes", "."]})
    manifest = workspace_dir / "workspace" / "package.json"
    fake_docker(monkeypatch, lambda: manifest.write_text(manifest.read_text().replace("^5.7.1", "^9.0.0")))

    problems = smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1")

    assert any("semver is locked at 5.7.1" in problem for problem in problems)


def test_apply_that_keeps_manifest_and_lock_in_agreement_passes(
    workspace_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = make_case({"run": ["ossiq", "apply", "--yes", "."]})
    fake_docker(monkeypatch)

    assert smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1") == []


@pytest.mark.parametrize(
    ("step", "rc", "stdout", "expected"),
    [
        ({"run": ["ossiq", "status"]}, 1, "", "exited 1, expected 0"),
        ({"run": ["ossiq", "status"], "rc": 2}, 0, "", "exited 0, expected 2"),
        ({"run": ["ossiq", "status"], "rc": "nonzero"}, 0, "", "exited 0, expected a failure"),
        ({"run": ["ossiq", "status"]}, 0, "Traceback (most recent call last)\n", "traceback"),
    ],
)
def test_exit_code_and_traceback_are_checked(
    workspace_dir: Path, monkeypatch: pytest.MonkeyPatch, step: dict[str, Any], rc: int, stdout: str, expected: str
) -> None:
    case = make_case(step)
    fake_docker(monkeypatch, rc=rc, stdout=stdout)

    problems = smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1")

    assert any(expected in problem for problem in problems)


def test_locked_and_declared_checks_read_the_workspace(workspace_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = make_case(
        {
            "run": ["ossiq", "apply", "--yes", "."],
            "locked": {"semver": {"at_least": "5.7.1"}, "ms": {"equals": "2.0.0"}},
            "declared": {"semver": {"changed": False}},
        }
    )
    fake_docker(monkeypatch)

    assert smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1") == []

    broken = make_case({"run": ["ossiq", "apply", "--yes", "."], "locked": {"semver": {"at_least": "5.7.2"}}})
    assert smoke.run_step(broken, broken.steps[0], 1, workspace_dir, "img", "r1")


def test_package_checks_read_an_export_from_the_workspace(workspace_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = '{"production_packages": [{"package_name": "semver", "recommended_version": "5.7.3", "is_yanked": false}]}'
    (workspace_dir / "workspace" / "export.json").write_text(report)
    case = make_case(
        {
            "run": ["ossiq", "export", "--output", "export.json", "."],
            "report": "export.json",
            "packages": {
                "semver": {"recommended_version": {"at_least": "5.7.2"}, "is_yanked": {"equals": False}},
                "ms": {"recommended_version": {"missing": True}},
            },
        }
    )
    fake_docker(monkeypatch)

    assert smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1") == []


def test_files_checks_report_a_file_that_was_not_written(workspace_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = make_case({"run": ["ossiq", "install", "skills", "claude"], "files": {"home/x.md": {"has": ["a"]}}})
    fake_docker(monkeypatch)

    assert smoke.run_step(case, case.steps[0], 1, workspace_dir, "img", "r1") == ["home/x.md was not written"]


def test_a_failing_step_stops_its_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = make_case({"run": ["ossiq", "status"], "rc": 3}, {"run": ["ossiq", "plan"]})
    monkeypatch.setattr(smoke, "LOG_ROOT", tmp_path)
    calls: list[int] = []
    monkeypatch.setattr(smoke, "run_step", lambda c, s, index, *rest: calls.append(index) or ["boom"])

    result = smoke.run_case(case, tmp_path, "img", "r1")

    assert calls == [1]
    assert result.status == smoke.Status.FAIL
    assert result.problems == ("step 1 `ossiq status`: boom",)
