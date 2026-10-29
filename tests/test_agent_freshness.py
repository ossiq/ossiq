"""Tests for qa/agent_freshness/run.py and eval.py (the GH-174 experiment).

Both scripts are loaded by path: `qa/` is not an importable package. Only the offline core is
covered - experiment.toml, what each arm's HOME holds, and the scorer's rules against hand-built
registry records and transcripts. Real runs and the lock check need Docker, the claude CLI and the
network.
"""

import importlib.util
import json
import re
import sys
import tomllib
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

QA_DIR = Path(__file__).resolve().parent.parent / "qa" / "agent_freshness"


def load_script(name: str, filename: str) -> ModuleType:
    """Import a qa script from its file path.

    Returns:
        The loaded module.
    """
    spec = importlib.util.spec_from_file_location(name, QA_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves its module through sys.modules, so registering it is not optional.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = load_script("agent_freshness_run", "run.py")
scorer = load_script("agent_freshness_eval", "eval.py")

RAW_EXPERIMENT = tomllib.loads((QA_DIR / "experiment.toml").read_text(encoding="utf-8"))
EXPERIMENT = runner.parse_experiment(RAW_EXPERIMENT)
AS_OF = datetime(2026, 10, 27, 12, tzinfo=UTC)
PACKUMENT = {
    "dist-tags": {"latest": "5.1.0"},
    "time": {
        "created": "2024-01-01T00:00:00.000Z",
        "4.0.0": "2024-01-01T00:00:00.000Z",
        "4.1.0": "2025-01-01T00:00:00.000Z",
        "4.2.0": "2025-02-01T00:00:00.000Z",
        "5.1.0": "2026-10-26T00:00:00.000Z",
        "6.0.0-beta.1": "2026-10-20T00:00:00.000Z",
        "5.2.0": "2026-11-01T00:00:00.000Z",
        "3.0.0": "2023-01-01T00:00:00.000Z",
    },
    # 3.0.0 has a `time` entry but no `versions` entry: it was unpublished.
    "versions": {
        "4.0.0": {},
        "4.1.0": {},
        "4.2.0": {"deprecated": "broken release, use 4.1.0"},
        "5.1.0": {},
        "6.0.0-beta.1": {},
        "5.2.0": {},
    },
}


def npm_score(declared: str, locked: str | None = None) -> Any:
    """Score `lib` at `declared` against PACKUMENT.

    Returns:
        The scorer's DependencyScore; its class is loaded by path, so the annotation can't name it.
    """
    return scorer.score_dependency(
        "npm", scorer.DeclaredDependency("lib", declared, locked), scorer.npm_record(PACKUMENT), AS_OF
    )


def test_experiment_is_the_matrix() -> None:
    assert [model.model for model in EXPERIMENT.models] == ["claude-opus-5-5", "claude-sonnet-5-5"]
    assert EXPERIMENT.arms == ("baseline", "ossiq")
    assert sorted(task.ecosystem for task in EXPERIMENT.tasks) == ["npm", "npm", "pypi", "pypi"]
    runs = runner.plan_runs(EXPERIMENT, EXPERIMENT.models, EXPERIMENT.arms, EXPERIMENT.tasks, EXPERIMENT.reps)
    assert len(runs) == 48
    # Each model runs as its own batch, because the summary groups by arm and would pool models.
    opus_runs = runner.plan_runs(EXPERIMENT, EXPERIMENT.models[:1], EXPERIMENT.arms, EXPERIMENT.tasks, EXPERIMENT.reps)
    assert len(opus_runs) == 24


def test_prompts_never_name_a_version() -> None:
    for task in EXPERIMENT.tasks:
        prompt = EXPERIMENT.prompt_for(task)
        assert prompt.startswith(RAW_EXPERIMENT["ecosystems"][task.ecosystem]["preamble"])
        assert prompt.endswith(RAW_EXPERIMENT["prompt"]["suffix"])
        assert not re.search(r"@\d|\bv?\d+\.\d+\.\d+\b", prompt), task.id


DEPENDENCY_TALK = re.compile(
    r"\b(depend\w*|packages?|librar\w*|install\w*|pin(?:ned)?|versions?|manifest|pyproject|requirements|lockfile)\b",
    re.IGNORECASE,
)


def test_prompts_keep_dependencies_out_of_the_foreground() -> None:
    # The experiment is about what an agent pulls in while it is busy with something else.
    for task in EXPERIMENT.tasks:
        for text in (task.prompt, RAW_EXPERIMENT["prompt"]["suffix"]):
            match = DEPENDENCY_TALK.search(text)
            assert match is None, f"{task.id} says {match.group() if match else ''!r}"


def test_each_run_starts_from_a_dependency_free_starter(tmp_path: Path) -> None:
    for task in EXPERIMENT.tasks:
        workspace = tmp_path / task.id
        runner.prepare_workspace(runner.RunSpec(EXPERIMENT.models[0], "baseline", task, 0), workspace)
        assert (workspace / scorer.MANIFESTS[task.ecosystem]).is_file()
        # The scorer counts every declared dependency as the agent's, so the starter must declare none.
        assert scorer.declared_dependencies(task.ecosystem, workspace) == []


def test_a_misspelt_key_is_rejected() -> None:
    with pytest.raises(runner.ExperimentError, match=r"unknown key\(s\) rep;"):
        runner.parse_experiment({**RAW_EXPERIMENT, "rep": 3})


def test_run_order_is_shuffled_reproducibly() -> None:
    first = runner.plan_runs(EXPERIMENT, EXPERIMENT.models, EXPERIMENT.arms, EXPERIMENT.tasks, 3)
    second = runner.plan_runs(EXPERIMENT, EXPERIMENT.models, EXPERIMENT.arms, EXPERIMENT.tasks, 3)
    assert [run.run_id for run in first] == [run.run_id for run in second]
    assert len({run.run_id for run in first}) == 48
    assert [run.arm for run in first[:6]] != [first[0].arm] * 6


def home_for(arm: str, tmp_path: Path) -> Path:
    home = tmp_path / arm
    home.mkdir()
    runner.prepare_home(runner.RunSpec(EXPERIMENT.models[0], arm, EXPERIMENT.tasks[0], 0), home)
    return home


def test_only_the_ossiq_arm_can_reach_ossiq(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSSIQ_GITHUB_TOKEN", "gho_test")
    assert not any(home_for("baseline", tmp_path).rglob("*"))
    values, secrets = runner.arm_environment(runner.RunSpec(EXPERIMENT.models[0], "baseline", EXPERIMENT.tasks[0], 0))
    assert "PATH" not in values and "OSSIQ_GITHUB_TOKEN" not in secrets

    home = home_for("ossiq", tmp_path)
    assert "{{ossiq}}" not in (home / runner.SKILLS_DIR / "ossiq" / "SKILL.md").read_text(encoding="utf-8")
    server = json.loads((home / "mcp.json").read_text(encoding="utf-8"))["mcpServers"]["ossiq"]
    # No cooldown override: the arm runs on OSS IQ's defaults, as `ossiq install skills` leaves them.
    assert server["env"] == {"OSSIQ_GITHUB_TOKEN": "gho_test"}


def test_agent_commands() -> None:
    opus, task = EXPERIMENT.models[0], EXPERIMENT.tasks[0]
    claude = runner.agent_command(runner.RunSpec(opus, "ossiq", task, 0))
    assert claude[:2] == ["claude", "-p"] and "--mcp-config" in claude and "--strict-mcp-config" in claude
    assert "--mcp-config" not in runner.agent_command(runner.RunSpec(opus, "baseline", task, 0))


def test_the_prompt_reaches_the_agent_on_stdin_never_on_a_command_line(tmp_path: Path) -> None:
    # Everything on the container's command lines is visible to `pkill -f` and to scans of /proc/*/cmdline,
    # so a prompt that names main.py there gets the agent killed by its own cleanup of a test server.
    named = {task.id: re.findall(r"[\w./-]+\.(?:py|js|xlsx)\b", task.prompt) for task in EXPERIMENT.tasks}
    assert any(named.values()), "no prompt names a file, so the file check below proves nothing"
    for task in EXPERIMENT.tasks:
        files = named[task.id]
        for arm in EXPERIMENT.arms:
            spec = runner.RunSpec(EXPERIMENT.models[0], arm, task, 0)
            command = runner.docker_command(spec, EXPERIMENT, tmp_path / "batch" / spec.run_id, "ossiq-exp")
            assert "-i" in command
            joined = " ".join(command)
            assert EXPERIMENT.prompt_for(task) not in joined
            assert not [name for name in files if name in joined]


def test_a_run_counts_as_finished_only_with_its_result_event(tmp_path: Path) -> None:
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text("", encoding="utf-8")
    assert not runner.has_result_event(transcript)
    transcript.write_text('{"type":"assistant"}\nnot json\n[1]\n', encoding="utf-8")
    assert not runner.has_result_event(transcript)
    transcript.write_text('{"type":"assistant"}\n{"type":"result","subtype":"success"}\n', encoding="utf-8")
    assert runner.has_result_event(transcript)


def test_newest_stable_is_as_of_the_run_and_skips_prereleases_deprecations_and_unpublished() -> None:
    record = scorer.npm_record(PACKUMENT)
    assert "3.0.0" not in record.releases
    assert scorer.newest_stable("npm", record, AS_OF).version == "5.1.0"
    assert scorer.newest_stable("npm", record, AS_OF, spec="^4.0.0").version == "4.1.0"
    assert record.retired is None


def test_npm_dependency_score() -> None:
    behind = npm_score("^4.0.0", "4.1.0")
    assert (behind.lag_days, behind.majors_behind, behind.installed_from) == (663, 1, "lock")
    assert (behind.exact, behind.version_found, behind.deprecated) == (False, True, False)

    fresh = npm_score("^5.0.0")
    assert (fresh.installed, fresh.installed_from, fresh.lag_days) == ("5.1.0", "resolved", 0)

    deprecated = npm_score("4.2.0", "4.2.0")
    assert deprecated.deprecated and deprecated.deprecation_note == "broken release, use 4.1.0"

    hallucinated = npm_score("4.9.9")
    assert (hallucinated.exact, hallucinated.version_found, hallucinated.installed) == (True, False, None)
    # A prerelease pin exists even though it never resolves to a stable release.
    assert npm_score("6.0.0-beta.1").version_found

    missing = scorer.score_dependency("npm", scorer.DeclaredDependency("nope", "1.0.0", None), scorer.MISSING, AS_OF)
    assert not missing.exists and not missing.version_found


def test_pypi_record_reads_yanks_project_status_and_inactive() -> None:
    project = {
        "info": {"classifiers": []},
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": False}],
            "1.1": [{"upload_time_iso_8601": "2020-02-01T00:00:00Z", "yanked": True, "yanked_reason": "bad"}],
        },
    }
    record = scorer.pypi_record(project, {"project-status": {"status": "archived"}})
    assert record.releases["1.1"].deprecated == "yanked: bad"
    assert record.retired == "project status archived"
    inactive = {**project, "info": {"classifiers": [scorer.INACTIVE_CLASSIFIER]}}
    assert scorer.pypi_record(inactive, None).retired == scorer.INACTIVE_CLASSIFIER
    score = scorer.score_dependency("pypi", scorer.DeclaredDependency("lib", "<2", "1.0"), record, AS_OF)
    assert score.deprecated and score.newest == "1.0" and not score.exact


@pytest.mark.parametrize(
    ("ecosystem", "spec", "version", "expected"),
    [
        ("npm", "^4.21.2", "5.1.0", False),
        ("npm", "^4.21.2", "4.22.0", True),
        ("npm", "latest", "9.0.0", True),
        ("npm", "github:user/repo", "1.0.0", None),
        ("pypi", "<2", "2.10.0", False),
        ("pypi", "", "2.10.0", True),
    ],
)
def test_admits(ecosystem: str, spec: str, version: str, expected: bool | None) -> None:
    assert scorer.admits(ecosystem, spec, version) is expected


@pytest.mark.parametrize(
    ("ecosystem", "spec", "expected"),
    [
        ("npm", "4.21.2", True),
        ("npm", "1.0.0-rc.1", True),
        ("npm", "^4.21.2", False),
        ("npm", "latest", False),
        ("pypi", "==2.6.1", True),
        ("pypi", ">=2.6", False),
        ("pypi", "==2.*", False),
        ("pypi", "", False),
    ],
)
def test_is_exact(ecosystem: str, spec: str, expected: bool) -> None:
    assert scorer.is_exact(ecosystem, spec) is expected


def test_parse_claude_transcript() -> None:
    events = [
        {"type": "system", "subtype": "init", "mcp_servers": [{"name": "ossiq", "status": "connected"}]},
        {
            "type": "assistant",
            "message": {"content": [{"type": "tool_use", "name": "WebSearch", "input": {"query": "x"}}]},
        },
        {
            "type": "assistant",
            "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "npm i x"}}]},
        },
        {
            "type": "user",
            "message": {"content": [{"type": "tool_result", "content": [{"type": "text", "text": "ok"}]}]},
        },
        {
            "type": "result",
            "total_cost_usd": 0.5,
            "usage": {"input_tokens": 10, "cache_read_input_tokens": 5, "output_tokens": 3},
        },
    ]
    facts = scorer.parse_transcript([json.dumps(event) for event in events] + ["not json"])
    # A connected server that the agent never called is not use.
    assert not facts.ossiq_used and not facts.ossiq_skill_used and not facts.ossiq_no_project
    assert facts.web_search_used
    assert (facts.commands, facts.outputs, facts.tool_calls) == (("npm i x",), ("ok",), 2)
    assert (facts.cost_usd, facts.input_tokens, facts.output_tokens) == (0.5, 15, 3)

    ossiq_events = [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "tool_use", "name": "Skill", "input": {"skill": "ossiq-dependency-check"}},
                    {"type": "tool_use", "name": "mcp__ossiq__ossiq_evaluate_dependency", "input": {"package": "zod"}},
                ]
            },
        },
        {
            "type": "user",
            "message": {
                "content": [
                    {"type": "tool_result", "content": "Unable to identify Package Manager for project at /work"}
                ]
            },
        },
    ]
    facts = scorer.parse_transcript(json.dumps(event) for event in ossiq_events)
    assert facts.ossiq_used and facts.ossiq_skill_used and facts.ossiq_no_project

    # The installed skill's directory is `ossiq`: that is the name the Skill tool is called with.
    skill_only = [
        {
            "type": "assistant",
            "message": {"content": [{"type": "tool_use", "name": "Skill", "input": {"skill": "ossiq", "args": "x"}}]},
        }
    ]
    facts = scorer.parse_transcript(json.dumps(event) for event in skill_only)
    assert facts.ossiq_skill_used and not facts.ossiq_used


def test_not_found_names() -> None:
    assert scorer.not_found_names("npm", ["npm error 404  'left-padx@*' is not in this registry."]) == {"left-padx"}
    assert scorer.not_found_names("pypi", ["Because Py_Yamlx was not found in the package registry"]) == {"py-yamlx"}


def test_declared_dependencies(tmp_path: Path) -> None:
    assert scorer.declared_dependencies("npm", tmp_path) == []
    assert scorer.declared_dependencies("pypi", tmp_path) == []

    npm = tmp_path / "npm"
    npm.mkdir()
    manifest = {"dependencies": {"express": "4.21.2"}, "devDependencies": {"eslint": "^8.57.0"}}
    (npm / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    lock = {
        "packages": {
            "node_modules/eslint": {"version": "8.57.1"},
            "node_modules/a/node_modules/eslint": {"version": "1.0.0"},
        }
    }
    (npm / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    assert scorer.declared_dependencies("npm", npm) == [
        scorer.DeclaredDependency("eslint", "^8.57.0", "8.57.1"),
        scorer.DeclaredDependency("express", "4.21.2", None),
    ]

    pypi = tmp_path / "pypi"
    pypi.mkdir()
    (pypi / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["PyYAML>=5.4"]\n', encoding="utf-8")
    (pypi / "requirements.txt").write_text("passlib==1.7.4  # hashing\n-r other.txt\n", encoding="utf-8")
    (pypi / "uv.lock").write_text('[[package]]\nname = "PyYAML"\nversion = "6.0.2"\n', encoding="utf-8")
    assert scorer.declared_dependencies("pypi", pypi) == [
        scorer.DeclaredDependency("passlib", "==1.7.4", None),
        scorer.DeclaredDependency("pyyaml", ">=5.4", "6.0.2"),
    ]


def test_html_report_escapes_agent_text_and_survives_nothing_to_plot() -> None:
    hostile = {"run_id": "b", "arm": "baseline", **asdict(npm_score("4.1.0")), "name": "<script>alert(1)</script>"}
    missing = {"run_id": "o", "arm": "ossiq", **asdict(npm_score("4.9.9"))}
    rows = [
        {"arm": "baseline", "resolves": True, "ossiq_used": False},
        {"arm": "ossiq", "resolves": None, "ossiq_used": True},
    ]
    batch = {"created_at": "2026-10-28T10:00:00+00:00", "versions": ["2.1.308 (Claude Code)"]}

    page = scorer.render_html("run<b>", batch, rows, [hostile, missing])
    assert "<script>" not in page and "&lt;script&gt;" in page and "run<b>" not in page
    assert page.count("<svg") == 2 and "started 2026-10-28" in page
    # The ossiq arm has no pin to plot and no lock result: its row is empty, not a crash.
    assert "Pins without a matching release aren't plotted (1)." in page
    assert "ossiq: 0 of 0 runs that don&#x27;t resolve" in page
    assert "<td>ossiq</td>" in page

    # Nothing plottable anywhere still gets an axis.
    assert "<svg" in scorer.render_html("t", {}, rows, [missing])


def test_bar_and_axis_helpers() -> None:
    assert scorer.tick_step(0) == 50 and scorer.tick_step(2693) == 500 and scorer.tick_step(10**6) == 10000
    # The tip is rounded, the baseline edge square, and a zero-width bar never divides by itself.
    path = scorer.bar_path(0, 0, 100, 14)
    assert path.startswith("M0.0,0.0h96.0a4.0,4.0 0 0 1 4.0,4.0") and path.endswith("h-96.0z")
    assert scorer.bar_path(0, 0, 2, 14).startswith("M0.0,0.0h0.0a2.0,2.0")


def test_summarize_counts_per_arm_and_ranks_the_worst_pins() -> None:
    pins = [
        {"run_id": "b", "arm": "baseline", **asdict(npm_score("4.1.0")), "cves": ("GHSA-1",)},
        {"run_id": "b", "arm": "baseline", **asdict(npm_score("4.9.9"))},
        {"run_id": "o", "arm": "ossiq", **asdict(npm_score("5.1.0"))},
    ]
    rows = [
        {"arm": "baseline", "resolves": False, "ossiq_used": False},
        {"arm": "ossiq", "resolves": True, "ossiq_used": True},
    ]
    report = scorer.summarize(rows, pins)
    assert "| baseline | 1 | 2 | 0 | 663 | 663 | 1 | 1 | 0 | 1 | 0/1 | 0/1 |" in report
    assert "| ossiq | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1/1 | 1/1 |" in report
    # A pin to a version that doesn't exist outranks one with a CVE, which outranks a merely stale one.
    missing = report.index("| baseline | b | lib | 4.9.9 |")
    vulnerable = report.index("| baseline | b | lib | 4.1.0 |")
    assert missing < vulnerable < report.index("| ossiq | o | lib | 5.1.0 |")
