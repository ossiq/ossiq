#!/usr/bin/env python3
"""GH-174 runner: have Claude Code build the same features with and without OSS IQ.

Every run is one throwaway container (qa/agent_freshness/Dockerfile) with a copy of a dependency-free
starter project and a fresh HOME, so nothing from the host reaches a run - in particular not the
ossiq skill a developer machine has installed. The two arms differ only in that HOME, PATH and
environment:

  baseline  nothing extra
  ossiq     the shipped ossiq skill + MCP server, as `ossiq install skills claude` sets them up

A run lands in qa_logs/agent_freshness/<batch>/<run_id>/: workspace/ (what the agent left behind),
transcript.jsonl (the CLI's JSON event stream), stderr.log and meta.json. A run whose meta.json says
`done` is skipped, so re-running a command resumes the batch and a higher `--reps` tops it up.
Score a batch with eval.py.

Usage:

    uv run python qa/agent_freshness/run.py --smoke
    uv run python qa/agent_freshness/run.py --batch pilot --tasks P1,P3 --reps 1
    uv run python qa/agent_freshness/run.py --batch main --parallel 4
    uv run python qa/agent_freshness/run.py --batch main --dry-run

Exit status: 0 when every run finished, 1 when a run failed (it is retried on the next invocation)
or a smoke cell failed, 2 when the batch could not start (invalid experiment.toml, no image, missing
credentials, or experiment.toml changed since the batch started).
"""

import argparse
import hashlib
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ossiq.commands.install import load_skill_content, render_skill

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
EXPERIMENT_FILE = HERE / "experiment.toml"
STARTERS = HERE / "starters"
LOG_ROOT = REPO_ROOT / "qa_logs" / "agent_freshness"

IMAGE = "ossiq-exp"
CONTAINER_HOME = "/home/runner"
CONTAINER_WORKSPACE = "/work"
CONTAINER_PATH = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"
OSSIQ_BIN_DIR = "/opt/ossiq-bin"
# coreutils `timeout` exits with this when it had to stop the agent.
EXIT_TIMEOUT = 124
# Headroom for the host-side backstop over the in-container `timeout`.
HOST_TIMEOUT_SLACK = 120

ARMS = ("baseline", "ossiq")
SKILLS_DIR = ".claude/skills"
CLAUDE_AUTH_ENV = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")
GITHUB_TOKEN_ENV = "OSSIQ_GITHUB_TOKEN"
# Left in a run's HOME only while the agent runs: it holds the GitHub token.
SECRET_FILES = ("mcp.json",)
# Package caches and installed trees: eval.py reads lockfiles, and these add up to gigabytes per batch.
BULKY_DIRS = ("home/.npm", "home/.cache", "workspace/node_modules", "workspace/.venv")

EXPERIMENT_KEYS = frozenset({"seed", "reps", "timeout_minutes", "arms", "models", "ecosystems", "prompt", "tasks"})
MODEL_KEYS = frozenset({"id", "model", "effort"})
ECOSYSTEM_KEYS = frozenset({"preamble"})
TASK_KEYS = frozenset({"id", "ecosystem", "prompt"})

SMOKE_TASK_ID = "SMOKE"
SMOKE_PROMPT = (
    "Don't modify any files. "
    "1) List, by exact name, every tool, MCP tool and skill available to you. "
    "2) If an MCP tool named ossiq_evaluate_dependency exists, call it once with package 'left-pad', "
    "registry_type 'npm', project_path '/work' and runtime {'node': 'unknown'}. "
    "3) If an `ossiq` command is on PATH, run `ossiq info left-pad /work --registry-type npm --format agent`. "
    "Report the next_action each call returned."
)
WEB_SEARCH_MARKERS = ("websearch", "web_search", "web search")

logger = logging.getLogger("ossiq-qa.agent-freshness")


class ExperimentError(Exception):
    """experiment.toml is invalid, or the batch can't run as configured."""


@dataclass(frozen=True)
class Model:
    """One Claude model, at one reasoning effort."""

    id: str
    model: str
    effort: str


@dataclass(frozen=True)
class Task:
    """One request for a manifest."""

    id: str
    ecosystem: str
    prompt: str


@dataclass(frozen=True)
class Experiment:
    """The experiment, as loaded from experiment.toml."""

    seed: int
    reps: int
    timeout_minutes: int
    arms: tuple[str, ...]
    models: tuple[Model, ...]
    tasks: tuple[Task, ...]
    preambles: Mapping[str, str]
    prompt_suffix: str

    def prompt_for(self, task: Task) -> str:
        """Return the exact prompt an agent receives for `task`."""
        return f"{self.preambles[task.ecosystem]} {task.prompt} {self.prompt_suffix}"


@dataclass(frozen=True)
class RunSpec:
    """One cell of the matrix: a model, in an arm, on a task, for one repetition."""

    model: Model
    arm: str
    task: Task
    rep: int

    @property
    def run_id(self) -> str:
        return f"{self.model.id}-{self.arm}-{self.task.id}-r{self.rep}"


@dataclass(frozen=True)
class RunOutcome:
    """How one run ended."""

    run_id: str
    status: str
    exit_code: int
    duration_s: float


def reject_unknown_keys(where: str, raw: Mapping[str, Any], allowed: frozenset[str]) -> None:
    """Fail on a misspelt key, which would otherwise silently fall back to a default."""
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ExperimentError(f"{where}: unknown key(s) {', '.join(unknown)}; expected {', '.join(sorted(allowed))}")


def parse_experiment(raw: Mapping[str, Any]) -> Experiment:
    """Validate the parsed experiment.toml and build the experiment from it.

    Raises:
        ExperimentError: On an unknown key, a duplicate id, or a reference to an undefined arm or
            ecosystem.
    """
    reject_unknown_keys("experiment.toml", raw, EXPERIMENT_KEYS)
    for name, ecosystem in raw["ecosystems"].items():
        reject_unknown_keys(f"[ecosystems.{name}]", ecosystem, ECOSYSTEM_KEYS)

    models = []
    for entry in raw["models"]:
        reject_unknown_keys(f"model {entry.get('id')}", entry, MODEL_KEYS)
        models.append(Model(id=entry["id"], model=entry["model"], effort=entry.get("effort", "")))

    tasks = []
    for entry in raw["tasks"]:
        reject_unknown_keys(f"task {entry.get('id')}", entry, TASK_KEYS)
        if entry["ecosystem"] not in raw["ecosystems"]:
            raise ExperimentError(f"task {entry['id']}: undefined ecosystem {entry['ecosystem']!r}")
        tasks.append(Task(id=entry["id"], ecosystem=entry["ecosystem"], prompt=entry["prompt"]))

    for kind, ids in (("model", [m.id for m in models]), ("task", [t.id for t in tasks])):
        if len(ids) != len(set(ids)):
            raise ExperimentError(f"duplicate {kind} id in {ids}")
    unknown_arms = set(raw["arms"]) - set(ARMS)
    if unknown_arms:
        raise ExperimentError(f"unknown arm(s) {', '.join(sorted(unknown_arms))}; expected {', '.join(ARMS)}")

    return Experiment(
        seed=raw["seed"],
        reps=raw["reps"],
        timeout_minutes=raw["timeout_minutes"],
        arms=tuple(raw["arms"]),
        models=tuple(models),
        tasks=tuple(tasks),
        preambles={name: ecosystem["preamble"] for name, ecosystem in raw["ecosystems"].items()},
        prompt_suffix=raw["prompt"]["suffix"],
    )


def plan_runs(
    experiment: Experiment, models: Sequence[Model], arms: Sequence[str], tasks: Sequence[Task], reps: int
) -> list[RunSpec]:
    """Expand the matrix and shuffle it, so arms and models interleave in time.

    Registry state drifts during a batch; interleaving spreads that drift evenly across the arms
    instead of handing the later releases to whichever arm happens to run last.

    Returns:
        The runs in execution order.
    """
    runs = [
        RunSpec(model=model, arm=arm, task=task, rep=rep)
        for model in models
        for arm in arms
        for task in tasks
        for rep in range(reps)
    ]
    random.Random(experiment.seed).shuffle(runs)
    return runs


def write_text(path: Path, content: str) -> None:
    """Write `content` to `path`, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def arm_environment(spec: RunSpec) -> tuple[dict[str, str], list[str]]:
    """The variables a run's container gets beyond HOME.

    Returns:
        Plain values for the docker command line (the arm's PATH), and the names of secrets docker
        copies from the host environment, which keeps their values out of `ps`.
    """
    # The workspace is a bind mount owned by the host user; without this git refuses to touch it.
    values = {
        "DISABLE_AUTOUPDATER": "1",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
    }
    secrets = [name for name in CLAUDE_AUTH_ENV if os.environ.get(name)]
    if spec.arm == "ossiq":
        values["PATH"] = f"{OSSIQ_BIN_DIR}:{CONTAINER_PATH}"
        secrets.append(GITHUB_TOKEN_ENV)
    return values, secrets


def prepare_home(spec: RunSpec, home: Path) -> None:
    """Lay out the run's HOME for its arm: the ossiq skill and MCP config, or nothing."""
    if spec.arm != "ossiq":
        return
    # What `ossiq install skills claude --via ossiq` writes, without its MCP config: see qa/README.md.
    write_text(home / SKILLS_DIR / "ossiq" / "SKILL.md", render_skill(load_skill_content(), "ossiq"))
    server = {
        "command": f"{OSSIQ_BIN_DIR}/ossiq",
        "args": ["mcp"],
        "env": {GITHUB_TOKEN_ENV: os.environ[GITHUB_TOKEN_ENV]},
    }
    write_text(home / "mcp.json", json.dumps({"mcpServers": {"ossiq": server}}, indent=2))


def prepare_workspace(spec: RunSpec, workspace: Path) -> None:
    """Copy the ecosystem's starter project, which declares no dependencies, into the run."""
    shutil.copytree(STARTERS / spec.task.ecosystem, workspace)


def agent_command(spec: RunSpec) -> list[str]:
    """The headless Claude Code invocation for this run's model and arm; it reads the prompt on stdin."""
    command = [
        "claude",
        "-p",
        "--model",
        spec.model.model,
        "--output-format",
        "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
        "--strict-mcp-config",
    ]
    if spec.arm == "ossiq":
        command += ["--mcp-config", f"{CONTAINER_HOME}/mcp.json"]
    if spec.model.effort:
        command += ["--effort", spec.model.effort]
    return command


def container_name(spec: RunSpec, run_dir: Path) -> str:
    """The name of the run's container, so a host-side timeout can remove it."""
    return f"exp-{run_dir.parent.name}-{spec.run_id}"


def docker_command(spec: RunSpec, experiment: Experiment, run_dir: Path, image: str) -> list[str]:
    """The `docker run` that starts one agent. The prompt is not in it: run_one sends it on stdin.

    As an argument, the prompt would sit in the agent's own process arguments, and a cleanup like
    `kill $(pgrep -f main.py)` or a scan of /proc/*/cmdline would then kill the agent itself whenever
    the prompt names that file. The image has no pkill, so agents write exactly that scan.
    """
    values, secrets = arm_environment(spec)
    docker = ["docker", "run", "--rm", "-i", "--name", container_name(spec, run_dir), "--user", "1000:1000"]
    docker += [
        "-v",
        f"{run_dir / 'workspace'}:{CONTAINER_WORKSPACE}",
        "-v",
        f"{run_dir / 'home'}:{CONTAINER_HOME}",
        "-e",
        f"HOME={CONTAINER_HOME}",
    ]
    for name, value in values.items():
        docker += ["-e", f"{name}={value}"]
    for name in secrets:
        docker += ["-e", name]
    return [*docker, image, "timeout", "-k", "30", str(experiment.timeout_minutes * 60), *agent_command(spec)]


def run_one(spec: RunSpec, prompt: str, run_dir: Path, experiment: Experiment, image: str) -> RunOutcome:
    """Run one agent in a fresh container and record what it did.

    Returns:
        `done` when the agent finished or hit the timeout (both are results), `failed` otherwise
        (killed early, an empty transcript, an infrastructure or auth error; retried on the next
        invocation).
    """
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    workspace, home = run_dir / "workspace", run_dir / "home"
    prepare_workspace(spec, workspace)
    home.mkdir()
    prepare_home(spec, home)

    timeout_s = experiment.timeout_minutes * 60
    docker = docker_command(spec, experiment, run_dir, image)

    started = datetime.now(UTC)
    with (run_dir / "transcript.jsonl").open("w") as out, (run_dir / "stderr.log").open("w") as err:
        try:
            exit_code = subprocess.run(
                docker, input=prompt, text=True, stdout=out, stderr=err, timeout=timeout_s + HOST_TIMEOUT_SLACK
            ).returncode
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", container_name(spec, run_dir)], capture_output=True, check=False)
            exit_code = EXIT_TIMEOUT
    finished = datetime.now(UTC)

    for name in SECRET_FILES:
        (home / name).unlink(missing_ok=True)
    for name in BULKY_DIRS:
        shutil.rmtree(run_dir / name, ignore_errors=True)

    # Exit 0 with no closing event is no result: a container stopped from outside can end that way.
    finished_cleanly = exit_code == EXIT_TIMEOUT or (exit_code == 0 and has_result_event(run_dir / "transcript.jsonl"))
    status = "done" if finished_cleanly else "failed"
    meta = {
        "run_id": spec.run_id,
        "model": spec.model.id,
        "model_name": spec.model.model,
        "effort": spec.model.effort,
        "arm": spec.arm,
        "task": spec.task.id,
        "ecosystem": spec.task.ecosystem,
        "rep": spec.rep,
        "prompt": prompt,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_s": round((finished - started).total_seconds(), 1),
        "exit_code": exit_code,
        "timed_out": exit_code == EXIT_TIMEOUT,
        "status": status,
    }
    write_text(run_dir / "meta.json", json.dumps(meta, indent=2))
    return RunOutcome(spec.run_id, status, exit_code, meta["duration_s"])


def is_done(run_dir: Path) -> bool:
    """Whether a previous invocation already finished this run."""
    meta = run_dir / "meta.json"
    return meta.is_file() and json.loads(meta.read_text(encoding="utf-8")).get("status") == "done"


def has_result_event(transcript: Path) -> bool:
    """Whether the stream holds Claude's closing `result` event, which a run stopped early never writes."""
    for line in transcript.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "result":
            return True
    return False


def command_output(command: Sequence[str]) -> str:
    """Run a short command and return its stripped stdout, or an empty string when it fails."""
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def record_batch(batch_dir: Path, image: str) -> None:
    """Write batch.json once, and refuse to continue a batch whose experiment.toml has changed since.

    Raises:
        ExperimentError: When experiment.toml no longer matches the batch it started.
    """
    raw = EXPERIMENT_FILE.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    path = batch_dir / "batch.json"
    if path.is_file():
        recorded = json.loads(path.read_text(encoding="utf-8"))["experiment_sha256"]
        if recorded != digest:
            raise ExperimentError(f"experiment.toml changed since {batch_dir.name} started; start a new --batch")
        return
    versions = command_output(
        [
            "docker",
            "run",
            "--rm",
            image,
            "sh",
            "-c",
            f"claude --version; {OSSIQ_BIN_DIR}/ossiq --version",
        ]
    )
    batch = {
        "created_at": datetime.now(UTC).isoformat(),
        "git_sha": command_output(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"]),
        "git_dirty": bool(command_output(["git", "-C", str(REPO_ROOT), "status", "--porcelain"])),
        "image_id": command_output(["docker", "image", "inspect", "-f", "{{.Id}}", image]),
        "versions": versions.splitlines(),
        "experiment_sha256": digest,
        "experiment": tomllib.loads(raw.decode("utf-8")),
    }
    write_text(path, json.dumps(batch, indent=2))


def missing_credentials(runs: Sequence[RunSpec]) -> list[str]:
    """Name every credential the selected runs need but the environment lacks."""
    missing = []
    if runs and not any(os.environ.get(name) for name in CLAUDE_AUTH_ENV):
        missing.append(f"one of {', '.join(CLAUDE_AUTH_ENV)} (`claude setup-token` prints an OAuth token)")
    if any(run.arm == "ossiq" for run in runs) and not os.environ.get(GITHUB_TOKEN_ENV):
        missing.append(GITHUB_TOKEN_ENV)
    return missing


def smoke_problems(spec: RunSpec, run_dir: Path, outcome: RunOutcome) -> list[str]:
    """Check one smoke cell: the model answered, and the arm saw exactly the help it should.

    The prompt itself names ossiq, so a reply mentioning it proves nothing. The checks look for what
    only a real tool leaves behind: the MCP server's tool names, and `recommended_version`, a field
    of ossiq's answer that the prompt never mentions.
    """
    text = (run_dir / "transcript.jsonl").read_text(encoding="utf-8", errors="replace").lower()
    compact = text.replace(" ", "")
    mcp_present = "mcp__ossiq__" in text or '"server":"ossiq"' in compact
    answered = "recommended_version" in text
    problems = [] if outcome.exit_code == 0 else [f"exit {outcome.exit_code} (see stderr.log)"]
    if not any(marker in text for marker in WEB_SEARCH_MARKERS):
        problems.append("no web search tool")
    if spec.arm == "ossiq":
        if not mcp_present:
            problems.append("ossiq MCP server missing")
        if not answered:
            problems.append("no ossiq answer")
        if "pending_user_action" in text:
            problems.append("ossiq asked for a GitHub login")
    elif mcp_present or answered or "ossiq-dependency-check" in text:
        problems.append("ossiq reachable outside the ossiq arm")
    return problems


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--batch", help="batch name: results go to qa_logs/agent_freshness/<batch>/")
    parser.add_argument("--smoke", action="store_true", help="one tool-listing run per model x arm, then checks")
    parser.add_argument("--models", help="comma-separated model ids (default: all)")
    parser.add_argument("--arms", help="comma-separated arms (default: all)")
    parser.add_argument("--tasks", help="comma-separated task ids (default: all)")
    parser.add_argument("--reps", type=int, help="repetitions per cell (default: experiment.toml)")
    parser.add_argument("--parallel", type=int, default=4, help="containers at a time (default: 4)")
    parser.add_argument("--image", default=IMAGE, help=f"agent image (default: {IMAGE})")
    parser.add_argument("--dry-run", action="store_true", help="list the runs and exit")
    return parser.parse_args()


def select(kind: str, wanted: str | None, available: Sequence[Any], key: Callable[[Any], str]) -> list[Any]:
    """Filter `available` by a comma-separated list of ids, rejecting ids that don't exist.

    Raises:
        ExperimentError: When an id isn't defined.
    """
    if not wanted:
        return list(available)
    ids = [part.strip() for part in wanted.split(",") if part.strip()]
    known = {key(item): item for item in available}
    unknown = [name for name in ids if name not in known]
    if unknown:
        raise ExperimentError(f"unknown {kind}: {', '.join(unknown)}; expected {', '.join(known)}")
    return [known[name] for name in ids]


def main() -> int:
    args = parse_args()
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    if not args.smoke and not args.batch:
        logger.error("pass --batch NAME (or --smoke)")
        return 2

    try:
        experiment = parse_experiment(tomllib.loads(EXPERIMENT_FILE.read_text(encoding="utf-8")))
        models = select("model", args.models, experiment.models, lambda m: m.id)
        arms = select("arm", args.arms, experiment.arms, lambda a: a)
        if args.smoke:
            tasks = [Task(SMOKE_TASK_ID, "npm", SMOKE_PROMPT)]
            reps = 1
        else:
            tasks = select("task", args.tasks, experiment.tasks, lambda t: t.id)
            reps = args.reps or experiment.reps
    except (ExperimentError, tomllib.TOMLDecodeError, KeyError) as error:
        logger.error(f"experiment.toml: {error}")
        return 2

    batch = args.batch or f"smoke-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
    batch_dir = LOG_ROOT / batch
    runs = plan_runs(experiment, models, arms, tasks, reps)
    pending = [run for run in runs if not is_done(batch_dir / run.run_id)]
    logger.info(f"{batch}: {len(runs)} runs, {len(runs) - len(pending)} already done, {len(pending)} to go")
    if args.dry_run:
        for run in pending:
            logger.info(f"  {run.run_id}")
        return 0

    missing = missing_credentials(pending)
    if missing:
        logger.error("missing credentials: " + "; ".join(missing))
        return 2
    if not command_output(["docker", "image", "inspect", "-f", "{{.Id}}", args.image]):
        logger.error(f"docker image {args.image} not found: run `just exp-build`")
        return 2

    batch_dir.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(batch_dir / "summary.log", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(file_handler)
    try:
        record_batch(batch_dir, args.image)
    except ExperimentError as error:
        logger.error(str(error))
        return 2

    failures: list[str] = []
    finished = 0
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = {
            pool.submit(
                run_one,
                run,
                SMOKE_PROMPT if args.smoke else experiment.prompt_for(run.task),
                batch_dir / run.run_id,
                experiment,
                args.image,
            ): run
            for run in pending
        }
        for future in as_completed(futures):
            run = futures[future]
            outcome = future.result()
            problems = smoke_problems(run, batch_dir / run.run_id, outcome) if args.smoke else []
            if outcome.status != "done":
                problems.append(f"failed with exit {outcome.exit_code}")
            finished += 1
            verdict = "FAIL " + "; ".join(problems) if problems else "ok"
            logger.info(f"[{finished}/{len(pending)}] {run.run_id} {verdict} ({outcome.duration_s:.0f}s)")
            if problems:
                failures.append(run.run_id)

    logger.info(f"{len(pending) - len(failures)} ok, {len(failures)} failed; logs in {batch_dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
