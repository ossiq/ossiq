"""Reproduce D1: which input flips `ossiq_evaluate_updates` for a CommonJS project.

Starts a fresh `ossiq mcp` process per run, the way the agent benchmark did, calls
`ossiq_evaluate_updates` once, and groups the per-package outcomes by variant. Each variant changes
exactly one input (strategy argument, Node on PATH, probe timing, cache state, cutoff date) so a
variant whose outcomes differ from the baseline names the input that decides the recommendation.

Run from the repository root:

    uv run python scripts/repro/mcp_determinism.py --runs 5 \
        --node-bin ~/.nvm/versions/node/v18.20.8/bin --node-bin ~/.nvm/versions/node/v22.12.0/bin

Raw responses are written to --out (one JSON file per run) for diffing against the benchmark's
archived s1/s3 responses.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROJECT = REPO_ROOT / "testdata" / "npm" / "small-cjs"
DEFAULT_CUTOFF = "2026-09-08"
# One second past adapters.runtime_environment.PROBE_TIMEOUT, so the probe gives up.
SLOW_NODE_DELAY_SECONDS = 4
WATCHED_FIELDS = ("to", "recommended_module_system", "latest_compatible_major", "breaking_change", "next_action")
MINIMAL_PATH = "/usr/bin:/bin"


@dataclass(frozen=True)
class Variant:
    """One way of starting the MCP server and calling it; differs from the baseline in one input."""

    name: str
    global_args: tuple[str, ...] = ()
    tool_args: dict[str, Any] = field(default_factory=dict)
    path: str | None = None
    fresh_cache: bool = False
    use_cutoff: bool = True
    runtime: object = "unknown"
    """The MCP `runtime` argument (required since D1-1); None omits it to check the titled error."""


STATED_NODE_VERSIONS = ("18.20.8", "20.18.3", "22.12.0", "26.8.1")


def ossiq_executable() -> Path:
    """The `ossiq` console script of the interpreter running this file, so PATH can be stripped."""
    executable = Path(sys.executable).parent / "ossiq"
    if not executable.exists():
        raise SystemExit(f"ossiq entry point not found next to {sys.executable}; run via `uv run python ...`")
    return executable


def slow_node_dir(workdir: Path) -> Path:
    """A directory whose `node` answers `--version` only after the runtime probe has timed out."""
    real_node = shutil.which("node")
    if real_node is None:
        raise SystemExit("slow-node variant needs a real `node` on PATH")
    target = workdir / "slow-node"
    target.mkdir(exist_ok=True)
    wrapper = target / "node"
    wrapper.write_text(f'#!/bin/sh\nsleep {SLOW_NODE_DELAY_SECONDS}\nexec "{real_node}" "$@"\n')
    wrapper.chmod(0o755)
    return target


def build_variants(node_bins: list[Path], workdir: Path, include_slow: bool) -> list[Variant]:
    """The baseline plus one variant per input the benchmark could have varied between runs."""
    current_path = os.environ.get("PATH", MINIMAL_PATH)
    variants = [
        Variant("baseline (strategy omitted)"),
        Variant("strategy=standard", tool_args={"update_strategy": "standard"}),
        Variant("strategy=latest", tool_args={"update_strategy": "latest"}),
        Variant("no node on PATH", path=MINIMAL_PATH),
        Variant("--no-probe-runtime", global_args=("--no-probe-runtime",)),
        Variant("cold cache per run", fresh_cache=True),
        Variant("no --cutoff-date", use_cutoff=False),
    ]
    for node_bin in node_bins:
        node_version = subprocess.run(
            [str(node_bin / "node"), "--version"], capture_output=True, text=True, check=True
        ).stdout.strip()
        variants.append(Variant(f"node {node_version}", path=f"{node_bin}:{MINIMAL_PATH}"))
        variants.append(
            Variant(
                f"node {node_version} + strategy=latest",
                path=f"{node_bin}:{MINIMAL_PATH}",
                tool_args={"update_strategy": "latest"},
            )
        )
    if include_slow:
        variants.append(Variant("node slower than probe timeout", path=f"{slow_node_dir(workdir)}:{current_path}"))
    # D1-1: the stated runtime, not PATH, decides. Every PATH variant above passes "unknown" and
    # should now agree with the baseline; these are the ones expected to differ.
    for node_version in STATED_NODE_VERSIONS:
        for strategy in ("standard", "latest"):
            variants.append(
                Variant(
                    f"runtime node={node_version} + strategy={strategy}",
                    tool_args={"update_strategy": strategy},
                    runtime={"node": node_version},
                )
            )
    variants.append(Variant("runtime missing (expect the titled error)", runtime=None))
    return variants


def call_evaluate_updates(variant: Variant, project: Path, cutoff: str, cache_dir: Path) -> dict[str, Any]:
    """Start `ossiq mcp`, send initialize + one tools/call, and return the decoded tool payload."""
    global_args = list(variant.global_args)
    if variant.use_cutoff:
        global_args += ["--cutoff-date", cutoff]
    command = [str(ossiq_executable()), "--cache-destination", str(cache_dir), *global_args, "mcp"]

    env = dict(os.environ)
    if variant.path is not None:
        env["PATH"] = variant.path

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "ossiq_evaluate_updates",
                "arguments": {
                    "project_path": str(project),
                    **({"runtime": variant.runtime} if variant.runtime is not None else {}),
                    **variant.tool_args,
                },
            },
        },
    ]
    stdin = "".join(json.dumps(request) + "\n" for request in requests)
    completed = subprocess.run(
        command, input=stdin, capture_output=True, text=True, env=env, cwd=REPO_ROOT, check=False
    )

    for line in completed.stdout.splitlines():
        message = json.loads(line)
        if message.get("id") != 2:
            continue
        result = message.get("result") or {}
        text = result["content"][0]["text"]
        if result.get("isError"):
            return {"error": text}
        return json.loads(text)
    return {"error": f"no tools/call response (exit {completed.returncode}): {completed.stderr[-500:]}"}


def outcome_key(payload: dict[str, Any], packages: tuple[str, ...]) -> str:
    """A compact, comparable summary of the watched fields for the watched packages."""
    if "error" in payload:
        return f"ERROR {payload['error'][:120]}"
    by_name = {entry["package"]: entry for entry in payload.get("updates", [])}
    parts = []
    for name in packages:
        entry = by_name.get(name)
        if entry is None:
            parts.append(f"{name}: <absent>")
            continue
        values = " ".join(f"{key}={entry.get(key)}" for key in WATCHED_FIELDS)
        parts.append(f"{name}: {entry.get('from')}-> {values}")
    runtime = payload.get("runtime_context") or {}
    parts.append(f"engine={runtime.get('engine_versions')} source={runtime.get('engine_context_source')}")
    return "\n    ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", type=Path, default=DEFAULT_PROJECT)
    parser.add_argument("--runs", type=int, default=5, help="Fresh MCP servers per variant")
    parser.add_argument("--cutoff-date", default=DEFAULT_CUTOFF)
    parser.add_argument("--packages", default="chalk,uuid", help="Comma-separated packages to summarise")
    parser.add_argument(
        "--node-bin", type=Path, action="append", default=[], help="Directory holding an alternative `node` binary"
    )
    parser.add_argument("--no-slow-node", action="store_true", help="Skip the probe-timeout variant")
    parser.add_argument("--only", help="Run only variants whose name contains this substring")
    parser.add_argument("--out", type=Path, default=None, help="Where to write raw responses")
    args = parser.parse_args()

    packages = tuple(name.strip() for name in args.packages.split(",") if name.strip())
    workdir = Path(tempfile.mkdtemp(prefix="ossiq-d1-"))
    out_dir = args.out or workdir / "responses"
    out_dir.mkdir(parents=True, exist_ok=True)
    shared_cache = workdir / "shared-cache"

    variants = build_variants([path.expanduser() for path in args.node_bin], workdir, not args.no_slow_node)
    if args.only:
        variants = [variant for variant in variants if args.only in variant.name]

    for variant in variants:
        outcomes: Counter[str] = Counter()
        for run in range(args.runs):
            cache_dir = workdir / f"cache-{variant.name}-{run}" if variant.fresh_cache else shared_cache
            payload = call_evaluate_updates(variant, args.project.resolve(), args.cutoff_date, cache_dir)
            slug = "".join(ch if ch.isalnum() else "-" for ch in variant.name)
            (out_dir / f"{slug}-run{run}.json").write_text(json.dumps(payload, indent=2))
            outcomes[outcome_key(payload, packages)] += 1

        verdict = "stable" if len(outcomes) == 1 else f"FLIPS ({len(outcomes)} distinct outcomes)"
        print(f"\n== {variant.name}: {verdict}")
        for outcome, count in outcomes.most_common():
            print(f"  {count}/{args.runs}  {outcome}")

    print(f"\nRaw responses: {out_dir}")


if __name__ == "__main__":
    main()
