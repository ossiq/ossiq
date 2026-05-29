#!/usr/bin/env python3
"""QA smoke-test: status→export→plan→apply→re-export against real-world repos.

Fetches only manifest files via the GitHub API — no full clones.
Usage: python qa/smoke_matrix.py  (or: just qa-matrix)
"""

import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

REPO_ROOT = Path(__file__).parent.parent
WORKSPACE = Path(os.environ.get("OSSIQ_QA_WORKSPACE", "/workspace"))
LOG_ROOT = Path(os.environ.get("OSSIQ_QA_LOGS", "/qa_logs"))
CACHE_FILE = os.environ.get("OSSIQ_QA_CACHE", "/cache/ossiq_cache.sqlite3")
GITHUB_TOKEN = os.environ.get("OSSIQ_GITHUB_TOKEN", "")

# Use the pre-built venv binary directly — bypasses uv sync and hatch build hooks entirely.
VENV_BIN = Path(os.environ.get("UV_PROJECT_ENVIRONMENT", "/home/qarunner/.venv")) / "bin"
OSSIQ_CMD = [str(VENV_BIN / "ossiq-cli")]

# ecosystem, owner/repo, tag, cutoff_date  (cutoff ≈ tag release date + 12 months)
TARGETS: list[tuple[str, str, str, str]] = [
    # ("npm", "koajs/koa", "2.14.2", "2024-01-01"),
    # ("npm", "mochajs/mocha", "v11.0.1", "2024-12-01"),
    # ("npm",  "graphql/graphql-js",  "v16.6.0", "2023-09-01"),
    # ("npm",  "typeorm/typeorm",     "v0.3.11", "2023-09-01"),
    ("npm", "socketio/socket.io", "4.5.4", "2023-11-01"),
    # ("pypi", "psf/requests",        "v2.28.1", "2023-07-01"),
    # ("pypi", "pallets/flask",       "2.2.2",   "2023-10-01"),
    # ("pypi", "pydantic/pydantic",   "v1.10.2", "2023-09-01"),
    # ("pypi", "tiangolo/fastapi",    "0.88.0",  "2023-12-01"),
    # ("pypi", "encode/httpx",        "0.23.3",  "2023-12-01"),
    # ("pypi", "pallets/click",       "8.1.3",   "2023-05-01"),
    # ("pypi", "celery/celery",       "v5.2.7",  "2023-06-01"),
    # ("pypi", "django/django",       "4.1.4",   "2023-12-01"),
    # ("pypi", "encode/starlette",    "0.22.0",  "2023-11-01"),
    # ("pypi", "apache/airflow",      "2.5.0",   "2023-07-01"),
]

TAIL_LINES = 40

logger: logging.Logger = logging.getLogger("ossiq-qa")


# ---------------------------------------------------------------------------
# Run result
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    """Result of a single subprocess invocation."""

    rc: int
    stdout: str
    stderr: str
    elapsed: float
    cmd: list[str]
    timed_out: bool = field(default=False)

    @property
    def ok(self) -> bool:
        """Return True when the command exited 0 and did not time out."""
        return self.rc == 0 and not self.timed_out


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def setup_logging(log_root: Path) -> None:
    """Configure the module-level logger with console + file handlers."""
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-4s] %(message)s", datefmt="%H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    file_handler = logging.FileHandler(log_root / "summary.log")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)


def log_failure(target_id: str, step: str, result: RunResult) -> None:
    """Inline the command and output tail into summary.log so triage needs no secondary files."""
    rc_label = "TIMEOUT" if result.timed_out else str(result.rc)
    logger.error("%s | %s failed (rc=%s, elapsed=%.1fs)", target_id, step, rc_label, result.elapsed)
    logger.error("%s | cmd: %s", target_id, shlex.join(result.cmd))

    def tail(text: str, label: str) -> None:
        lines = text.splitlines()
        if not lines:
            return
        trimmed = lines[-TAIL_LINES:]
        if len(lines) > TAIL_LINES:
            logger.error("%s | %s (last %d/%d lines):", target_id, label, TAIL_LINES, len(lines))
        else:
            logger.error("%s | %s:", target_id, label)
        for line in trimmed:
            logger.error("%s |   %s", target_id, line)

    tail(result.stdout, "stdout")
    tail(result.stderr, "stderr")


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------


def run_cmd(args: list[str], cwd: Path, timeout: int, log_path: Path) -> RunResult:
    """Run a command and write a full transcript to log_path.

    Captures stdout and stderr. On timeout the partial output is preserved.
    """
    start = time.monotonic()
    stdout = ""
    stderr = ""
    rc = -1
    timed_out = False

    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        stdout = proc.stdout
        stderr = proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        raw_out = exc.stdout or b""
        raw_err = exc.stderr or b""
        stdout = raw_out.decode(errors="replace") if isinstance(raw_out, bytes) else str(raw_out)
        stderr = raw_err.decode(errors="replace") if isinstance(raw_err, bytes) else str(raw_err)

    elapsed = time.monotonic() - start
    divider = "─" * 60

    with log_path.open("w") as f:
        f.write(f"CMD:     {shlex.join(args)}\n")
        f.write(f"CWD:     {cwd}\n")
        f.write(f"STARTED: {datetime.now(UTC).isoformat()}\n")
        f.write(f"{divider}\n")
        f.write("STDOUT:\n")
        f.write(stdout if stdout else "(empty)\n")
        f.write(f"\n{divider}\n")
        f.write("STDERR:\n")
        f.write(stderr if stderr else "(empty)\n")
        f.write(f"\n{divider}\n")
        if timed_out:
            f.write(f"RESULT:  TIMEOUT after {elapsed:.1f}s\n")
        else:
            f.write(f"RC:      {rc}\n")
            f.write(f"ELAPSED: {elapsed:.1f}s\n")

    return RunResult(rc=rc, stdout=stdout, stderr=stderr, elapsed=elapsed, cmd=list(args), timed_out=timed_out)


# ---------------------------------------------------------------------------
# Manifest fetchers
# ---------------------------------------------------------------------------


def fetch_manifest(repo: str, filepath: str, tag: str, dest: Path) -> bool:
    """Fetch one file from the GitHub Contents API. Returns True when dest is non-empty."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/contents/{filepath}?ref={tag}", "-H", "Accept: application/vnd.github.raw"],
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        logger.debug("fetch_manifest %s/%s@%s: timed out", repo, filepath, tag)
        return False
    if result.returncode != 0:
        logger.debug(
            "fetch_manifest %s/%s@%s: rc=%d — %s",
            repo,
            filepath,
            tag,
            result.returncode,
            result.stderr.decode(errors="replace").strip(),
        )
        return False
    dest.write_bytes(result.stdout)
    return dest.stat().st_size > 0


def fetch_npm(repo: str, tag: str, target_dir: Path) -> bool:
    """Fetch package.json + package-lock.json. Returns True when both are present and non-empty."""
    pkg_ok = fetch_manifest(repo, "package.json", tag, target_dir / "package.json")
    lock_ok = fetch_manifest(repo, "package-lock.json", tag, target_dir / "package-lock.json")
    return pkg_ok and lock_ok


def fetch_pypi(repo: str, tag: str, target_dir: Path) -> bool:
    """Fetch PyPI manifests in priority order. Returns True when a usable set is present."""
    pyproject_ok = fetch_manifest(repo, "pyproject.toml", tag, target_dir / "pyproject.toml")
    uv_lock_ok = fetch_manifest(repo, "uv.lock", tag, target_dir / "uv.lock")
    if pyproject_ok and uv_lock_ok:
        return True
    (target_dir / "uv.lock").unlink(missing_ok=True)

    if pyproject_ok:
        req_ok = fetch_manifest(repo, "requirements.txt", tag, target_dir / "requirements.txt")
        if req_ok:
            return True
    (target_dir / "pyproject.toml").unlink(missing_ok=True)

    return fetch_manifest(repo, "requirements.txt", tag, target_dir / "requirements.txt")


# ---------------------------------------------------------------------------
# Per-target pipeline
# ---------------------------------------------------------------------------


def build_base_args(cutoff: str) -> list[str]:
    """Return global ossiq-cli flags that precede every subcommand."""
    args = ["--cache-destination", CACHE_FILE, "--cutoff-date", cutoff]
    return args


def run_target(ecosystem: str, repo: str, tag: str, cutoff: str, target_id: str) -> Literal["PASS", "FAIL", "SKIP"]:
    """Run the full 9-step smoke pipeline for one target. Returns PASS, FAIL, or SKIP."""
    target_dir = WORKSPACE / target_id
    logs_dir = LOG_ROOT / target_id
    target_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    def write_result(value: str) -> None:
        (logs_dir / "result.log").write_text(f"{value}\n")

    # --- Manifest fetch -------------------------------------------------------
    logger.info("%s | fetching manifests (%s @ %s)", target_id, repo, tag)
    if ecosystem == "npm":
        if not fetch_npm(repo, tag, target_dir):
            logger.warning("%s | SKIP: package.json or package-lock.json not found at tag %s", target_id, tag)
            write_result("SKIP")
            return "SKIP"
    else:
        if not fetch_pypi(repo, tag, target_dir):
            logger.warning("%s | SKIP: no supported PyPI manifest at tag %s", target_id, tag)
            write_result("SKIP")
            return "SKIP"

    base_args = build_base_args(cutoff)

    # --- Step 03: status ------------------------------------------------------
    logger.info("%s | step 03 status", target_id)
    result = run_cmd(
        OSSIQ_CMD + base_args + ["status", str(target_dir)],
        cwd=REPO_ROOT,
        timeout=300,
        log_path=logs_dir / "03_status.log",
    )
    if not result.ok:
        log_failure(target_id, "step 03 status", result)
        write_result("FAIL:step03")
        return "FAIL"

    # --- Step 04: pre-apply export --------------------------------------------
    logger.info("%s | step 04 export", target_id)
    pre_export = logs_dir / "04_pre_export.json"
    result = run_cmd(
        OSSIQ_CMD + base_args + ["export", "--schema-version", "1.4", "--output", str(pre_export), str(target_dir)],
        cwd=REPO_ROOT,
        timeout=120,
        log_path=logs_dir / "04_export.log",
    )
    if not result.ok:
        log_failure(target_id, "step 04 export", result)
        write_result("FAIL:step04")
        return "FAIL"

    with pre_export.open() as f:
        export_data: dict = json.load(f)

    pkg_count: int = export_data.get("summary", {}).get("total_packages", 0)
    if pkg_count == 0:
        logger.warning("%s | SKIP: export returned 0 packages", target_id)
        write_result("SKIP")
        shutil.rmtree(target_dir, ignore_errors=True)
        return "SKIP"

    # --- Step 05: downgrade assertion (WARN only) ----------------------------
    downgrades = [
        p
        for p in export_data.get("production_packages", [])
        if p.get("recommended_version") is not None
        and p.get("recommended_version") != p.get("installed_version")
        and (p.get("time_lag_days") or 0) < 0
    ]
    if downgrades:
        logger.warning(
            "%s | step 05 — %d package(s) have recommended < installed (time_lag_days < 0)",
            target_id,
            len(downgrades),
        )

    # --- Step 06: plan --------------------------------------------------------
    logger.info("%s | step 06 plan", target_id)
    result = run_cmd(
        OSSIQ_CMD + base_args + ["plan", str(target_dir)],
        cwd=REPO_ROOT,
        timeout=300,
        log_path=logs_dir / "06_plan.log",
    )
    if not result.ok:
        log_failure(target_id, "step 06 plan", result)
        write_result("FAIL:step06")
        return "FAIL"

    # --- Step 07: apply -------------------------------------------------------
    logger.info("%s | step 07 apply", target_id)
    result = run_cmd(
        OSSIQ_CMD + base_args + ["apply", "--yes", str(target_dir)],
        cwd=REPO_ROOT,
        timeout=600,
        log_path=logs_dir / "07_apply.log",
    )
    if not result.ok:
        log_failure(target_id, "step 07 apply", result)
        write_result("FAIL:step07")
        return "FAIL"

    # --- Step 07b: npm lock regeneration -------------------------------------
    if ecosystem == "npm" and shutil.which("npm"):
        npm_result = run_cmd(
            ["npm", "install", "--prefix", str(target_dir), "--package-lock-only"],
            cwd=target_dir,
            timeout=120,
            log_path=logs_dir / "07b_npm_install.log",
        )
        if not npm_result.ok:
            logger.warning(
                "%s | step 07b npm --package-lock-only failed (rc=%d); step 09 comparison may be inaccurate",
                target_id,
                npm_result.rc,
            )

    # --- Step 08: post-apply status -------------------------------------------
    logger.info("%s | step 08 status (post-apply)", target_id)
    result = run_cmd(
        OSSIQ_CMD + base_args + ["status", str(target_dir)],
        cwd=REPO_ROOT,
        timeout=300,
        log_path=logs_dir / "08_status_post.log",
    )
    if not result.ok:
        log_failure(target_id, "step 08 post-apply status", result)
        write_result("FAIL:step08")
        return "FAIL"

    # --- Step 09: post-apply export + comparison ------------------------------
    logger.info("%s | step 09 export (post-apply)", target_id)
    post_export = logs_dir / "09_post_export.json"
    result = run_cmd(
        OSSIQ_CMD + base_args + ["export", "--schema-version", "1.4", "--output", str(post_export), str(target_dir)],
        cwd=REPO_ROOT,
        timeout=120,
        log_path=logs_dir / "09_export.log",
    )
    if not result.ok:
        log_failure(target_id, "step 09 post-apply export", result)
        write_result("FAIL:step09")
        return "FAIL"

    with post_export.open() as f:
        post_data: dict = json.load(f)

    recs = {p["package_name"]: p.get("recommended_version") for p in export_data.get("production_packages", [])}
    post = {p["package_name"]: p.get("installed_version") for p in post_data.get("production_packages", [])}
    comparison = [
        {"package": name, "expected": ver, "got": post.get(name), "ok": ver == post.get(name)}
        for name, ver in recs.items()
        if ver is not None
    ]
    (logs_dir / "09_comparison.json").write_text(json.dumps(comparison, indent=2))

    not_applied = [c for c in comparison if not c["ok"]]
    if not_applied:
        logger.warning(
            "%s | step 09 — %d package(s) not at recommended version post-apply",
            target_id,
            len(not_applied),
        )

    # --- Crash check ----------------------------------------------------------
    for log_file in logs_dir.glob("*.log"):
        content = log_file.read_text(errors="replace")
        if "Traceback" in content:
            logger.error("%s | Python traceback found in %s", target_id, log_file.name)
            write_result("FAIL:traceback")
            return "FAIL"

    logger.info("%s | PASS (packages=%d)", target_id, pkg_count)
    write_result("PASS")
    shutil.rmtree(target_dir, ignore_errors=True)
    return "PASS"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point: iterate TARGETS, run each pipeline, print summary."""
    if not GITHUB_TOKEN:
        print("[ERROR] OSSIQ_GITHUB_TOKEN is not set", file=sys.stderr)
        sys.exit(1)

    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    setup_logging(LOG_ROOT)

    logger.info("ossiq QA matrix — %s", datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    logger.info("WORKSPACE=%s  LOG_ROOT=%s  CACHE=%s", WORKSPACE, LOG_ROOT, CACHE_FILE)

    passed: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []

    for ecosystem, repo, tag, cutoff in TARGETS:
        name = repo.split("/")[-1]
        target_id = f"{ecosystem}_{name}_{tag.removeprefix('v')}"
        logger.info("--- %s ---", target_id)

        outcome = run_target(ecosystem, repo, tag, cutoff, target_id)
        if outcome == "PASS":
            passed.append(target_id)
        elif outcome == "SKIP":
            skipped.append(target_id)
        else:
            failed.append(target_id)

    logger.info("=" * 60)
    logger.info("Results: %d passed, %d skipped, %d failed", len(passed), len(skipped), len(failed))
    if failed:
        logger.info("Failed targets:")
        for t in failed:
            logger.info("  - %s  (logs: %s/%s/)", t, LOG_ROOT, t)

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
