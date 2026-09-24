"""Supply-chain invariants of .github/workflows/: SHA pins, permissions, provenance.

These encode the SLSA v1.2 Build Level 3 posture. Each one stands for a defect that
existed before that work: floating action tags, a workflow with no permissions block at
all, a custom PAT handed to a third-party action on pull-request runs, and no build
provenance anywhere. The trusted-publisher assertions guard the one class of change that
breaks publishing silently rather than loudly.

See docs/how-to/verifying-a-release.md for the consumer side of the same contract.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_ROOT = PROJECT_ROOT / ".github" / "workflows"
VERIFY_DOC = PROJECT_ROOT / "docs" / "how-to" / "verifying-a-release.md"

# `uses:` values that are not a local `./.github/workflows/...` reference must be pinned
# to a full 40-character commit SHA: a tag is mutable, so a floating tag is a build step
# that can change under us. `pypa/gh-action-pypi-publish@release/v1` was a mutable branch.
ACTION_REF_PATTERN = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
USES_LINE_PATTERN = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)(?P<rest>.*)$", re.MULTILINE)

# Registry trusted publishers are bound to (repository, workflow filename, environment).
# PyPI additionally refuses reusable workflows outright, and npm matches the *calling*
# workflow's filename -- so these two files and their environment are load-bearing.
PYPI_PUBLISH_WORKFLOW = "release.yml"
NPM_PUBLISH_WORKFLOW = "binaries.yml"
RELEASE_ENVIRONMENT = "release"
PUBLISH_MARKERS = ("pypa/gh-action-pypi-publish", "npm publish")

# Owners whose actions may receive a secret in a `with:` block. Anything else getting one
# is a credential handed to third-party code.
TRUSTED_ACTION_OWNERS = ("actions", "pypa", "docker", "astral-sh")
ALLOWED_SECRET_NAMES = ("GITHUB_TOKEN", "DOCKER_USERNAME", "DOCKER_PASSWORD")
SECRET_REFERENCE_PATTERN = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")

# The artifact the isolated dist build hands to the publish job. Hardcoded in both files
# rather than plumbed through a workflow output, so it needs an assertion.
DIST_ARTIFACT_NAME = "python-dist"


def workflow_files() -> list[Path]:
    """Every workflow definition, sorted for stable failure output.

    Returns:
        Paths to all .yml files under .github/workflows/.
    """
    return sorted(WORKFLOWS_ROOT.glob("*.yml"))


def reusable_build_files() -> list[Path]:
    """The reusable build workflows that carry the Build L3 signer identities.

    Returns:
        Paths to all reusable-build-*.yml files.
    """
    return sorted(WORKFLOWS_ROOT.glob("reusable-build-*.yml"))


def load_workflow(path: Path) -> dict[str, Any]:
    """Parse a workflow, normalising YAML 1.1's `on` -> True key collapse.

    PyYAML resolves the bare key `on` to the boolean True, so a naive lookup of "on"
    silently misses every trigger block.

    Args:
        path: The workflow file to parse.

    Returns:
        The parsed mapping, with the trigger block available under the "on" key.
    """
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if True in document:
        document["on"] = document.pop(True)
    return document


def jobs_of(path: Path) -> dict[str, dict[str, Any]]:
    """Return a workflow's jobs mapping.

    Args:
        path: The workflow file to parse.

    Returns:
        Job id -> job definition.
    """
    return load_workflow(path).get("jobs") or {}


def executable_text(path: Path) -> str:
    """Every command and action reference a workflow actually runs.

    Excludes comments and prose, so a marker like "npm publish" is not matched by a
    comment explaining where `npm publish` lives.

    Args:
        path: The workflow file to parse.

    Returns:
        The `run` and `uses` values of every job and step, newline-joined.
    """
    parts: list[str] = []
    for job in jobs_of(path).values():
        if "uses" in job:
            parts.append(str(job["uses"]))
        for step in job.get("steps") or []:
            parts.extend(str(step[key]) for key in ("run", "uses") if key in step)
    return "\n".join(parts)


def workflow_running(marker: str) -> list[Path]:
    """Find workflows that actually run `marker`.

    Args:
        marker: Literal substring to search for in executed commands.

    Returns:
        Paths whose steps include the marker.
    """
    return [path for path in workflow_files() if marker in executable_text(path)]


def test_every_action_reference_is_sha_pinned() -> None:
    """A floating tag is a mutable build step, so every action is pinned to a commit."""
    violations: list[str] = []
    for path in workflow_files():
        for match in USES_LINE_PATTERN.finditer(path.read_text(encoding="utf-8")):
            ref = match.group("ref")
            if ref.startswith("./"):
                continue
            if not ACTION_REF_PATTERN.match(ref):
                violations.append(f"{path.name}: {ref}")

    assert not violations, "action references must be pinned to a 40-character SHA:\n  " + "\n  ".join(violations)


def test_every_sha_pin_carries_a_version_comment() -> None:
    """Dependabot reads the trailing `# vX.Y.Z` to bump a pin; humans read it too."""
    violations: list[str] = []
    for path in workflow_files():
        for match in USES_LINE_PATTERN.finditer(path.read_text(encoding="utf-8")):
            ref = match.group("ref")
            if ref.startswith("./"):
                continue
            if not re.match(r"\s*#\s*v?\d", match.group("rest")):
                violations.append(f"{path.name}: {ref}{match.group('rest')}")

    assert not violations, "SHA pins need a trailing version comment:\n  " + "\n  ".join(violations)


def test_every_workflow_declares_permissions() -> None:
    """quality-gate.yml once had none, so it ran at the repo-default token scope."""
    missing = [path.name for path in workflow_files() if "permissions" not in load_workflow(path)]

    assert not missing, f"workflows without a top-level permissions block: {missing}"


def test_jobs_declare_permissions_when_the_workflow_grants_none() -> None:
    """Under `permissions: {}` a job inherits nothing, so it must opt in explicitly."""
    violations: list[str] = []
    for path in workflow_files():
        document = load_workflow(path)
        if document.get("permissions"):
            continue
        for job_id, job in (document.get("jobs") or {}).items():
            if "permissions" not in job:
                violations.append(f"{path.name}:{job_id}")

    assert not violations, "jobs with no permissions under a deny-all workflow:\n  " + "\n  ".join(violations)


@pytest.mark.parametrize(
    ("filename", "marker"),
    [(PYPI_PUBLISH_WORKFLOW, "pypa/gh-action-pypi-publish"), (NPM_PUBLISH_WORKFLOW, "npm publish")],
)
def test_publishing_stays_in_its_registry_bound_workflow(filename: str, marker: str) -> None:
    """Trusted publishers match (repo, workflow filename, environment).

    Moving a publish step to another file, or dropping `environment: release`, breaks
    publishing until the publisher is reconfigured on the registry side -- a failure that
    only shows up mid-release.
    """
    assert (WORKFLOWS_ROOT / filename).is_file(), f"{filename} is bound to a trusted publisher and must not be renamed"

    holders = [path.name for path in workflow_running(marker)]
    assert holders == [filename], f"{marker!r} must appear only in {filename}, found in {holders}"

    environments = {
        job.get("environment", {}).get("name")
        for job in jobs_of(WORKFLOWS_ROOT / filename).values()
        if marker in yaml.safe_dump(job)
    }
    assert environments == {RELEASE_ENVIRONMENT}, (
        f"the publish job in {filename} must keep `environment: {RELEASE_ENVIRONMENT}`, got {environments}"
    )


def test_publish_jobs_are_not_reusable_workflow_calls() -> None:
    """PyPI rejects reusable workflows as trusted publishers, so publishing cannot move.

    Encodes the limitation so a later tidy-up cannot quietly reintroduce it:
    "Reusable workflows cannot currently be used as the workflow in a Trusted Publisher."
    """
    violations: list[str] = []
    for path in workflow_files():
        for job_id, job in jobs_of(path).items():
            if "uses" not in job:
                continue
            body = yaml.safe_dump(job)
            if any(marker in body for marker in PUBLISH_MARKERS):
                violations.append(f"{path.name}:{job_id}")

    assert not violations, "publish steps must not live in a `uses:` job:\n  " + "\n  ".join(violations)


def test_every_reusable_build_workflow_attests_provenance() -> None:
    """The reusable build files exist to sign provenance; one that does not is pointless."""
    assert reusable_build_files(), "no reusable-build-*.yml found, so nothing signs provenance"

    missing = [
        path.name
        for path in reusable_build_files()
        if "actions/attest-build-provenance" not in path.read_text(encoding="utf-8")
    ]

    assert not missing, f"reusable build workflows without an attestation step: {missing}"


def test_reusable_build_workflows_accept_no_inputs() -> None:
    """A caller-supplied input can steer a build this file's identity then vouches for.

    A `runner` input is the sharp case: the caller could point the build at an untrusted
    self-hosted runner while the trusted signer identity still signed the output.
    """
    violations: list[str] = []
    for path in reusable_build_files():
        trigger = load_workflow(path).get("on") or {}
        call = trigger.get("workflow_call") or {}
        if call.get("inputs"):
            violations.append(f"{path.name}: {sorted(call['inputs'])}")

    assert not violations, "reusable build workflows must take no inputs:\n  " + "\n  ".join(violations)


def test_dist_build_disables_build_isolation() -> None:
    """Without it hatchling is resolved fresh from PyPI, unpinned and unhashed.

    PEP 517 `requires` has no hash mechanism, so this is what makes the build backend
    come from uv.lock instead of a live resolve.
    """
    body = (WORKFLOWS_ROOT / "reusable-build-dist.yml").read_text(encoding="utf-8")

    assert "uv build --no-build-isolation" in body, (
        "reusable-build-dist.yml must build with --no-build-isolation so hatchling comes from uv.lock"
    )


def test_release_path_needs_no_node() -> None:
    """The release build must never depend on npm or on a network fetch mid-build."""
    dist_workflow = WORKFLOWS_ROOT / "reusable-build-dist.yml"

    assert "OSSIQ_SKIP_FRONTEND_BUILD" in dist_workflow.read_text(encoding="utf-8"), (
        "reusable-build-dist.yml should signal that it needs no frontend build"
    )
    assert "npm" not in executable_text(dist_workflow), "the dist build path must not invoke npm"


def test_dist_artifact_name_agrees_across_build_and_publish() -> None:
    """The name is hardcoded in both files rather than plumbed through an output."""
    producer = (WORKFLOWS_ROOT / "reusable-build-dist.yml").read_text(encoding="utf-8")
    consumer = (WORKFLOWS_ROOT / PYPI_PUBLISH_WORKFLOW).read_text(encoding="utf-8")

    assert f"name: {DIST_ARTIFACT_NAME}" in producer, f"reusable-build-dist.yml should upload {DIST_ARTIFACT_NAME}"
    assert f"name: {DIST_ARTIFACT_NAME}" in consumer, f"{PYPI_PUBLISH_WORKFLOW} should download {DIST_ARTIFACT_NAME}"


def test_signer_workflow_filenames_are_documented() -> None:
    """Consumers verify against these filenames, so a rename is a breaking change.

    Failing here instead of in users' verify commands is the whole point.
    """
    documented = VERIFY_DOC.read_text(encoding="utf-8")
    undocumented = [path.name for path in reusable_build_files() if path.name not in documented]

    assert not undocumented, f"these signer workflows are not in {VERIFY_DOC.relative_to(PROJECT_ROOT)}: {undocumented}"


def test_no_secret_other_than_github_token_reaches_a_third_party_action() -> None:
    """A custom PAT was once handed to a third-party action on pull-request runs."""
    violations: list[str] = []
    for path in workflow_files():
        for job_id, job in jobs_of(path).items():
            for step in job.get("steps") or []:
                action = step.get("uses", "")
                if not action or action.startswith("./"):
                    continue
                if action.split("/", 1)[0] in TRUSTED_ACTION_OWNERS:
                    continue
                for name in SECRET_REFERENCE_PATTERN.findall(yaml.safe_dump(step.get("with") or {})):
                    if name not in ALLOWED_SECRET_NAMES:
                        violations.append(f"{path.name}:{job_id} -> {action} gets secrets.{name}")

    assert not violations, "secrets passed to third-party actions:\n  " + "\n  ".join(violations)
