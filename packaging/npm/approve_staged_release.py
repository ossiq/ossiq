#!/usr/bin/env python3
"""Verify and approve a staged npm release of the OSS IQ CLI.

`binaries.yml` stages six packages per release -- five platform packages plus the
`@ossiq/cli` launcher that pins them -- and npm keeps each one invisible until a
maintainer approves it with 2FA. The launcher has to go live *last*: npm silently skips
an optional dependency it cannot resolve, so a launcher approved first installs with no
binary at all.

This script proves that what npm holds staged is what CI built and attested, then prints
the approvals in dependency order. It approves nothing unless `--approve` is passed.

Usage:
    python packaging/npm/approve_staged_release.py --run-id <binaries.yml run id>
    python packaging/npm/approve_staged_release.py --run-id <id> --approve

`npm stage list --json` has no documented schema, so `--stage-list-json` accepts a saved
payload: if npm's shape is not understood, save it, finish by hand, and feed it back in.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

DEFAULT_REPO = "ossiq/ossiq"
TARBALL_ARTIFACT = "npm-tarballs"
SIGNER_WORKFLOW = "ossiq/ossiq/.github/workflows/reusable-build-npm.yml"

# `npm stage list --json` is undocumented and has never been observed in this project, so
# every field is resolved through a list of plausible names. Adding the name npm turns out
# to use is a one-line change; a row matching none of them is reported, never dropped.
STAGE_LIST_KEYS = ("stages", "staged", "packages", "results", "versions", "data")
PACKAGE_KEYS = ("name", "package", "packageName", "package_name")
VERSION_KEYS = ("version", "packageVersion", "package_version")
STAGE_ID_KEYS = ("id", "stageId", "stage_id", "stagingId", "stage")
SPEC_KEYS = ("spec", "packageSpec", "package_spec")


class DiagnosticKind(StrEnum):
    """What a finding is about, so output can be grouped and gated consistently."""

    MISSING_STAGED_ENTRY = "not staged"
    ALREADY_PUBLISHED = "already live"
    LAUNCHER_AHEAD_OF_PLATFORMS = "launcher ahead of its platforms"
    VERSION_MISMATCH = "version mismatch"
    DUPLICATE_STAGED_ENTRY = "staged twice"
    UNEXPECTED_STAGED_ENTRY = "not part of this release"
    UNREADABLE_STAGED_ENTRY = "unreadable staged entry"
    UNREADABLE_STAGE_LIST = "unreadable stage list"
    ATTESTATION_FAILED = "attestation failed"
    STAGED_BYTES_DIFFER = "staged bytes differ from CI's"
    STAGED_BYTES_UNVERIFIED = "staged bytes not compared"


@dataclass(frozen=True)
class ExpectedPackage:
    """One row of the release manifest: a package CI staged, and the tarball it staged."""

    package: str
    tarball: str
    is_launcher: bool


@dataclass(frozen=True)
class StagedEntry:
    """One row of `npm stage list`, normalised out of an undocumented payload shape."""

    package: str
    version: str
    stage_id: str


@dataclass(frozen=True)
class Diagnostic:
    """A finding. `blocking` is what stops `--approve` from touching the registry."""

    kind: DiagnosticKind
    detail: str
    blocking: bool


@dataclass(frozen=True)
class ApprovalStep:
    """One approval to perform, in the order it must happen."""

    package: str
    version: str
    stage_id: str
    tarball: str
    is_launcher: bool

    @property
    def command(self) -> tuple[str, ...]:
        """The command that makes this staged version live.

        Returns:
            Argument vector for `npm stage approve`.
        """
        return ("npm", "stage", "approve", self.stage_id)


@dataclass(frozen=True)
class ApprovalPlan:
    """The ordered approvals plus everything found while checking them."""

    version: str
    steps: tuple[ApprovalStep, ...]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def blocked(self) -> bool:
        """Whether anything found makes it unsafe to approve.

        Returns:
            True if at least one diagnostic is blocking.
        """
        return any(diagnostic.blocking for diagnostic in self.diagnostics)

    def with_diagnostics(self, more: Sequence[Diagnostic]) -> ApprovalPlan:
        """Return a copy carrying additional findings.

        Args:
            more: Diagnostics to append.

        Returns:
            A new plan with the diagnostics added.
        """
        return dataclasses.replace(self, diagnostics=self.diagnostics + tuple(more))


@dataclass(frozen=True)
class CommandResult:
    """A finished subprocess, captured."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def string_keyed(value: object) -> dict[str, object]:
    """Re-key an arbitrary parsed-JSON value by string.

    Every mapping here comes from JSON that no schema governs, so narrowing with
    `isinstance` alone leaves the key type unknown. Re-keying gives the readers below a
    concrete mapping and costs nothing at this size.

    Args:
        value: Any parsed value; anything that is not a mapping yields an empty dict.

    Returns:
        The mapping, keyed by string.
    """
    if not isinstance(value, Mapping):
        return {}
    return {str(key): item for key, item in value.items()}


def manifest_row(entry: object, source: str) -> tuple[str, str]:
    """Pull `(package, tarball)` out of one manifest row.

    Args:
        entry: The row, as parsed from manifest.json.
        source: Where it came from, for the error message.

    Returns:
        The package name and the tarball filename.

    Raises:
        SystemExit: If the row is not an object or lacks either key.
    """
    if not isinstance(entry, Mapping):
        raise SystemExit(f"manifest.json: {source} is not an object")
    fields = string_keyed(entry)
    try:
        return str(fields["package"]), str(fields["tarball"])
    except KeyError as error:
        raise SystemExit(f"manifest.json: {source} has no {error.args[0]!r}") from error


def expected_packages(manifest: Mapping[str, object]) -> tuple[ExpectedPackage, ...]:
    """Read the manifest into approval order: platform packages first, launcher last.

    Args:
        manifest: The parsed manifest.json that build_npm_packages.py wrote.

    Returns:
        The expected packages, in the order they must be approved.

    Raises:
        SystemExit: If the manifest lacks platform packages or a launcher.
    """
    platform = manifest.get("platform_packages")
    launcher = manifest.get("launcher")
    if not isinstance(platform, list) or not platform:
        raise SystemExit("manifest.json: no 'platform_packages' list")
    if launcher is None:
        raise SystemExit("manifest.json: no 'launcher' entry")

    expected = []
    for index, entry in enumerate(platform):
        package, tarball = manifest_row(entry, f"platform_packages[{index}]")
        expected.append(ExpectedPackage(package=package, tarball=tarball, is_launcher=False))

    package, tarball = manifest_row(launcher, "launcher")
    expected.append(ExpectedPackage(package=package, tarball=tarball, is_launcher=True))
    return tuple(expected)


def candidate_rows(payload: object) -> list[object] | None:
    """Find the list of staged rows inside an undocumented payload.

    Handles a bare list, an object holding the list under a plausible key, and an object
    keyed by stage id.

    Args:
        payload: Whatever `npm stage list --json` produced.

    Returns:
        The rows, or None if the shape is unrecognised.
    """
    if isinstance(payload, list):
        return list(payload)
    if not isinstance(payload, Mapping):
        return None

    fields = string_keyed(payload)
    for key in STAGE_LIST_KEYS:
        value = fields.get(key)
        if isinstance(value, list):
            return list(value)

    if fields and all(isinstance(value, Mapping) for value in fields.values()):
        # A mapping of stage id -> row; fold the key in so the id is not lost.
        return [{"id": key, **string_keyed(value)} for key, value in fields.items()]
    return None


def first_string(row: Mapping[str, object], keys: Sequence[str]) -> str | None:
    """Return the first non-empty string among `keys`.

    Args:
        row: One staged entry.
        keys: Field names to try, in order of preference.

    Returns:
        The value found, or None.
    """
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def split_spec(spec: str) -> tuple[str, str] | None:
    """Split `@scope/name@version` into its package and version.

    Args:
        spec: A package spec.

    Returns:
        The package and version, or None if there is no version to split off.
    """
    index = spec.rfind("@")
    if index <= 0:
        return None
    return spec[:index], spec[index + 1 :]


def parse_stage_list(payload: object) -> tuple[tuple[StagedEntry, ...], tuple[Diagnostic, ...]]:
    """Normalise `npm stage list --json` output, reporting whatever cannot be read.

    Never raises: an unusable payload has to produce an explanation the maintainer can act
    on, not a traceback, because the fallback is to approve by hand.

    Args:
        payload: The parsed JSON payload.

    Returns:
        The entries understood, and diagnostics for everything else.
    """
    rows = candidate_rows(payload)
    if rows is None:
        detail = f"npm stage list returned a {type(payload).__name__} this script cannot read"
        return (), (Diagnostic(DiagnosticKind.UNREADABLE_STAGE_LIST, detail, True),)

    entries: list[StagedEntry] = []
    diagnostics: list[Diagnostic] = []
    for row in rows:
        if not isinstance(row, Mapping):
            diagnostics.append(
                Diagnostic(DiagnosticKind.UNREADABLE_STAGED_ENTRY, f"a {type(row).__name__}, not an object", True)
            )
            continue

        fields = string_keyed(row)
        package = first_string(fields, PACKAGE_KEYS)
        version = first_string(fields, VERSION_KEYS)
        stage_id = first_string(fields, STAGE_ID_KEYS)

        spec = first_string(fields, SPEC_KEYS)
        if spec and not (package and version):
            split = split_spec(spec)
            if split:
                package = package or split[0]
                version = version or split[1]

        if package and version and stage_id:
            entries.append(StagedEntry(package=package, version=version, stage_id=stage_id))
        else:
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.UNREADABLE_STAGED_ENTRY,
                    f"no package/version/stage id among keys {sorted(fields)}",
                    True,
                )
            )
    return tuple(entries), tuple(diagnostics)


def build_plan(
    expected: Sequence[ExpectedPackage],
    staged: Sequence[StagedEntry],
    *,
    version: str,
    published: frozenset[str] = frozenset(),
) -> ApprovalPlan:
    """Match staged entries to the manifest and order the approvals.

    Args:
        expected: The manifest's packages, in approval order.
        staged: Entries npm reports as staged.
        version: The version this release is supposed to be.
        published: `package@version` specs already live, which turn a missing staged entry
            into a note instead of a failure -- the resume path after a partial approval.

    Returns:
        The ordered plan and its diagnostics.
    """
    by_package: dict[str, list[StagedEntry]] = {}
    for entry in staged:
        by_package.setdefault(entry.package, []).append(entry)

    steps: list[ApprovalStep] = []
    diagnostics: list[Diagnostic] = []

    for item in expected:
        spec = f"{item.package}@{version}"
        matches = by_package.get(item.package, [])

        if not matches:
            if spec in published:
                diagnostics.append(
                    Diagnostic(DiagnosticKind.ALREADY_PUBLISHED, f"{spec} is live; nothing to approve", False)
                )
            else:
                diagnostics.append(
                    Diagnostic(
                        DiagnosticKind.MISSING_STAGED_ENTRY,
                        f"{spec} is neither staged nor published; re-stage it or publish it by hand",
                        True,
                    )
                )
            continue

        if len(matches) > 1:
            found = ", ".join(sorted(entry.stage_id for entry in matches))
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.DUPLICATE_STAGED_ENTRY,
                    f"{item.package} has {len(matches)} staged entries ({found}); pick one by hand",
                    True,
                )
            )
            continue

        entry = matches[0]
        if entry.version != version:
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.VERSION_MISMATCH,
                    f"{item.package} is staged at {entry.version}, but this release is {version}",
                    True,
                )
            )
            continue

        steps.append(
            ApprovalStep(
                package=item.package,
                version=version,
                stage_id=entry.stage_id,
                tarball=item.tarball,
                is_launcher=item.is_launcher,
            )
        )

    expected_names = {item.package for item in expected}
    for entry in staged:
        if entry.package not in expected_names:
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.UNEXPECTED_STAGED_ENTRY,
                    f"{entry.package}@{entry.version} is staged but not part of this release; left alone",
                    False,
                )
            )

    # A launcher that went live before its platform packages is the breakage this whole
    # script exists to prevent. It is urgent but not blocking: the remedy is to approve the
    # packages still pending, which blocking would prevent.
    launcher_live = any(item.is_launcher and f"{item.package}@{version}" in published for item in expected)
    if launcher_live and any(not step.is_launcher for step in steps):
        diagnostics.append(
            Diagnostic(
                DiagnosticKind.LAUNCHER_AHEAD_OF_PLATFORMS,
                "the launcher is already live while platform packages are not: installs on those "
                "platforms resolve no binary. Approve the rest now.",
                False,
            )
        )

    return ApprovalPlan(version=version, steps=tuple(steps), diagnostics=tuple(diagnostics))


def launcher_is_last(plan: ApprovalPlan) -> bool:
    """Whether the launcher is approved after every platform package.

    Checked again immediately before approving, so a later refactor that reorders the
    steps cannot quietly ship the breakage this tool guards against.

    Args:
        plan: The plan to check.

    Returns:
        True if no step before the last one is the launcher.
    """
    return all(not step.is_launcher for step in plan.steps[:-1])


def render_plan(plan: ApprovalPlan, *, approve: bool) -> tuple[str, ...]:
    """Lay the plan out for a terminal.

    Args:
        plan: The plan to render.
        approve: Whether the caller is about to approve rather than just look.

    Returns:
        The lines to print.
    """
    lines = [f"Staged npm release {plan.version}"]

    blocking = [item for item in plan.diagnostics if item.blocking]
    notes = [item for item in plan.diagnostics if not item.blocking]
    for diagnostic in (*blocking, *notes):
        marker = "BLOCKED" if diagnostic.blocking else "note"
        lines.append(f"  {marker}: {diagnostic.kind}: {diagnostic.detail}")

    if not plan.steps:
        lines.append("  nothing left to approve")
    else:
        lines.append("")
        lines.append(f"{len(plan.steps)} to approve, in this order (the launcher pins the rest, so it is last):")
        for position, step in enumerate(plan.steps, start=1):
            suffix = "  <- launcher, last" if step.is_launcher else ""
            lines.append(f"  {position}. {step.package}@{step.version}{suffix}")
            lines.append(f"     {' '.join(step.command)}")

    lines.append("")
    if plan.blocked:
        lines.append("Refusing to approve: resolve the BLOCKED findings above first.")
    elif plan.steps and not approve:
        lines.append("Nothing has been approved. Re-run with --approve to make these live.")
    return tuple(lines)


def run_command(args: Sequence[str], *, cwd: Path | None = None, timeout: int = 600) -> CommandResult:
    """Run a command and capture it.

    Args:
        args: The argument vector.
        cwd: Directory to run in.
        timeout: Seconds before giving up.

    Returns:
        The captured result; a timeout becomes returncode 124.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argument vectors, never a shell
            list(args),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(args), 124, "", f"timed out after {timeout}s")
    except FileNotFoundError as error:
        return CommandResult(tuple(args), 127, "", str(error))
    return CommandResult(tuple(args), completed.returncode, completed.stdout, completed.stderr)


def run_interactive(args: Sequence[str]) -> int:
    """Run a command with the terminal attached, so npm can prompt for the OTP.

    Args:
        args: The argument vector.

    Returns:
        The exit status.
    """
    return subprocess.run(list(args), check=False).returncode  # noqa: S603 - fixed argument vector


def download_artifact(run_id: str, repo: str, destination: Path) -> Path:
    """Fetch the npm tarballs CI packed and attested for a run.

    Args:
        run_id: The binaries.yml run.
        repo: `owner/name` to download from.
        destination: Directory to extract into.

    Returns:
        The directory holding `npm/` and `build/npm/manifest.json`.

    Raises:
        SystemExit: If the download fails.
    """
    destination.mkdir(parents=True, exist_ok=True)
    result = run_command(
        ("gh", "run", "download", run_id, "--repo", repo, "-n", TARBALL_ARTIFACT, "--dir", str(destination))
    )
    if result.returncode != 0:
        raise SystemExit(f"could not download the {TARBALL_ARTIFACT} artifact of run {run_id}:\n{result.stderr}")
    return destination


def load_manifest(path: Path) -> dict[str, object]:
    """Read manifest.json.

    Args:
        path: Path to the manifest.

    Returns:
        The parsed manifest.

    Raises:
        SystemExit: If it is missing or not an object.
    """
    if not path.is_file():
        raise SystemExit(f"no manifest at {path}; is this a {TARBALL_ARTIFACT} artifact?")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"{path} is not valid JSON: {error}") from error
    if not isinstance(manifest, dict):
        raise SystemExit(f"{path} does not hold an object")
    return manifest


def stage_list_payload(path: Path | None) -> tuple[object | None, str]:
    """Get the staged-package list, from a file or from npm.

    Args:
        path: A saved payload to read instead of calling npm.

    Returns:
        The parsed payload (None if it could not be parsed) and the raw text, so an
        unreadable payload can be shown to the maintainer verbatim.
    """
    if path is not None:
        raw = path.read_text(encoding="utf-8")
    else:
        result = run_command(("npm", "stage", "list", "--json"))
        raw = result.stdout or result.stderr
        if result.returncode != 0:
            return None, raw
    try:
        return json.loads(raw), raw
    except json.JSONDecodeError:
        return None, raw


def verify_attestation(tarball: Path, repo: str) -> CommandResult:
    """Check a tarball against the provenance `reusable-build-npm.yml` signed.

    Args:
        tarball: The .tgz to verify.
        repo: `owner/name` the attestation belongs to.

    Returns:
        The captured result.
    """
    return run_command(
        (
            "gh",
            "attestation",
            "verify",
            str(tarball),
            "--repo",
            repo,
            "--signer-workflow",
            SIGNER_WORKFLOW,
        )
    )


def published_specs(packages: Sequence[str], version: str) -> frozenset[str]:
    """Ask npm which of these `package@version` specs are already live.

    Args:
        packages: Package names to check.
        version: The version of interest.

    Returns:
        The specs npm serves.
    """
    live = set()
    for package in packages:
        spec = f"{package}@{version}"
        result = run_command(("npm", "view", spec, "version"))
        if result.returncode == 0 and version in result.stdout:
            live.add(spec)
    return frozenset(live)


def digest_of(path: Path) -> str:
    """Return a file's SHA-256.

    Args:
        path: The file to hash.

    Returns:
        Hex digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def staged_tarball(stage_id: str, destination: Path) -> Path | None:
    """Download a staged tarball, if npm's CLI allows it.

    Best effort on purpose: `npm stage download`'s output location is undocumented, so
    anything unexpected returns None and the caller reports the comparison as not done
    rather than failing a release over it.

    Args:
        stage_id: The staged version to fetch.
        destination: An empty directory to download into.

    Returns:
        The downloaded tarball, or None.
    """
    destination.mkdir(parents=True, exist_ok=True)
    result = run_command(("npm", "stage", "download", stage_id), cwd=destination)
    if result.returncode != 0:
        return None
    tarballs = sorted(destination.glob("*.tgz"))
    return tarballs[0] if len(tarballs) == 1 else None


def check_attestations(plan: ApprovalPlan, tarball_dir: Path, repo: str) -> tuple[Diagnostic, ...]:
    """Verify CI's provenance over every tarball about to be approved.

    Args:
        plan: The plan whose steps name the tarballs.
        tarball_dir: Directory holding the .tgz files.
        repo: `owner/name` for the attestation lookup.

    Returns:
        One diagnostic per tarball that fails.
    """
    diagnostics = []
    for step in plan.steps:
        tarball = tarball_dir / step.tarball
        if not tarball.is_file():
            diagnostics.append(
                Diagnostic(DiagnosticKind.ATTESTATION_FAILED, f"{step.tarball} is not in the artifact", True)
            )
            continue
        result = verify_attestation(tarball, repo)
        if result.returncode != 0:
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.ATTESTATION_FAILED,
                    f"{step.tarball} is not the artifact {SIGNER_WORKFLOW} signed:\n      {result.stderr.strip()}",
                    True,
                )
            )
    return tuple(diagnostics)


def compare_staged_bytes(plan: ApprovalPlan, tarball_dir: Path, work_dir: Path) -> tuple[Diagnostic, ...]:
    """Compare what npm holds staged against the tarball CI attested.

    Args:
        plan: The plan whose steps name the staged versions.
        tarball_dir: Directory holding CI's .tgz files.
        work_dir: Scratch space for downloads.

    Returns:
        A diagnostic per package: a mismatch is blocking, an impossible comparison is not.
    """
    diagnostics = []
    for step in plan.steps:
        artifact = tarball_dir / step.tarball
        if not artifact.is_file():
            continue
        downloaded = staged_tarball(step.stage_id, work_dir / step.stage_id)
        if downloaded is None:
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.STAGED_BYTES_UNVERIFIED,
                    f"{step.package}: could not download the staged tarball, so only CI's copy was verified",
                    False,
                )
            )
            continue
        if digest_of(downloaded) != digest_of(artifact):
            diagnostics.append(
                Diagnostic(
                    DiagnosticKind.STAGED_BYTES_DIFFER,
                    f"{step.package}: what npm holds staged is not the tarball CI attested",
                    True,
                )
            )
    return tuple(diagnostics)


def manual_fallback(expected: Sequence[ExpectedPackage], version: str, raw: str) -> tuple[str, ...]:
    """Explain how to finish by hand when npm's stage list cannot be read.

    Args:
        expected: The manifest's packages, in approval order.
        version: The release version.
        raw: What npm actually printed.

    Returns:
        The lines to print.
    """
    lines = [
        "Could not read `npm stage list --json`. Its schema is undocumented, so this may",
        "simply be a shape this script has not seen. npm printed:",
        "",
        *(f"  {line}" for line in raw.splitlines()[:40] or ["(nothing)"]),
        "",
        "Approve by hand instead, in this order (npmjs.com -> Staged Packages works too):",
        "",
        "  npm stage list",
    ]
    lines.extend(f"  npm stage approve <stage-id for {item.package}@{version}>" for item in expected)
    lines.extend(
        (
            "",
            "The launcher is last on purpose. Then save the payload and pass it back with",
            "--stage-list-json so the checks can run, and add the field names to this script.",
        )
    )
    return tuple(lines)


def resolve_artifact_dir(args: argparse.Namespace, work_dir: Path) -> Path:
    """Get the directory holding CI's tarballs, downloading it if needed.

    Args:
        args: Parsed arguments.
        work_dir: Scratch space for a download.

    Returns:
        The artifact directory.
    """
    if args.artifact_dir is not None:
        return args.artifact_dir
    return download_artifact(args.run_id, args.repo, work_dir / "artifact")


def build_parser() -> argparse.ArgumentParser:
    """Define the command line.

    Returns:
        The parser.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--run-id", help="binaries.yml run whose npm-tarballs artifact to check")
    source.add_argument(
        "--artifact-dir",
        type=Path,
        help="an already-downloaded artifact (expects npm/ and build/npm/manifest.json inside)",
    )
    parser.add_argument("--repo", default=DEFAULT_REPO, help=f"repository to verify against (default: {DEFAULT_REPO})")
    parser.add_argument(
        "--stage-list-json",
        type=Path,
        help="read a saved `npm stage list --json` payload instead of calling npm",
    )
    parser.add_argument("--version", help="expected version; cross-checked against the manifest")
    parser.add_argument(
        "--approve",
        action="store_true",
        help="actually approve, in order (npm prompts for your OTP once per package)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Verify a staged release and, with --approve, make it live.

    Args:
        argv: Command-line arguments.

    Returns:
        0 if verified, 1 if blocked or an approval failed.
    """
    args = build_parser().parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="ossiq-approve-") as scratch:
        work_dir = Path(scratch)
        artifact_dir = resolve_artifact_dir(args, work_dir)
        manifest = load_manifest(artifact_dir / "build" / "npm" / "manifest.json")

        version = str(manifest.get("version", ""))
        if not version:
            raise SystemExit("manifest.json has no 'version'")
        if args.version and args.version != version:
            raise SystemExit(f"this artifact is {version}, but --version says {args.version}; wrong run?")

        expected = expected_packages(manifest)
        payload, raw = stage_list_payload(args.stage_list_json)
        if payload is None:
            print("\n".join(manual_fallback(expected, version, raw)))
            return 1

        staged, parse_diagnostics = parse_stage_list(payload)
        if any(item.kind is DiagnosticKind.UNREADABLE_STAGE_LIST for item in parse_diagnostics):
            # Valid JSON in a shape this script does not know. Same remedy as unparseable
            # output: show what npm said and how to finish by hand.
            print("\n".join(manual_fallback(expected, version, raw)))
            return 1

        plan = build_plan(expected, staged, version=version)

        # Only worth six `npm view` calls when something is missing, which is the partial
        # approval case; a complete stage list needs no registry lookup at all.
        if any(item.kind is DiagnosticKind.MISSING_STAGED_ENTRY for item in plan.diagnostics):
            live = published_specs([item.package for item in expected], version)
            plan = build_plan(expected, staged, version=version, published=live)

        plan = plan.with_diagnostics(parse_diagnostics)
        plan = plan.with_diagnostics(check_attestations(plan, artifact_dir / "npm", args.repo))
        plan = plan.with_diagnostics(compare_staged_bytes(plan, artifact_dir / "npm", work_dir / "staged"))

        print("\n".join(render_plan(plan, approve=args.approve)))

        if not args.approve:
            return 1 if plan.blocked else 0
        if plan.blocked:
            return 1
        if not launcher_is_last(plan):
            raise SystemExit("refusing to approve: the launcher is not last in the plan")

        for position, step in enumerate(plan.steps, start=1):
            print(f"\n[{position}/{len(plan.steps)}] approving {step.package}@{step.version}")
            status = run_interactive(step.command)
            if status != 0:
                remaining = plan.steps[position:]
                print(f"\n`{' '.join(step.command)}` failed. {len(remaining)} left; finish in this order:")
                for step_left in remaining:
                    print(f"  {' '.join(step_left.command)}   # {step_left.package}")
                return 1

        print(f"\nApproved {len(plan.steps)}. Verify with: npx --yes @ossiq/cli@{version} --version")
        return 0


if __name__ == "__main__":
    sys.exit(main())
