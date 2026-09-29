"""Tests for packaging/npm/approve_staged_release.py.

The script is loaded by path: `packaging/` is not an importable package, and the name would
collide with the `packaging` distribution anyway.

Only the pure core is covered. The I/O layer shells out to `gh` and `npm`, and the shape of
`npm stage list --json` is undocumented -- which is exactly why `parse_stage_list` has to
survive payloads nobody has seen, and why that is where the tests concentrate.
"""

import importlib.util
import itertools
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "packaging" / "npm" / "approve_staged_release.py"

PLATFORMS = ("darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-x64")
VERSION = "0.1.14"
LAUNCHER = "@ossiq/cli"


def load_script() -> ModuleType:
    """Import approve_staged_release.py from its file path.

    Returns:
        The loaded module.
    """
    spec = importlib.util.spec_from_file_location("approve_staged_release", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves its module through sys.modules, so registering it is not optional.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


approve = load_script()


def manifest(version: str = VERSION) -> dict[str, object]:
    """Build a manifest shaped like the one build_npm_packages.py writes.

    Args:
        version: The version to stamp.

    Returns:
        The manifest mapping.
    """
    return {
        "version": version,
        "platform_packages": [
            {
                "directory": f"cli-{target}",
                "package": f"@ossiq/cli-{target}",
                "tarball": f"ossiq-cli-{target}-{version}.tgz",
            }
            for target in PLATFORMS
        ],
        "launcher": {"directory": "cli", "package": LAUNCHER, "tarball": f"ossiq-cli-{version}.tgz"},
    }


def release_packages() -> list[str]:
    """The six package names, platform packages first.

    Returns:
        Package names in approval order.
    """
    return [f"@ossiq/cli-{target}" for target in PLATFORMS] + [LAUNCHER]


def staged(packages: Sequence[str] | None = None, version: str = VERSION) -> list:
    """Build StagedEntry objects with distinct stage ids.

    Args:
        packages: Package names to stage; defaults to the whole release.
        version: The version each is staged at.

    Returns:
        A list of StagedEntry.
    """
    names = list(packages) if packages is not None else release_packages()
    return [
        approve.StagedEntry(package=name, version=version, stage_id=f"stage-{index}")
        for index, name in enumerate(names)
    ]


def kinds(plan) -> list:
    """The diagnostic kinds a plan carries.

    Args:
        plan: The plan to inspect.

    Returns:
        Kinds in the order reported.
    """
    return [diagnostic.kind for diagnostic in plan.diagnostics]


def test_expected_packages_puts_the_launcher_last() -> None:
    """The launcher pins the platform versions, so every consumer needs it ordered last."""
    expected = approve.expected_packages(manifest())

    assert [item.package for item in expected] == release_packages()
    assert expected[-1].is_launcher
    assert not any(item.is_launcher for item in expected[:-1])


def test_expected_packages_rejects_a_manifest_without_a_launcher() -> None:
    """A manifest with no launcher means a partial release; approving it would be wrong."""
    incomplete = manifest()
    del incomplete["launcher"]

    with pytest.raises(SystemExit, match="launcher"):
        approve.expected_packages(incomplete)


def test_expected_packages_rejects_a_manifest_without_platform_packages() -> None:
    """Same reasoning from the other side: the launcher alone installs no binary."""
    incomplete = manifest()
    incomplete["platform_packages"] = []

    with pytest.raises(SystemExit, match="platform_packages"):
        approve.expected_packages(incomplete)


def test_expected_packages_names_the_missing_key_of_a_bad_row() -> None:
    """The manifest schema is an untested contract with three YAML consumers."""
    broken = manifest()
    broken["platform_packages"] = [{"directory": "cli-darwin-arm64", "package": "@ossiq/cli-darwin-arm64"}]

    with pytest.raises(SystemExit, match="tarball"):
        approve.expected_packages(broken)


def test_plan_orders_platform_packages_before_the_launcher() -> None:
    """npm's listing order is arbitrary; the manifest decides the approval order."""
    shuffled = list(reversed(staged()))

    plan = approve.build_plan(approve.expected_packages(manifest()), shuffled, version=VERSION)

    assert [step.package for step in plan.steps] == release_packages()
    assert not plan.blocked
    assert plan.diagnostics == ()


def test_launcher_is_last_whatever_order_npm_lists() -> None:
    """The invariant the tool exists for, over every ordering npm could hand back."""
    expected = approve.expected_packages(manifest())

    for ordering in itertools.permutations(staged()):
        plan = approve.build_plan(expected, list(ordering), version=VERSION)

        assert approve.launcher_is_last(plan)
        assert plan.steps[-1].package == LAUNCHER


def test_plan_blocks_on_a_missing_staged_entry() -> None:
    """A launcher approved without all five platform packages breaks those platforms."""
    partial = staged([name for name in release_packages() if not name.endswith("win32-x64")])

    plan = approve.build_plan(approve.expected_packages(manifest()), partial, version=VERSION)

    assert approve.DiagnosticKind.MISSING_STAGED_ENTRY in kinds(plan)
    assert plan.blocked
    assert "@ossiq/cli-win32-x64" not in [step.package for step in plan.steps]


def test_plan_notes_a_missing_entry_that_is_already_live() -> None:
    """Re-running after a partial approval must not be blocked by its own progress.

    An approved package leaves the stage list, so "missing" and "already live" look the
    same until the registry is asked.
    """
    remaining = staged([name for name in release_packages() if name != "@ossiq/cli-darwin-arm64"])

    plan = approve.build_plan(
        approve.expected_packages(manifest()),
        remaining,
        version=VERSION,
        published=frozenset({f"@ossiq/cli-darwin-arm64@{VERSION}"}),
    )

    assert approve.DiagnosticKind.ALREADY_PUBLISHED in kinds(plan)
    assert not plan.blocked


def test_plan_warns_when_the_launcher_went_live_before_its_platforms() -> None:
    """The exact breakage this ordering exists to prevent, caught after the fact.

    Not blocking: the remedy is to approve the packages still pending, which blocking
    would prevent.
    """
    plan = approve.build_plan(
        approve.expected_packages(manifest()),
        staged([name for name in release_packages() if name != LAUNCHER]),
        version=VERSION,
        published=frozenset({f"{LAUNCHER}@{VERSION}"}),
    )

    assert approve.DiagnosticKind.LAUNCHER_AHEAD_OF_PLATFORMS in kinds(plan)
    assert not plan.blocked
    assert len(plan.steps) == len(PLATFORMS)


def test_plan_blocks_on_a_version_mismatch() -> None:
    """Approving a stale stage would put a different build behind this version string."""
    entries = staged()
    entries[0] = approve.StagedEntry(package=entries[0].package, version="0.1.13", stage_id="old")

    plan = approve.build_plan(approve.expected_packages(manifest()), entries, version=VERSION)

    assert approve.DiagnosticKind.VERSION_MISMATCH in kinds(plan)
    assert plan.blocked
    assert "old" not in [step.stage_id for step in plan.steps]


def test_plan_blocks_when_one_package_is_staged_twice() -> None:
    """Guessing which of two stage ids to approve is unrecoverable, so it stops."""
    entries = [*staged(), approve.StagedEntry(package=LAUNCHER, version=VERSION, stage_id="duplicate")]

    plan = approve.build_plan(approve.expected_packages(manifest()), entries, version=VERSION)

    assert approve.DiagnosticKind.DUPLICATE_STAGED_ENTRY in kinds(plan)
    assert plan.blocked


def test_plan_leaves_a_staged_package_outside_the_release_alone() -> None:
    """Another release staged in parallel is someone else's business, not a failure."""
    entries = [*staged(), approve.StagedEntry(package="@ossiq/unrelated", version="9.9.9", stage_id="other")]

    plan = approve.build_plan(approve.expected_packages(manifest()), entries, version=VERSION)

    assert approve.DiagnosticKind.UNEXPECTED_STAGED_ENTRY in kinds(plan)
    assert not plan.blocked
    assert "@ossiq/unrelated" not in [step.package for step in plan.steps]


def test_parse_stage_list_accepts_a_bare_list() -> None:
    """The simplest plausible shape."""
    entries, diagnostics = approve.parse_stage_list(
        [{"name": LAUNCHER, "version": VERSION, "id": "abc"}],
    )

    assert diagnostics == ()
    assert entries == (approve.StagedEntry(package=LAUNCHER, version=VERSION, stage_id="abc"),)


@pytest.mark.parametrize("container", approve.STAGE_LIST_KEYS)
def test_parse_stage_list_accepts_a_wrapped_list(container: str) -> None:
    """npm may wrap the rows under any of several plausible keys."""
    payload = {container: [{"name": LAUNCHER, "version": VERSION, "id": "abc"}]}

    entries, diagnostics = approve.parse_stage_list(payload)

    assert diagnostics == ()
    assert entries[0].stage_id == "abc"


def test_parse_stage_list_accepts_a_mapping_keyed_by_stage_id() -> None:
    """The other plausible shape, where the id is the key rather than a field."""
    entries, diagnostics = approve.parse_stage_list({"abc": {"name": LAUNCHER, "version": VERSION}})

    assert diagnostics == ()
    assert entries == (approve.StagedEntry(package=LAUNCHER, version=VERSION, stage_id="abc"),)


@pytest.mark.parametrize("package_key", approve.PACKAGE_KEYS)
@pytest.mark.parametrize("stage_id_key", approve.STAGE_ID_KEYS)
def test_parse_stage_list_accepts_alternate_field_names(package_key: str, stage_id_key: str) -> None:
    """Field names are guesses until a real staged release is observed."""
    entries, diagnostics = approve.parse_stage_list([{package_key: LAUNCHER, "version": VERSION, stage_id_key: "abc"}])

    assert diagnostics == ()
    assert entries == (approve.StagedEntry(package=LAUNCHER, version=VERSION, stage_id="abc"),)


def test_parse_stage_list_splits_a_spec_at_the_last_at_sign() -> None:
    """A scoped name contains an `@` of its own, so the split cannot be leftmost."""
    entries, diagnostics = approve.parse_stage_list([{"spec": f"{LAUNCHER}@{VERSION}", "id": "abc"}])

    assert diagnostics == ()
    assert entries == (approve.StagedEntry(package=LAUNCHER, version=VERSION, stage_id="abc"),)


def test_parse_stage_list_reports_a_row_it_cannot_read() -> None:
    """A dropped row would read as "not staged" and send someone re-staging for nothing."""
    entries, diagnostics = approve.parse_stage_list([{"surprising": "shape"}])

    assert entries == ()
    assert [item.kind for item in diagnostics] == [approve.DiagnosticKind.UNREADABLE_STAGED_ENTRY]
    assert diagnostics[0].blocking
    assert "surprising" in diagnostics[0].detail


@pytest.mark.parametrize("payload", [{"ok": True}, "text", 42, None, {}])
def test_parse_stage_list_reports_an_unrecognised_payload(payload: object) -> None:
    """It must explain itself rather than raise: the fallback is to approve by hand."""
    entries, diagnostics = approve.parse_stage_list(payload)

    assert entries == ()
    assert [item.kind for item in diagnostics] == [approve.DiagnosticKind.UNREADABLE_STAGE_LIST]
    assert diagnostics[0].blocking


def test_render_plan_names_every_package_with_the_launcher_last() -> None:
    """The printed order is what gets followed by hand, so it has to match the plan."""
    plan = approve.build_plan(approve.expected_packages(manifest()), staged(), version=VERSION)

    rendered = "\n".join(approve.render_plan(plan, approve=False))

    for package in release_packages():
        assert package in rendered
    assert rendered.index(LAUNCHER + "@") > rendered.index("@ossiq/cli-win32-x64@")
    assert "--approve" in rendered


def test_render_plan_refuses_instead_of_listing_when_blocked() -> None:
    """A blocked plan must not read like a to-do list someone can work through."""
    plan = approve.build_plan(approve.expected_packages(manifest()), staged()[:2], version=VERSION)

    rendered = "\n".join(approve.render_plan(plan, approve=False))

    assert "Refusing to approve" in rendered
    assert "BLOCKED" in rendered


def test_manual_fallback_lists_every_package_in_approval_order() -> None:
    """When the payload is unreadable this text is the only instruction there is."""
    expected = approve.expected_packages(manifest())

    lines = approve.manual_fallback(expected, VERSION, '{"unexpected": true}')

    rendered = "\n".join(lines)
    for package in release_packages():
        assert package in rendered
    assert rendered.index(f"{LAUNCHER}@{VERSION}") > rendered.index(f"@ossiq/cli-win32-x64@{VERSION}")
    assert "unexpected" in rendered
