"""
Writing an update plan into pnpm-workspace.yaml: the ranges of `catalog:` dependencies and the
overrides pnpm reads from there.

The file is the user's, so it is edited through ruamel's round-trip loader, which keeps comments
and quoting. Text in, text out: no I/O.
"""

from __future__ import annotations

import copy
import io
from collections.abc import Mapping, MutableMapping
from typing import TYPE_CHECKING, Any

from ruamel.yaml import YAML, YAMLError
from ruamel.yaml.comments import CommentedMap

from ossiq.adapters.package_managers.npm.constants import DEP_SECTIONS
from ossiq.adapters.package_managers.npm.writer import final_spec, write_transitive_overrides
from ossiq.adapters.package_managers.pnpm.constants import CATALOG_PROTOCOL, DEFAULT_CATALOG
from ossiq.adapters.package_managers.pnpm.overrides import parse_pnpm_override_rules
from ossiq.domain.exceptions import PackageManagerExecutionError

if TYPE_CHECKING:
    from ossiq.service.update import UpdatePlan


def round_trip_yaml() -> YAML:
    """Return a loader/dumper that writes back what it read, in the layout pnpm itself writes."""
    yaml = YAML()
    yaml.preserve_quotes = True
    # shortcut: sequences are re-indented to pnpm's own `  - item` layout, so a file that indents
    # them differently shows that diff; upgrade by detecting the file's indentation on load.
    yaml.indent(mapping=2, sequence=4, offset=2)
    # Never re-wrap a long line the user wrote.
    yaml.width = 4096
    return yaml


def load_workspace(text: str | None) -> CommentedMap:
    """Parse pnpm-workspace.yaml for editing.

    Args:
        text: The file's text; None or blank for a project that has none.

    Returns:
        The top-level mapping, empty when there is no file or it holds only comments.
        shortcut: a comments-only file loses its comments when something is written into it.

    Raises:
        PackageManagerExecutionError: The text is not YAML, or its top level is not a mapping.
    """
    if text is None or not text.strip():
        return CommentedMap()
    try:
        document = round_trip_yaml().load(text)
    except YAMLError as exc:
        raise PackageManagerExecutionError(f"pnpm-workspace.yaml is not valid YAML: {exc}") from exc
    if document is None:
        return CommentedMap()
    if not isinstance(document, CommentedMap):
        raise PackageManagerExecutionError("pnpm-workspace.yaml must hold a mapping at its top level")
    return document


def dump_workspace(workspace: CommentedMap) -> str:
    """Render a mapping from load_workspace back to text."""
    out = io.StringIO()
    round_trip_yaml().dump(workspace, out)
    return out.getvalue()


def append_entry(mapping: CommentedMap, key: str, value: object) -> None:
    """Add *key* after the last entry of *mapping*, leaving the blank line or comments that follow it behind it.

    ruamel keeps whatever sits between a mapping's last entry and the next block (a blank line, the
    next block's heading comment) on that last entry, so a plain assignment lands the new key after
    them, in front of a heading that is not its own.
    """
    last = next(reversed(mapping), None)
    mapping[key] = value
    slots = mapping.ca.items.get(last) if last is not None else None
    if not slots or slots[2] is None:
        return
    token = slots[2]
    # The comment's first line ends the last entry's own line: an inline comment, or nothing.
    inline, _, trailing = token.value.partition("\n")
    if not trailing:
        return
    moved = copy.copy(token)
    moved.value = f"\n{trailing}"
    mapping.ca.items[key] = [None, None, moved, None]
    if inline:
        kept = copy.copy(token)
        kept.value = f"{inline}\n"
        slots[2] = kept
    else:
        slots[2] = None


def sync_mapping(target: CommentedMap, desired: Mapping[str, Any]) -> None:
    """Make *target* hold exactly *desired*, touching only the entries that differ.

    New entries are added before stale ones are removed, so the text after a removed last entry
    moves to the one that follows it instead of vanishing with it.
    """
    for key, value in desired.items():
        if key not in target:
            append_entry(target, key, value)
        elif target[key] != value:
            target[key] = value
    for key in [key for key in target if key not in desired]:
        del target[key]


def find_catalog(workspace: CommentedMap, name: str) -> MutableMapping[str, Any]:
    """Return the catalog called *name*; the default one lives under `catalog` or `catalogs.default`."""
    if name == DEFAULT_CATALOG and isinstance(workspace.get("catalog"), dict):
        return workspace["catalog"]
    catalogs = workspace.get("catalogs")
    found = catalogs.get(name) if isinstance(catalogs, dict) else None
    return found if isinstance(found, dict) else {}


def write_catalog_specs(pkg: dict[str, Any], workspace: CommentedMap, plan: UpdatePlan) -> None:
    """Write the final range of each updated `catalog:` dependency into its catalog entry.

    A catalog or entry the workspace does not have is skipped: `pnpm install` names the missing
    entry itself, and the caller restores the project.

    Args:
        pkg: The decoded package.json, which says which dependencies use a catalog.
        workspace: The mapping from load_workspace, edited in place.
        plan: The plan whose direct entries are written.
    """
    direct_entries = {entry.identity: entry for entry in plan.direct_entries}
    for section in DEP_SECTIONS:
        for name, spec in pkg.get(section, {}).items():
            entry = direct_entries.get(name)
            if entry is None or not spec.startswith(CATALOG_PROTOCOL):
                continue
            catalog = find_catalog(workspace, spec.removeprefix(CATALOG_PROTOCOL) or DEFAULT_CATALOG)
            current = catalog.get(name)
            if isinstance(current, str):
                # type(current) keeps a quoted value quoted.
                catalog[name] = type(current)(final_spec(current, entry, plan.pin_all))


def write_workspace_overrides(pkg: dict[str, Any], workspace: CommentedMap, plan: UpdatePlan) -> None:
    """Persist transitive recommendations as overrides in the workspace file.

    The ownership record stays in package.json (`ossiq:metadata`), so the rules about which
    overrides OSS IQ may rewrite are npm's, unchanged; see write_transitive_overrides.

    Args:
        pkg: The decoded package.json, which holds the ownership record; edited in place.
        workspace: The mapping from load_workspace; its `overrides` is edited in place.
        plan: The plan whose transitive entries are written.

    Raises:
        PackageManagerExecutionError: `overrides` exists but is not a mapping.
    """
    existing = workspace.get("overrides")
    if existing is not None and not isinstance(existing, dict):
        raise PackageManagerExecutionError("`overrides` in pnpm-workspace.yaml is not a mapping")

    # The shared writer works on plain dicts; the result is synced back onto the YAML below.
    holder = {"overrides": dict(existing or {}), "ossiq:metadata": pkg.get("ossiq:metadata", {})}
    if not write_transitive_overrides(holder, plan, parse=parse_pnpm_override_rules):
        return

    pkg["ossiq:metadata"] = holder["ossiq:metadata"]
    if isinstance(existing, dict):
        sync_mapping(existing, holder["overrides"])
    elif "overrides" in workspace:
        workspace["overrides"] = CommentedMap(holder["overrides"])
    else:
        append_entry(workspace, "overrides", CommentedMap(holder["overrides"]))


def edit_workspace(text: str | None, pkg: dict[str, Any], plan: UpdatePlan) -> str | None:
    """Apply a plan's catalog and override changes to the text of pnpm-workspace.yaml.

    Args:
        text: The file's text as it was before OSS IQ touched it; None when there is no file.
        pkg: The decoded package.json; its ownership record is updated in place.
        plan: The plan to write.

    Returns:
        The new text, or None when the plan changes nothing there, so an untouched file is never
        rewritten and a missing one never created.

    Raises:
        PackageManagerExecutionError: The file cannot be edited (see load_workspace).
    """
    workspace, pristine = load_workspace(text), load_workspace(text)
    write_catalog_specs(pkg, workspace, plan)
    write_workspace_overrides(pkg, workspace, plan)
    return dump_workspace(workspace) if workspace != pristine else None
