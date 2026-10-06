"""
Writing an update plan back into a decoded package.json: relaxed direct specifiers, and transitive
recommendations persisted as overrides with a record of what OSS IQ wrote.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ossiq.adapters.package_managers.npm.constants import DEP_SECTIONS
from ossiq.adapters.package_managers.npm.overrides import (
    holds_recorded_value,
    parse_override_rules,
    rules_governing,
    superseded_override_keys,
    user_owns_override,
)

if TYPE_CHECKING:
    from ossiq.service.update import UpdatePlan


def relax_spec(original_spec: str, recommended: str, pin_all: bool) -> str:
    """Return the final specifier for an updated direct dep.

    --pin-all writes the exact recommended version. Otherwise the original operator is kept and
    its floor bumped to the recommended version; specs without a ^/~ operator pin to exact. npm
    aliases (npm:pkg@range) are left untouched — bumping the inner constraint is unsupported.
    """
    s = original_spec.strip()
    if s.startswith("npm:"):
        return original_spec
    if pin_all:
        return recommended
    if s.startswith("^"):
        return f"^{recommended}"
    if s.startswith("~"):
        return f"~{recommended}"
    return recommended


def apply_direct_specs(pkg: dict[str, Any], plan: UpdatePlan) -> None:
    """Write final direct-dep specifiers to pkg in-place.

    Updated deps are relaxed via relax_spec (or exact-pinned for forced/pin-all);
    deps not in the plan are left untouched.
    """
    # Keyed by the manifest key, which is what this loop iterates. For an npm alias
    # (`uuid-v7: "npm:uuid@^7.0.0"`) the registry name never equals the key, so keying on
    # package_name matched nothing at all — and a plain `uuid` declared alongside an aliased
    # `uuid-*` could pick up the wrong entry's version.
    direct_entries = {e.identity: e for e in plan.direct_entries}
    for section in DEP_SECTIONS:
        for name, current_spec in list(pkg.get(section, {}).items()):
            entry = direct_entries.get(name)
            if entry is None:
                continue
            if entry.is_forced:
                pkg[section][name] = entry.recommended_version
            else:
                pkg[section][name] = relax_spec(current_spec, entry.recommended_version, plan.pin_all)


def write_transitive_overrides(pkg: dict[str, Any], plan: UpdatePlan) -> None:
    """Persist transitive recommendations as overrides in *pkg*, recording what OSS IQ wrote.

    Each is keyed to the copy it replaces (`name@<installed>`), so npm rewrites only the edges whose
    range reaches that copy. A plain `name` override would force the version onto every copy of the
    name, collapsing nested copies npm kept apart on purpose.

    Never overwrites a rule the user owns: a key whose value was edited since OSS IQ wrote it, or a
    rule of theirs that already governs the same copy, is left as it is. A rule written for one copy
    is never retired by another copy's entry in the same plan.
    """
    entries = [entry for entry in plan.all_entries if not entry.is_direct]
    if not entries:
        return

    overrides: dict[str, Any] = pkg.get("overrides", {})
    metadata: dict[str, Any] = pkg.get("ossiq:metadata", {})
    tool_overrides: dict[str, Any] = metadata.get("overrides", {})

    written: set[str] = set()
    for entry in entries:
        key = f"{entry.package_name}@{entry.current_version}"
        # A key the user deleted is free to be written again; one they edited is theirs.
        if overrides.get(key) is not None and not holds_recorded_value(overrides, tool_overrides, key):
            continue
        # Parsed per entry on purpose: earlier entries add and retire rules in `overrides`.
        governing = rules_governing(parse_override_rules(overrides), entry.package_name, entry.current_version)
        if user_owns_override(governing, overrides, tool_overrides):
            continue
        for stale in superseded_override_keys(governing, overrides, tool_overrides, keep={key, *written}):
            overrides.pop(stale, None)
            tool_overrides.pop(stale, None)
        overrides[key] = entry.recommended_version
        tool_overrides[key] = entry.recommended_version
        written.add(key)

    if written:
        pkg["overrides"] = overrides
        metadata["overrides"] = tool_overrides
        pkg["ossiq:metadata"] = metadata
