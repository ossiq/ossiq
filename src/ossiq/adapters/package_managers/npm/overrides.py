"""
The `overrides` block of package.json: parsing it into rules, deciding which rule governs a
copy of a package, and telling the rules OSS IQ wrote apart from the ones the user did.

Pure: no I/O, so the same rules serve the lockfile read side and the manifest write side.
"""

from collections.abc import Collection, Iterable
from dataclasses import dataclass

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.solver.version_matchers import version_satisfies_constraint


@dataclass(frozen=True)
class OverrideRule:
    """One rule of a package.json `overrides` block, lifted out of its nesting.

    Mirrors npm's own override sets (arborist `override-set.js`): a rule names a package, may be
    keyed to the versions it applies to (`foo@^1`), and may be scoped under ancestor packages.
    """

    name: str
    value: str
    # The range the rule is keyed to; None when it applies to every version of the package.
    key: str | None = None
    # Ancestor package names the rule is scoped under, outermost first. Empty for a root rule.
    scope_path: tuple[str, ...] = ()
    # The key exactly as written in package.json, which is how OSS IQ's own metadata block names it.
    raw_key: str = ""


def split_override_key(raw_key: str) -> tuple[str, str | None]:
    """Split an overrides key into its package name and the range it is keyed to.

    Args:
        raw_key: A key as written in `overrides`, e.g. `foo`, `foo@^1.2` or `@scope/foo@1.2.3`.

    Returns:
        The package name, and the range after the last `@` that isn't the scope marker; None when
        the key carries no range.
    """
    at = raw_key.rfind("@")
    if at > 0:
        return raw_key[:at], raw_key[at + 1 :] or None
    return raw_key, None


def collect_override_rules(overrides: dict, scope: tuple[str, ...], rules: list[OverrideRule]) -> None:
    """Append every rule under *overrides* to *rules*, in document order, recursing into scopes."""
    for raw_key, value in overrides.items():
        name, key = split_override_key(raw_key)
        if isinstance(value, str):
            rules.append(OverrideRule(name=name, value=value, key=key, scope_path=scope, raw_key=raw_key))
        elif isinstance(value, dict):
            # "." is npm's self-reference: what the package itself is forced to, as opposed to
            # what its descendants are.
            own = value.get(".")
            if isinstance(own, str):
                rules.append(OverrideRule(name=name, value=own, key=key, scope_path=scope, raw_key=raw_key))
            nested = {child: spec for child, spec in value.items() if child != "."}
            if nested:
                collect_override_rules(nested, (*scope, name), rules)


def parse_override_rules(overrides: object) -> list[OverrideRule]:
    """Flatten an npm `overrides` block into rules.

    Handles flat entries (`{"foo": "1.0.0"}`), version-keyed ones (`{"foo@^1": "1.2.3"}`) and
    scoped ones (`{"foo": {".": "1.0.0", "bar": "2.0.0"}}`, where `bar` is forced only beneath `foo`).

    Args:
        overrides: The decoded `overrides` value; anything but a mapping yields no rules.

    Returns:
        The rules, outermost scope first within each entry.
    """
    rules: list[OverrideRule] = []
    if isinstance(overrides, dict):
        collect_override_rules(overrides, (), rules)
    return rules


def override_rule_matches_version(rule: OverrideRule, version: str) -> bool:
    """Whether *version* of the rule's package counts as governed by the rule.

    The same test as arborist's `getNodeRule`: the version sits inside the rule's key, or already
    sits at what the rule forces.
    """
    if rule.key is None:
        return True
    if version_satisfies_constraint(version, rule.key, ProjectPackagesRegistry.NPM):
        return True
    # A `$name` value follows a root dependency's spec; it is not a range to test against.
    return not rule.value.startswith("$") and version_satisfies_constraint(
        version, rule.value, ProjectPackagesRegistry.NPM
    )


def rules_governing(rules: Iterable[OverrideRule], name: str, version: str) -> list[OverrideRule]:
    """The rules that govern this copy of *name*, in the order they were written."""
    return [rule for rule in rules if rule.name == name and override_rule_matches_version(rule, version)]


def select_governing_rule(rules: Iterable[OverrideRule], name: str, version: str) -> OverrideRule | None:
    """The one rule that governs this copy of *name*, or None.

    A rule keyed to specific versions is the more specific statement, so it wins over a blanket one.
    """
    governing = rules_governing(rules, name, version)
    return next((rule for rule in governing if rule.key is not None), governing[0] if governing else None)


def holds_recorded_value(overrides: dict[str, object], tool_overrides: dict[str, object], key: str) -> bool:
    """Whether *key* holds exactly what OSS IQ last recorded for it; absent from both counts as equal.

    Args:
        overrides: The manifest's `overrides` block.
        tool_overrides: What OSS IQ last wrote (`ossiq:metadata.overrides`).
        key: A key as written in `overrides`.
    """
    return tool_overrides.get(key) == overrides.get(key)


def user_owns_override(
    governing: Iterable[OverrideRule], overrides: dict[str, object], tool_overrides: dict[str, object]
) -> bool:
    """Whether any of the *governing* rules is one the user wrote or has edited since OSS IQ did.

    A key counts as OSS IQ's only while its value is still the one OSS IQ last wrote there; a value
    edited since belongs to the user, and so does any key OSS IQ never wrote.
    """
    return any(not holds_recorded_value(overrides, tool_overrides, rule.raw_key) for rule in governing)


def superseded_override_keys(
    governing: Iterable[OverrideRule],
    overrides: dict[str, object],
    tool_overrides: dict[str, object],
    keep: Collection[str],
) -> list[str]:
    """Keys OSS IQ wrote earlier for this copy, which a new rule for it replaces.

    A bump moves the copy to a new version, so the rule that produced the current one is left
    stale beside the new rule. Scoped rules are the user's by construction and are never returned.

    Args:
        governing: The rules governing the copy, from `rules_governing`.
        overrides: The manifest's `overrides` block.
        tool_overrides: What OSS IQ last wrote (`ossiq:metadata.overrides`).
        keep: Keys that must survive: the one being written, and those written for other copies
            earlier in the same update.
    """
    return [
        rule.raw_key
        for rule in governing
        if rule.raw_key not in keep
        and not rule.scope_path
        and holds_recorded_value(overrides, tool_overrides, rule.raw_key)
    ]
