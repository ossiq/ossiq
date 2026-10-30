"""
The `overrides` pnpm records at the top of pnpm-lock.yaml, parsed into the rules npm's overrides
use, so one marking pass serves both lockfiles.

Pure: no I/O.
"""

import re

from ossiq.adapters.package_managers.npm.overrides import OverrideRule, split_override_key

# pnpm's own parent delimiter: a `>` that does not follow `@`, `|` or a space, so the range in
# `foo@>1` is not mistaken for a parent selector.
PARENT_DELIMITER = re.compile(r"(?<=[^ |@])>")


def parse_pnpm_override_rules(overrides: object) -> list[OverrideRule]:
    """Turn pnpm's flat override keys into rules.

    pnpm writes `foo`, `foo@^2` and `qar@1>zoo` (zoo, forced only beneath qar) as flat keys instead
    of npm's nesting. Like pnpm, only the first `>` splits a key.

    Args:
        overrides: The decoded `overrides` mapping; anything else yields no rules.

    Returns:
        One rule per entry with a string value, in document order.
    """
    if not isinstance(overrides, dict):
        return []
    rules = []
    for raw_key, value in overrides.items():
        # YAML keys need not be strings (`1: foo`).
        if not (isinstance(raw_key, str) and isinstance(value, str)):
            continue
        *parents, target = PARENT_DELIMITER.split(raw_key, maxsplit=1)
        name, key = split_override_key(target)
        # shortcut: the parent's version selector is dropped, so `a@1>b` scopes under any `a`;
        # a scoped rule counts as the user's either way.
        scope_path = tuple(split_override_key(parent)[0] for parent in parents)
        rules.append(OverrideRule(name=name, value=value, key=key, scope_path=scope_path, raw_key=raw_key))
    return rules
