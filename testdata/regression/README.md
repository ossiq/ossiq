# Regression fixtures

Projects whose expected OSS IQ output is written down next to them, checked by scripts under
`qa/`. Unlike the other `testdata/` projects, these are frozen. Don't edit a dependency or
regenerate a lockfile unless you update its `expectations.toml` in the same change.

| Directory | Checked by | What it pins |
|-----------|------------|--------------|
| `update-strategies/` | `qa/update_strategies_regression.py` (`just qa-strategies`) | What each `--update-strategy` tier recommends, plans and applies |

How each suite works, and how to add a project to it: [qa/README.md](../../qa/README.md).
