HELP_TEXT = """
Dependency health and update tool for NPM and PyPI projects.

Run `ossiq` (or `ossiq status`) from your project directory for an overview.
Use `ossiq plan` to see what would change, `ossiq apply` to execute updates.
"""

HELP_LAG_THRESHOULD = """
Time delta after which a package is considered to be lagging to highlight in the report.
Supported units: y/m/w/d/h, default: d (days).
"""

ARGS_HELP_DEBUG = "Enable debug logging output (logging module). Overrides OSSIQ_DEBUG env var."

ARGS_HELP_GITHUB_TOKEN = """Github Token to increase requests limits"""
ARGS_HELP_CONFIG = """Path to a config file with OSSIQ_* values (default: ~/.ossiq/config)"""
ARGS_HELP_CACHE_DESTINATION = """Directory where cache will be stored (default: ~/.ossiq/cache.sqlite3)"""
ARGS_HELP_CACHE_TTL = """For how long cache is stored"""
ARGS_HELP_OUTPUT = """Destination where to generate output"""

HELP_PRODUCTION_ONLY = """
Exclude non-production packages. Default: false
"""

HELP_STATUS_FULL = """
Show every dependency and the detail columns (EPSS, update mode, installed, lag, maintenance
state). Default: only packages that need action, with a minimal column set.
"""

HELP_REGISTRY_TYPE = """
Specify which project registry type (ecosystem) to use. Default: None. Possible options: npm, pypi
"""

HELP_SCHEMA_VERSION = """
Export schema version. Default: latest. Possible options: 1.5
"""

WARNING_MULTIPLE_REGISTRY_TYPES = """
`{project_path}` contains multiple registry types. Use `--registry-type` option to narrow it down
"""

# The inspected filenames come from the adapters themselves (api.inspected_manifests), so this text
# never has to be kept in step with which adapters exist.
HINT_NO_PACKAGE_MANAGER = (
    "Inspected {inspected}; found: {found}. "
    "A pyproject.toml alone needs either a lockfile (uv.lock, pylock.toml) or a non-empty "
    "[project].dependencies section - a Poetry-only manifest ([tool.poetry.dependencies]) "
    "isn't supported yet."
)

ERROR_EXIT_OUTDATED_PACKAGES = """There are libraries with outdated versions:
exiting with non-zero exit code
""".replace("\n", " ")

HELP_PACKAGE_NAME = """
Name of the package to inspect. Exact match against the package name or its alias (case-insensitive).
"""

HELP_IGNORE_PACKAGE = "Exclude package from solver recommendations (repeatable)."

HELP_ALLOW_PARTIAL = (
    "Accept a result built on incomplete data. Only --update-strategy security/deprecation refuse "
    "one: without vulnerability data their 'nothing to do' is indistinguishable from a clean project."
)

IGNORE_REASON_NON_REGISTRY = "not on npm registry (git/URL source)"
IGNORE_REASON_IGNORE_FLAG = "excluded via --ignore"

HELP_PIN_ALL = "Write exact ==version specifiers for every updated direct dependency."

HELP_REWRITE_VERSIONS = "Include already-pinned (==x.y.z) dependencies in the plan and rewrite their pinned version."

ARGS_HELP_CUTOFF_DATE = (
    "Treat versions published after this ISO date (e.g. 2026-05-01) as invisible. "
    "Translates to 23:59:59 UTC of that date. Overrides OSSIQ_CUTOFF_DATE env var."
)
ARGS_HELP_COOLDOWN_PERIOD = (
    "Versions younger than this many days receive a freshness soft-penalty in the solver "
    "(default: 7). Overrides OSSIQ_COOLDOWN_PERIOD env var."
)
ARGS_HELP_STABILITY = (
    "Measure upstream repository stability and maintenance state (default: on). Costs two GitHub "
    "requests per direct-dependency repo (commit sample + README deprecation scan); disable it "
    "with --no-stability where the API quota is tight. Overrides OSSIQ_STABILITY env var."
)
ARGS_HELP_STABILITY_CACHE_TTL = (
    "For how long GitHub stability data (commits, activity, README) is cached, in hours "
    "(default: 168, i.e. 7 days). Overrides OSSIQ_STABILITY_CACHE_TTL env var."
)
ARGS_HELP_STABILITY_RESPONSIVENESS = (
    "Compute the engagement-flow trend of the maintenance model from a batched GitHub GraphQL "
    "query over a 180-day window (~2-6 requests per direct-dependency repo). Requires a GitHub "
    "token; defaults on when one is set, off otherwise. Overrides OSSIQ_STABILITY_RESPONSIVENESS "
    "env var."
)
ARGS_HELP_PROBE_RUNTIME = (
    "Detect the actually-installed Python/Node/npm runtime (default: on), preferred over the "
    "project's declared engine floor when checking recommendation compatibility. Runs a few local "
    "subprocess/file probes (timeout 3s each, never blocks a scan on failure); disable with "
    "--no-probe-runtime for CI/sandboxed environments or to compare only against the declared "
    "floor. Overrides OSSIQ_PROBE_RUNTIME env var."
)

HELP_INFO_COMMAND = """
Deep-dive into a single package: drift status, dependency tree trace, policy compliance,
security advisories, and transitive dependency CVEs.
"""

ERROR_PACKAGE_NOT_FOUND = """
Package `{package_name}` not found in the project dependency tree.
"""

HELP_PLAN_COMMAND = """
Show solver-recommended package version changes without making any changes.

Use `--pin-all` to write exact ==version specifiers for updated deps.
Use `--rewrite-versions` to also include PINNED (==x.y.z) deps that are otherwise frozen.
Use `--override pkg==version` to force an exact version, bypassing the solver and cooldown.
Use `--update-strategy` to pick which tier of the update pyramid to target (default: standard).
"""

HELP_APPLY_COMMAND = """
Apply solver-recommended updates in-process with rollback on failure.

Shows the plan first and prompts for confirmation (use `--yes` for CI). A second confirmation
covers any update that widens the declared version constraint or carries a known API break.
"""

HELP_PLAN_NO_RECOMMENDATIONS = "No updates recommended — the solver found all packages are already at optimal versions."

HELP_PLAN_NO_RECOMMENDATIONS_FOR_TIER = "No packages need updates under --update-strategy {tier} — nothing to do."

HELP_UPDATE_STRATEGY = (
    "Which tier of the update pyramid to target: security, deprecation, standard (default), "
    "latest, cutting-edge. Each tier is a strict superset of the one below — see strategy/README.md."
)

HELP_STRATEGY_OVERRIDE = (
    "Run one package at a different tier than --update-strategy: pkg=tier (repeatable). "
    "E.g. --strategy-override lodash=cutting-edge."
)

ERROR_STRATEGY_OVERRIDE_IGNORE_CONFLICT = (
    "Cannot both --strategy-override and --ignore the same package(s): {packages}."
)

WARNING_STRATEGY_OVERRIDE_UNKNOWN_PACKAGE = (
    "--strategy-override {package}: package not found in the dependency tree — ignored."
)

WARNING_STRATEGY_OVERRIDE_SHADOWED_BY_OVERRIDE = (
    "--strategy-override {package}: ignored — --override forces an exact version for this package."
)

HELP_PLAN_HIGHER_TIER_FOOTER = "{count} more update{plural} available under --update-strategy {tier}."

HELP_PLAN_ACKNOWLEDGE_CONFIRM_HEADER = (
    "The following updates need explicit acknowledgement - they widen the declared version "
    "constraint (authorized by --update-strategy {tier}), or carry a known API/module-system break:"
)

HELP_OVERRIDE_PACKAGE = (
    "Force a package to an exact version, bypassing the solver and the cooldown: --override pkg==1.2.3 "
    "(repeatable). Direct deps get their specifier rewritten; transitive deps get a persistent override entry."
)

ERROR_OVERRIDE_SPEC_INVALID = (
    "Invalid --override value `{value}`. Expected format: package==version (e.g. lodash==4.17.21)."
)

ERROR_OVERRIDE_DUPLICATE = "Conflicting --override values for `{package}`: specify each package only once."

ERROR_OVERRIDE_IGNORE_CONFLICT = "Cannot both --override and --ignore the same package(s): {packages}."

ERROR_OVERRIDE_UNKNOWN_PACKAGES = (
    "--override target(s) not found in the dependency tree: {packages}. Check the spelling, or remove the override."
)

WARNING_OVERRIDE_VERSION_UNKNOWN = (
    "--override {package}=={version}: version not found in the registry — install may fail."
)

WARNING_OVERRIDE_AMBIGUOUS_ALIAS = (
    "--override {package}: the project declares it under several manifest keys ({aliases}), which "
    "npm installs as separate copies. Only one can be forced — name the key instead to pick it."
)

HELP_PLAN_FORCED_WARNING = (
    "Forced versions (--override) bypass solver compatibility checks and the cooldown period. "
    "OSS IQ has not verified these versions satisfy parent constraints — review and test before shipping."
)

HELP_PLAN_NEW_DEP_FRESH_WARNING = (
    "⚠ new dependencies younger than the {days}-day cooldown — the cooldown hold does not apply to packages "
    "entering your tree for the first time; review them before applying."
)

HELP_PLAN_CONVERGENCE_NOTICE = (
    "Applying this plan re-resolves the dependency tree, which can surface further updates. "
    "Re-run `ossiq plan` after `ossiq apply` to evaluate the updated tree."
)

HELP_PLAN_HELD_FOR_COOLDOWN_HEADER = (
    "Held for cooldown — newer versions exist but are younger than the {days}-day cooldown:"
)

HELP_PLAN_HELD_FOR_WIDENING_HEADER = "Requires constraint widening — a newer version exists outside the declared range:"

HELP_STATUS_COOLDOWN_HOLD = (
    "↳ {version} is {age_days} days old; nothing older to move to before the {days}-day cooldown"
)

HELP_PLAN_CVE_BYPASS_NOTE = "↳ cooldown bypassed — installed version has a known CVE or is end-of-life"

HELP_PLAN_KNOWN_BREAK_NOTE = "↳ known API/module-system break — every newer release carries it, so none was held back"

HELP_ADD_COMMAND = """
Inspect a package's health metrics and warnings before adding it to your project.

Fetches metadata, CVE data, download counts, and maintainer info, then runs
the package health rules. Blocks on critical warnings unless --force is passed.
Use --version to pin an exact version.
"""

HELP_ADD_PACKAGE_NAME = "Name of the package to inspect and add."

HELP_ADD_VERSION = "Pin to a specific version (e.g. 1.2.3). Default: latest recommended."

HELP_ADD_FORCE = "Proceed even if critical health warnings are present."

HELP_APPLY_RERUN_HINT = (
    "Updates are resolved in a single pass; applying them re-resolves the dependency tree and can surface "
    "further recommendations. Re-run `ossiq plan` to check whether a follow-up pass is needed."
)

HELP_UPDATE_CONTEXT_COMMAND = """
Diff a package's installed (or prospective) version against an arbitrary target version.

Reports module-system/API breaking changes, engine (Node/Python) compatibility against the
detected or declared runtime, and any candidates rejected along the way — for a specific version
an agent is considering, which need not be OSS IQ's own recommendation. Use before applying an
update to a version other than `recommended_version`.
"""

HELP_UPDATE_CONTEXT_TO = "Target version to evaluate against. Default: OSS IQ's recommended_version."
