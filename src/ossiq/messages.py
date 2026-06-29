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
ARGS_HELP_CACHE_DESTINATION = """Directory where cache will be stored"""
ARGS_HELP_CACHE_TTL = """For how long cache is stored"""
ARGS_HELP_PRESENTATION = """Output could be generated as console output, html or json"""
ARGS_HELP_OUTPUT = """Destination where to generate output,
appropriate for respective presentations"""

HELP_PRODUCTION_ONLY = """
Exclude non-production packages. Default: false
"""

HELP_REGISTRY_TYPE = """
Specify which project registry type (ecosystem) to use. Default: None. Possible options: npm, pypi
"""

HELP_OUTPUT_FORMAT = """
Output format. Default: json. Possible options: json, csv, cyclonedx
"""

HELP_SCHEMA_VERSION = """
Export schema version. Default: latest. Possible options: 1.0, 1.1
"""

WARNING_MULTIPLE_REGISTRY_TYPES = """
`{project_path}` contains multiple registry types. Use `--registry-type` option to narrow it down
"""

ERROR_EXIT_OUTDATED_PACKAGES = """There are libraries with outdated versions:
exiting with non-zero exit code
""".replace("\n", " ")

HELP_PACKAGE_NAME = """
Name of the package to inspect. Exact match against the package name or its alias (case-insensitive).
"""

HELP_IGNORE_PACKAGE = "Exclude package from solver recommendations (repeatable)."

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

HELP_INFO_COMMAND = """
Deep-dive into a single package: drift status, dependency tree trace, policy compliance,
security advisories, and transitive dependency CVEs.
"""

ERROR_PACKAGE_NOT_FOUND = """
Package `{package_name}` not found in the project dependency tree.
"""

HELP_PLAN_COMMAND = """
Show solver-recommended package version changes without making any changes.

Use `--script` to emit a bash update script instead of the plan table.
Use `--pin-all` to write exact ==version specifiers for updated deps.
Use `--rewrite-versions` to also include PINNED (==x.y.z) deps that are otherwise frozen.
Use `--override pkg==version` to force an exact version, bypassing the solver and cooldown.
Use `--security` to narrow the plan to CVE-affected packages only.
"""

HELP_APPLY_COMMAND = """
Apply solver-recommended updates in-process with rollback on failure.

Shows the plan first and prompts for confirmation (use `--yes` for CI).
"""

HELP_PLAN_NO_RECOMMENDATIONS = "No updates recommended — the solver found all packages are already at optimal versions."

HELP_SECURITY_ONLY = "Include only CVE-affected packages (direct and transitive) in the update plan."

HELP_PLAN_NO_SECURITY_RECOMMENDATIONS = "No CVE-affected packages need updates — nothing to do under --security."

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

HELP_PLAN_CVE_BYPASS_NOTE = "↳ cooldown bypassed — installed version has a known CVE"

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
