HELP_TEXT = """
Utility to determine difference between versions of the same package.
Currently supported ecosystems:
 - NPM: TypeScript, JavaScript
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

ARGS_HELP_CUTOFF_DATE = (
    "Treat versions published after this ISO date (e.g. 2026-05-01) as invisible. "
    "Translates to 23:59:59 UTC of that date. Overrides OSSIQ_CUTOFF_DATE env var."
)
ARGS_HELP_COOLDOWN_PERIOD = (
    "Versions younger than this many days receive a freshness soft-penalty in the solver "
    "(default: 7). Overrides OSSIQ_COOLDOWN_PERIOD env var."
)

HELP_PACKAGE_COMMAND = """
Deep-dive into a single package: drift status, dependency tree trace, policy compliance,
security advisories, and transitive dependency CVEs.
"""

ERROR_PACKAGE_NOT_FOUND = """
Package `{package_name}` not found in the project dependency tree.
"""

HELP_UPDATE_COMMAND = """
Plan or execute solver-recommended package version updates.

Use `ossiq update plan` to preview what would change.
Use `ossiq update execute` to apply updates in-process with rollback on failure.
Use `--pin-all` to write exact ==version specifiers for updated deps.
Use `--rewrite-versions` to also update PINNED (==x.y.z) deps that are otherwise frozen.
"""

HELP_UPDATE_NO_RECOMMENDATIONS = (
    "No updates recommended — the solver found all packages are already at optimal versions."
)
