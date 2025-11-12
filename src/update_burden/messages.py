HELP_TEXT = """
Utility to determine difference between versions of the same package.
Currently supported ecosystems:
 - NPM: TypeScript, JavaScript
"""

HELP_LAG_THRESHOULD = """
Time delta after which a package is considered to be lagging.
Supported units: y/m/w/d/h, default: d (days).
Exit with non-zero status code if lag exceeds this threshold.
"""

ARGS_HELP_GITHUB_TOKEN = """The server host. Overrides respective env var."""
ARGS_HELP_PRESENTATION = """Output could be generated as console output, html or json"""
ARGS_HELP_OUTPUT = """Destination where to generate output,
appropriate for respective presentations"""

HELP_PRODUCTION_ONLY = """
Exclude development packages if specified. Default: false
"""

ERROR_EXIT_OUTDATED_PACKAGES = """There are libraries with outdated versions:
exiting with non-zero exit code
""".replace("\n", " ")
