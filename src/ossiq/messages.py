HELP_TEXT = """
Utility to determine difference between versions of the same package.
Currently supported ecosystems:
 - NPM: TypeScript, JavaScript
"""

HELP_LAG_THRESHOULD = """
Time delta after which a package is considered to be lagging to highlight in the report.
Supported units: y/m/w/d/h, default: d (days).
"""

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
