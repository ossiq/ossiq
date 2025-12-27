"""
Utils related to package managers
"""

from cel import Context, evaluate


def find_lockfile_parser(
    supported_versions,
    options: dict,
) -> str | None:
    """
    Find and return lockfile parser instance: suppose to be one of
    instances of this class, dedicated to a specific schema version.

    Parser could be reused across different schema versions if
    schema change is not relevant to the information needed.
    """
    context = Context(options)

    for version_condition, version_handler in supported_versions.items():
        if evaluate(version_condition, context):
            return version_handler

    return None
