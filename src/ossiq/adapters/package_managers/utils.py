"""
Utils related to package managers
"""

from cel import Context, evaluate
from packaging.specifiers import SpecifierSet
from packaging.version import Version


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


def extract_min_python_version(requires_python: str) -> str | None:
    """Return 'X.Y' for the minimum Python declared in a requires-python specifier.

    Parses >= / ~= / == operators to find the lowest declared lower bound.
    Returns None when the specifier is unparseable or has no lower bound.
    """

    try:
        bounds = [Version(s.version) for s in SpecifierSet(requires_python) if s.operator in (">=", "~=", "==")]
        if bounds:
            m = min(bounds)
            return f"{m.major}.{m.minor}"
    except ValueError:
        pass
    return None
