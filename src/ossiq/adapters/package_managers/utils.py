"""
Utils related to package managers
"""

import re

from cel import Context, evaluate

# Compiled pattern to extract the leading package name from a PEP 508 requirement spec
# (stops at version operators, extras bracket, environment markers, whitespace)
_PEP508_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")


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


def normalize_pep503_name(spec: str) -> str:
    """
    Extract and normalise a package name from a PEP 508 requirement specifier.

    Strips version operators, extras, environment markers, and whitespace, then
    applies PEP 503 normalisation (lowercase; collapse runs of [-_.] to a single '-').

    Examples:
        "urllib3<2.0"             -> "urllib3"
        "grpcio>=1.50"            -> "grpcio"
        "requests[security]>=2.0" -> "requests"
        "My_Package"              -> "my-package"
    """
    spec = spec.strip()
    m = _PEP508_NAME_RE.match(spec)
    name = m.group(1) if m else spec
    return re.sub(r"[-_.]+", "-", name).lower()
