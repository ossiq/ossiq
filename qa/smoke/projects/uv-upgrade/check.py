"""packaging 22 removed LegacyVersion; idna works on every release."""

import sys

import idna

from packaging import version

# Looked up by name: no packaging release after 21 has it, so importing it would fail a type check.
legacy_version = getattr(version, "LegacyVersion", None)
if legacy_version is None:
    # A plain message, like a test runner's: the matrix treats a printed traceback as an ossiq crash.
    sys.exit("packaging has no LegacyVersion: it was removed in 22.0")

assert idna.encode("example.com") == b"example.com"
assert version.Version("1.2.3") < version.Version("1.2.4")
assert legacy_version("not a version") is not None
print("ok")
