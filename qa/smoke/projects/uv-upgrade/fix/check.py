"""The same checks without LegacyVersion, which no packaging release after 21 has."""

import idna
from packaging.version import InvalidVersion, Version

assert idna.encode("example.com") == b"example.com"
assert Version("1.2.3") < Version("1.2.4")
try:
    Version("not a version")
except InvalidVersion:
    pass
else:
    raise AssertionError("an invalid version was accepted")
print("ok")
