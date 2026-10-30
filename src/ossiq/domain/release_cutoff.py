"""
A package manager's own limit on how recent a release it will install.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase

from ossiq.domain.common import normalize_dist_name


@dataclass(frozen=True)
class ReleaseCutoff:
    """Latest publish instant a package manager will resolve to, globally and per package.

    The package manager enforces it on every version it moves to, whatever OSS IQ recommends. uv
    leaves an already-locked version alone even when it postdates the cutoff; pnpm 11 and later
    re-check locked entries too.

    Attributes:
        source: The setting that imposes the cutoff, as messages name it (e.g. "uv exclude-newer").
        default: Cutoff for every package without its own entry; None when there is none.
        per_package: Overrides keyed by `normalize_dist_name`, or by a lowercase glob when the key
            contains `*` (pnpm's `minimumReleaseAgeExclude: ["@org/*"]`). A None value lifts the
            cutoff for that package (uv's `exclude-newer-package = { name = false }`).
    """

    source: str
    default: datetime | None = None
    per_package: Mapping[str, datetime | None] = field(default_factory=dict)

    def cutoff_for(self, package_name: str) -> datetime | None:
        """Return the cutoff that applies to `package_name`, or None when it is unrestricted."""
        key = normalize_dist_name(package_name)
        if key in self.per_package:
            return self.per_package[key]
        # Globs match the raw lowercase name: normalize_dist_name("react-*") would cut it to "react".
        name = package_name.lower()
        for pattern, cutoff in self.per_package.items():
            if "*" in pattern and fnmatchcase(name, pattern):
                return cutoff
        return self.default

    def admits(self, package_name: str, published_at: datetime | None) -> bool:
        """Return whether the package manager would move `package_name` to a release published then.

        An unknown publish time is admitted, the same rule the cooldown applies: missing data never
        withholds a release.
        """
        cutoff = self.cutoff_for(package_name)
        return cutoff is None or published_at is None or published_at <= cutoff
