"""
A package manager's own limit on how recent a release it will install.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from ossiq.domain.common import normalize_dist_name


@dataclass(frozen=True)
class ReleaseCutoff:
    """Latest publish instant a package manager will resolve to, globally and per package.

    The package manager enforces it on every version it moves to, whatever OSS IQ recommends, but
    leaves an already-locked version alone even when it postdates the cutoff.

    Attributes:
        source: The setting that imposes the cutoff, as messages name it (e.g. "uv exclude-newer").
        default: Cutoff for every package without its own entry; None when there is none.
        per_package: Overrides keyed by `normalize_dist_name`. A None value lifts the cutoff for
            that package (uv's `exclude-newer-package = { name = false }`).
    """

    source: str
    default: datetime | None = None
    per_package: Mapping[str, datetime | None] = field(default_factory=dict)

    def cutoff_for(self, package_name: str) -> datetime | None:
        """Return the cutoff that applies to `package_name`, or None when it is unrestricted."""
        key = normalize_dist_name(package_name)
        if key in self.per_package:
            return self.per_package[key]
        return self.default

    def admits(self, package_name: str, published_at: datetime | None) -> bool:
        """Return whether the package manager would move `package_name` to a release published then.

        An unknown publish time is admitted, the same rule the cooldown applies: missing data never
        withholds a release.
        """
        cutoff = self.cutoff_for(package_name)
        return cutoff is None or published_at is None or published_at <= cutoff
