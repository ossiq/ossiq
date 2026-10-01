"""
A package manager's own limit on how recent a release it will install.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ReleaseCutoff:
    """Latest publish instant a package manager will resolve to, globally and per package.

    Attributes:
        default: Cutoff for every package without its own entry; None when there is none.
        per_package: Overrides keyed by normalized package name. A None value lifts the cutoff for
            that package (uv's `exclude-newer-package = { name = false }`).
    """

    default: datetime | None = None
    per_package: Mapping[str, datetime | None] = field(default_factory=dict)

    def cutoff_for(self, package_name: str) -> datetime | None:
        """Return the cutoff that applies to `package_name`, or None when it is unrestricted."""
        if package_name in self.per_package:
            return self.per_package[package_name]
        return self.default
