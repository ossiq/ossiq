"""
How a project installs its packages, as far as their declared requirements care.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

from ossiq.domain.common import normalize_dist_name


@dataclass(frozen=True)
class RequirementScope:
    """The extras a project enables and the oldest Python it supports.

    A release declares requirements gated on extras and on environment markers; whether one
    applies depends on the project, not on the release. The registry and the solver read it
    through this value so both judge a requirement the same way.

    Attributes:
        extras_by_package: Extras the project enables per package, keyed by `normalize_dist_name`.
        python_floor: Oldest Python the project supports as "X.Y"; None when it declares none.
    """

    extras_by_package: Mapping[str, frozenset[str]] = field(default_factory=dict)
    python_floor: str | None = None

    def extras_for(self, package: str) -> frozenset[str]:
        """Return the extras enabled on *package*, empty when it has none."""
        return self.extras_by_package.get(normalize_dist_name(package), frozenset())
