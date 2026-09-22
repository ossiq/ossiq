"""Base scores for CVSS vector strings, covering CVSS v2.0 and v3.0/v3.1.

A vector string carries the metrics a score is derived from, never the score itself, so any caller
holding one (OSV reports CVE severity this way) has to run the specification's formula over it.
CVSS v4.0 scores through a MacroVector lookup table rather than a closed-form formula and is not
implemented here; its vectors read as unscorable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping

# CVSS v3.1 specification, section 7.1 (formula) and 7.4 (metric weights):
# https://www.first.org/cvss/v3-1/specification-document
# v3.0 and v3.1 agree on both; they diverge only in temporal and environmental metrics, which a
# base score never reads.
V3_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
V3_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
V3_USER_INTERACTION = {"N": 0.85, "R": 0.62}
V3_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}
# Changing scope makes the same privilege level count for more, so the weight depends on it.
V3_PRIVILEGES_REQUIRED_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
V3_PRIVILEGES_REQUIRED_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

# CVSS v2.0 complete guide, section 3.2.1: https://www.first.org/cvss/v2/guide
V2_ACCESS_VECTOR = {"L": 0.395, "A": 0.646, "N": 1.0}
V2_ACCESS_COMPLEXITY = {"H": 0.35, "M": 0.61, "L": 0.71}
V2_AUTHENTICATION = {"M": 0.45, "S": 0.56, "N": 0.704}
V2_IMPACT = {"N": 0.0, "P": 0.275, "C": 0.660}


def parse_metrics(vector: str) -> dict[str, str]:
    """Split a CVSS vector into its metric abbreviations and values.

    Args:
        vector: A vector string, with or without a leading "CVSS:<version>/" prefix.

    Returns:
        Each metric abbreviation mapped to its value; segments without a colon are dropped, and a
        version prefix survives harmlessly as a "CVSS" entry no formula looks up.
    """

    metrics: dict[str, str] = {}
    for segment in vector.split("/"):
        key, separator, value = segment.partition(":")
        if separator:
            metrics[key] = value
    return metrics


def roundup_to_tenth(value: float) -> float:
    """Round up to the next tenth, as the CVSS v3.1 Roundup function defines it.

    Works in integer hundred-thousandths because binary floating point makes the obvious
    `math.ceil(value * 10) / 10` lift an exact 4.0 to 4.1.
    """

    hundred_thousandths = round(value * 100_000)
    if hundred_thousandths % 10_000 == 0:
        return hundred_thousandths / 100_000
    return (hundred_thousandths // 10_000 + 1) / 10.0


class AbstractCvssVersion(ABC):
    """One CVSS version's base-score formula, dispatched by `supports`."""

    @staticmethod
    @abstractmethod
    def supports(vector: str) -> bool:
        """Whether this version recognises the vector string as its own."""

    @staticmethod
    @abstractmethod
    def base_score(metrics: Mapping[str, str]) -> float | None:
        """Score the parsed metrics, or None when a required one is missing or unrecognised."""


class CvssV3(AbstractCvssVersion):
    """CVSS v3.0 and v3.1, which share the base-score formula and its weights."""

    PREFIXES = ("CVSS:3.0/", "CVSS:3.1/")

    @staticmethod
    def supports(vector: str) -> bool:
        return vector.startswith(CvssV3.PREFIXES)

    @staticmethod
    def base_score(metrics: Mapping[str, str]) -> float | None:
        try:
            scope_changed = metrics["S"] == "C"
            privileges_required = (
                V3_PRIVILEGES_REQUIRED_SCOPE_CHANGED if scope_changed else V3_PRIVILEGES_REQUIRED_SCOPE_UNCHANGED
            )
            exploitability = (
                8.22
                * V3_ATTACK_VECTOR[metrics["AV"]]
                * V3_ATTACK_COMPLEXITY[metrics["AC"]]
                * privileges_required[metrics["PR"]]
                * V3_USER_INTERACTION[metrics["UI"]]
            )
            confidentiality = V3_IMPACT[metrics["C"]]
            integrity = V3_IMPACT[metrics["I"]]
            availability = V3_IMPACT[metrics["A"]]
        except KeyError:
            # A required metric is absent, or holds a value outside the tables (the "X" not-defined
            # placeholder among them). Reporting the vector unscorable beats inventing a number.
            return None

        impact_subscore = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
        if scope_changed:
            impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
        else:
            impact = 6.42 * impact_subscore

        if impact <= 0:
            return 0.0
        scope_multiplier = 1.08 if scope_changed else 1.0
        return roundup_to_tenth(min(scope_multiplier * (impact + exploitability), 10.0))


class CvssV2(AbstractCvssVersion):
    """CVSS v2.0, whose vectors carry no version prefix and so are recognised by their metrics."""

    @staticmethod
    def supports(vector: str) -> bool:
        # Authentication ("Au") exists in v2 and in no later version, so it is what separates a
        # bare v2 vector from arbitrary text that happens to contain slashes and colons.
        return not vector.startswith("CVSS:") and "AV:" in vector and "Au:" in vector

    @staticmethod
    def base_score(metrics: Mapping[str, str]) -> float | None:
        try:
            exploitability = (
                20.0
                * V2_ACCESS_VECTOR[metrics["AV"]]
                * V2_ACCESS_COMPLEXITY[metrics["AC"]]
                * V2_AUTHENTICATION[metrics["Au"]]
            )
            confidentiality = V2_IMPACT[metrics["C"]]
            integrity = V2_IMPACT[metrics["I"]]
            availability = V2_IMPACT[metrics["A"]]
        except KeyError:
            return None

        impact = 10.41 * (1 - (1 - confidentiality) * (1 - integrity) * (1 - availability))
        impact_factor = 0.0 if impact == 0 else 1.176
        return round((0.6 * impact + 0.4 * exploitability - 1.5) * impact_factor, 1)


# Supporting a further CVSS version means one more class and one more entry here.
CVSS_VERSIONS: tuple[type[AbstractCvssVersion], ...] = (CvssV3, CvssV2)


def parse_cvss_base_score(vector: str) -> float | None:
    """Compute the base score a CVSS vector string encodes.

    Args:
        vector: A vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".

    Returns:
        The base score, or None when no supported version claims the vector (v4.0 and anything
        that is not a vector at all included) or a required metric is missing or unrecognised.
    """

    vector = vector.strip()
    for version in CVSS_VERSIONS:
        if version.supports(vector):
            return version.base_score(parse_metrics(vector))
    return None


__all__ = ("CVSS_VERSIONS", "AbstractCvssVersion", "CvssV2", "CvssV3", "parse_cvss_base_score")
