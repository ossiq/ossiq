"""Tests for classify_motives: reducing raw evidence to the four UpdateMotive flags."""

import dataclasses
from typing import Any

from ossiq.strategy.motive import PackageFacts, UpdateMotive, classify_motives

BASE_FACTS = PackageFacts(
    package_name="example",
    installed_version="1.0.0",
    cve_epss_scores=(),
    maintenance_state=None,
    is_registry_deprecated=False,
    deprecation_strength="none",
)


def make_facts(**overrides: Any) -> PackageFacts:
    return dataclasses.replace(BASE_FACTS, **overrides)


def test_unscored_cve_counts_as_exploitable() -> None:
    facts = make_facts(cve_epss_scores=(None,))
    motives = classify_motives(facts)
    assert UpdateMotive.EXPLOITABLE_CVE in motives
    assert UpdateMotive.SUPPRESSED_CVE not in motives


def test_cve_below_noise_floor_is_suppressed_only() -> None:
    facts = make_facts(cve_epss_scores=(0.001,))
    motives = classify_motives(facts)
    assert UpdateMotive.SUPPRESSED_CVE in motives
    assert UpdateMotive.EXPLOITABLE_CVE not in motives


def test_cve_at_or_above_noise_floor_is_exploitable() -> None:
    facts = make_facts(cve_epss_scores=(0.005,))
    motives = classify_motives(facts)
    assert UpdateMotive.EXPLOITABLE_CVE in motives
    assert UpdateMotive.SUPPRESSED_CVE not in motives


def test_mixed_cves_set_both_flags() -> None:
    facts = make_facts(cve_epss_scores=(0.001, 0.5))
    motives = classify_motives(facts)
    assert UpdateMotive.EXPLOITABLE_CVE in motives
    assert UpdateMotive.SUPPRESSED_CVE in motives


def test_winding_down_alone_is_not_end_of_life() -> None:
    facts = make_facts(maintenance_state="winding_down")
    assert UpdateMotive.END_OF_LIFE not in classify_motives(facts)


def test_abandoned_is_end_of_life() -> None:
    facts = make_facts(maintenance_state="abandoned")
    assert UpdateMotive.END_OF_LIFE in classify_motives(facts)


def test_deprecated_state_is_end_of_life() -> None:
    facts = make_facts(maintenance_state="deprecated")
    assert UpdateMotive.END_OF_LIFE in classify_motives(facts)


def test_registry_deprecation_marker_is_end_of_life() -> None:
    facts = make_facts(is_registry_deprecated=True)
    assert UpdateMotive.END_OF_LIFE in classify_motives(facts)


def test_strong_deprecation_evidence_is_end_of_life() -> None:
    facts = make_facts(deprecation_strength="strong")
    assert UpdateMotive.END_OF_LIFE in classify_motives(facts)


def test_weak_deprecation_evidence_alone_is_not_end_of_life() -> None:
    facts = make_facts(deprecation_strength="weak")
    assert UpdateMotive.END_OF_LIFE not in classify_motives(facts)


def test_drift_is_unconditional() -> None:
    assert UpdateMotive.DRIFT in classify_motives(make_facts())
