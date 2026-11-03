"""Tests for the trust tier ladder."""

from ossiq.domain.provenance import (
    SOURCE_REASON_PREFIX,
    ProvenanceFacts,
    ProvenancePolicy,
    SourceLevel,
    TrustTier,
)
from ossiq.risk.provenance import source_violation


class TestTrustTier:
    def test_the_ladder_runs_from_no_evidence_to_a_trusted_publisher(self):
        assert [tier.rank for tier in (TrustTier.NONE, TrustTier.PROVENANCE, TrustTier.TRUSTED_PUBLISHER)] == [0, 1, 2]

    def test_a_stronger_tier_outranks_a_weaker_one(self):
        assert TrustTier.TRUSTED_PUBLISHER.rank > TrustTier.PROVENANCE.rank > TrustTier.NONE.rank

    def test_tiers_are_spelled_as_the_config_file_will_spell_them(self):
        assert [tier.value for tier in TrustTier] == ["none", "provenance", "trusted-publisher"]


class TestViolationsByDimension:
    """A surface marks the Build cell for build reasons and the Source cell for repository reasons."""

    BUILD = "no provenance, below the required provenance"
    SOURCE = "source repository is version-controlled, below the required protected-history"

    def test_repository_reasons_are_the_source_ones(self):
        facts = ProvenanceFacts(violations=(self.BUILD, self.SOURCE))

        assert facts.source_violations == (self.SOURCE,)

    def test_every_other_reason_is_a_build_one(self):
        facts = ProvenanceFacts(violations=(self.BUILD, "trust downgrade: no provenance", self.SOURCE))

        assert facts.build_violations == (self.BUILD, "trust downgrade: no provenance")

    def test_no_violations_split_into_nothing(self):
        facts = ProvenanceFacts()

        assert facts.source_violations == () and facts.build_violations == ()

    def test_the_wording_the_policy_actually_produces_is_recognized_as_a_source_reason(self):
        # Guards the prefix against a reworded message: the split is only as good as this match.
        reason = source_violation(ProvenancePolicy(min_source=SourceLevel.REVIEWED), SourceLevel.VERSION_CONTROLLED)

        assert reason is not None and reason.startswith(SOURCE_REASON_PREFIX)
        assert ProvenanceFacts(violations=(reason,)).source_violations == (reason,)
