"""Whether a scan's result is trustworthy enough to report as an answer.

`status` is deliberately not a CI gate — it exits 0 on a project full of `evict` verdicts, and any
gate belongs in the consumer's own check over the JSON export. This module carves out the one case
where silence is indistinguishable from a clean answer: a security-tier run whose vulnerability
data never arrived prints *"No packages need updates under --update-strategy security — nothing to
do."*, character for character what a genuinely clean project prints.

Lives in `service/` rather than in a command so the CLI and the MCP server apply one rule — the
CLI turns the raised error into an exit code, MCP into a titled error payload.
"""

from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
from ossiq.domain.exceptions import SecurityDataIncomplete
from ossiq.strategy.pyramid import MINIMAL_DIFF_TIERS, UpdateStrategy

# The steps a security-tier verdict actually rests on. REPOSITORIES feeds `end_of_life`, which
# `deprecation` admits, but a missing maintenance signal degrades that tier's coverage rather than
# emptying its result the way a missing CVE feed does — so it is not grounds for refusing to
# answer. PACKAGES/VERSIONS report no status at all (see ScanStep).
SECURITY_STEPS: frozenset[ScanStep] = frozenset({ScanStep.VULNERABILITIES, ScanStep.EPSS})


def security_data_degraded(completeness: DataCompleteness) -> dict[ScanStep, DataSourceStatus]:
    """The security-relevant steps that did not come back ok."""
    return {step: status for step, status in completeness.degraded_steps.items() if step in SECURITY_STEPS}


def check_security_data_complete(
    completeness: DataCompleteness,
    strategy: UpdateStrategy,
    *,
    allow_partial: bool,
) -> None:
    """Refuse to present a minimal-diff verdict built on missing vulnerability data.

    Only the tiers that move a package *because of* a CVE are covered. Under `standard` and above,
    drift alone justifies an update, so a degraded OSV run produces a thinner answer rather than a
    silently empty one — and the stderr warning plus `data_completeness` already say so.

    Args:
        completeness: Per-step outcomes accumulated over the scan.
        strategy: The tier this run was asked for.
        allow_partial: The user's explicit acceptance of an incomplete answer.

    Raises:
        SecurityDataIncomplete: The run asked a security question its data cannot answer.
    """
    if allow_partial or strategy not in MINIMAL_DIFF_TIERS:
        return
    degraded = security_data_degraded(completeness)
    if not degraded:
        return
    detail = ", ".join(f"{step.value} {status.value}" for step, status in sorted(degraded.items()))
    raise SecurityDataIncomplete(
        f"--update-strategy {strategy.value} depends on vulnerability data that did not arrive ({detail}), "
        "so an empty result cannot be distinguished from a clean project."
    )
