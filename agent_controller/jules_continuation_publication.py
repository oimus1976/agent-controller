from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from agent_controller.provider_contract import PublicationClassification
from agent_controller.publication_observation import (
    TargetReadClient,
    PublicationObservationError,
    observe_publication_state,
)


@dataclass(frozen=True)
class JulesContinuationResult:
    classification: PublicationClassification
    guidance: str
    baseline_bound_sha: Optional[str] = None
    current_bound_sha: Optional[str] = None
    provider_reported_branch: Optional[str] = None
    independently_observed_provider_sha: Optional[str] = None


def observe_jules_continuation_publication(
    *,
    provider: str,
    operation_id: str,
    repo: str,
    bound_branch: str,
    authoritative_baseline_bound_sha: str,
    provider_reported_completion: bool,
    provider_reported_branch: Optional[str],
    target_client: TargetReadClient,
) -> JulesContinuationResult:
    try:
        evidence = observe_publication_state(
            provider=provider,
            operation_id=operation_id,
            repo=repo,
            bound_branch=bound_branch,
            authoritative_baseline_bound_sha=authoritative_baseline_bound_sha,
            provider_reported_completion=provider_reported_completion,
            provider_reported_branch=provider_reported_branch,
            target_client=target_client,
        )
    except PublicationObservationError:
        return JulesContinuationResult(
            classification=PublicationClassification.PUBLICATION_AMBIGUOUS,
            guidance="attention required; publication ambiguous; no publication or retry recommendation.",
        )

    classification = evidence.classify()

    if classification == PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN:
        guidance = "attention required; provider workspace completion may be known, but GitHub publication is not established; no mutation/retry recommendation."
        return JulesContinuationResult(classification=classification, guidance=guidance)

    if classification == PublicationClassification.BOUND_BRANCH_ADVANCED:
        guidance = "attention required; mark current head as new untrusted evidence requiring objective scope, exact-head CI, and independent review from scratch."
        return JulesContinuationResult(
            classification=classification,
            guidance=guidance,
            baseline_bound_sha=evidence.authoritative_baseline_bound_sha,
            current_bound_sha=evidence.authoritative_current_bound_sha,
        )

    if classification == PublicationClassification.NEW_PROVIDER_BRANCH_EXPOSED:
        guidance = "attention required; new provider branch exposed; it is not the Controller-bound PR branch; no branch/PR mutation."
        return JulesContinuationResult(
            classification=classification,
            guidance=guidance,
            provider_reported_branch=evidence.provider_reported_branch,
            independently_observed_provider_sha=evidence.independently_observed_provider_sha,
        )

    return JulesContinuationResult(
        classification=PublicationClassification.PUBLICATION_AMBIGUOUS,
        guidance="attention required; publication ambiguous; no publication or retry recommendation.",
        baseline_bound_sha=evidence.authoritative_baseline_bound_sha,
        current_bound_sha=evidence.authoritative_current_bound_sha,
        provider_reported_branch=evidence.provider_reported_branch,
        independently_observed_provider_sha=evidence.independently_observed_provider_sha,
    )
