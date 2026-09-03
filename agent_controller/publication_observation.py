from __future__ import annotations

from typing import Optional, Protocol

from agent_controller.provider_contract import (
    PublicationClassification,
    PublicationStateEvidence,
)


class TargetReadClient(Protocol):
    def get_ref_sha(self, repo: str, ref: str) -> str | None:
        ...


class PublicationObservationError(RuntimeError):
    """Explicit fail-closed result for an authoritative GitHub read failure."""

    classification = PublicationClassification.PUBLICATION_AMBIGUOUS


def observe_publication_state(
    *,
    provider: str,
    operation_id: str,
    repo: str,
    bound_branch: str,
    authoritative_baseline_bound_sha: str,
    provider_reported_completion: bool,
    provider_reported_branch: Optional[str],
    target_client: TargetReadClient,
) -> PublicationStateEvidence:
    """
    Independently observes the target repository and constructs
    PublicationStateEvidence.

    Raises PublicationObservationError for authoritative read uncertainty
    (for example auth, transport, malformed responses, or a missing bound branch).
    The error explicitly carries PUBLICATION_AMBIGUOUS fail-closed semantics.
    """
    try:
        current_bound_sha = target_client.get_ref_sha(repo, bound_branch)
    except Exception as exc:
        raise PublicationObservationError("bound branch GitHub read failed") from exc

    if current_bound_sha is None:
        raise PublicationObservationError("bound branch is absent on GitHub")

    independently_observed_provider_sha = None

    if provider_reported_branch is not None and provider_reported_branch != bound_branch:
        try:
            independently_observed_provider_sha = target_client.get_ref_sha(
                repo, provider_reported_branch
            )
        except Exception as exc:
            raise PublicationObservationError(
                "provider branch GitHub read failed"
            ) from exc

        # None here means the exact distinct provider-reported branch is
        # definitively absent; it is not authoritative publication evidence.

    return PublicationStateEvidence(
        provider=provider,
        operation_id=operation_id,
        repo=repo,
        bound_branch=bound_branch,
        authoritative_baseline_bound_sha=authoritative_baseline_bound_sha,
        authoritative_current_bound_sha=current_bound_sha,
        provider_reported_completion=provider_reported_completion,
        provider_reported_branch=provider_reported_branch,
        independently_observed_provider_sha=independently_observed_provider_sha,
    )
