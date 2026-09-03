from __future__ import annotations

from typing import Optional, Protocol

from agent_controller.provider_contract import PublicationStateEvidence


class TargetReadClient(Protocol):
    def get_ref_sha(self, repo: str, ref: str) -> str | None:
        ...


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
) -> Optional[PublicationStateEvidence]:
    """
    Independently observes the target repository and constructs
    PublicationStateEvidence.

    Returns None if an unexpected error occurs during observation
    (e.g., auth, transport, or malformed responses).
    """
    try:
        current_bound_sha = target_client.get_ref_sha(repo, bound_branch)
    except Exception:
        # Any bound-branch read failure is fail-closed/ambiguous.
        return None

    if current_bound_sha is None:
        # Bound branch must exist (since it has a baseline).
        return None

    independently_observed_provider_sha = None

    if provider_reported_branch is not None and provider_reported_branch != bound_branch:
        try:
            independently_observed_provider_sha = target_client.get_ref_sha(repo, provider_reported_branch)
        except Exception:
            # Any provider-branch transport/auth/malformed-response failure is fail-closed/ambiguous, never equivalent to absence.
            return None
        
        # If get_ref_sha returns None, we keep independently_observed_provider_sha as None to signify definite absence.

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
