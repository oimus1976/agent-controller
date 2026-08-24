from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable

from agent_controller.inspector import evaluate_scope
from agent_controller.provider_contract import (
    ArtifactEvidence,
    TaskBinding,
    VerificationResult,
    VerificationSource,
)


@runtime_checkable
class GitHubArtifactReadClient(Protocol):
    """Minimal read-only GitHub facts required for artifact verification.

    Network/API implementation is intentionally outside PN1. Tests inject
    deterministic facts; future adapters may wrap existing GitHub primitives.
    """

    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        ...

    def compare_commits(self, repo: str, base_sha: str, head_sha: str) -> Mapping[str, Any]:
        ...


def _blocked(evidence: ArtifactEvidence) -> ArtifactEvidence:
    return replace(
        evidence,
        independently_verified=False,
        verification_source=VerificationSource.GITHUB,
        verified_repo=None,
        verified_ref=None,
        verified_sha=None,
        verification_result=VerificationResult.BLOCKED,
    )


def _failed(evidence: ArtifactEvidence) -> ArtifactEvidence:
    return replace(
        evidence,
        independently_verified=False,
        verification_source=VerificationSource.GITHUB,
        verified_repo=None,
        verified_ref=None,
        verified_sha=None,
        verification_result=VerificationResult.FAIL,
    )


def _uncertain(evidence: ArtifactEvidence) -> ArtifactEvidence:
    return replace(
        evidence,
        independently_verified=False,
        verification_source=VerificationSource.GITHUB,
        verified_repo=None,
        verified_ref=None,
        verified_sha=None,
        verification_result=VerificationResult.UNCERTAIN,
    )


def verify_github_artifact(
    *,
    task: TaskBinding,
    evidence: ArtifactEvidence,
    github: GitHubArtifactReadClient,
) -> ArtifactEvidence:
    """Independently verify one provider-reported GitHub artifact.

    Provider identity never changes the verification rules. Provider-reported
    ref/SHA remain claims until GitHub resolves the ref and comparison facts
    prove freshness, ancestry, and scope.
    """

    if task.repo is None or task.expected_start_sha is None:
        return _blocked(evidence)

    if evidence.provider_reported_ref is None:
        return _blocked(evidence)

    try:
        resolved_sha = github.get_ref_sha(task.repo, evidence.provider_reported_ref)
    except Exception:
        return _uncertain(evidence)

    if resolved_sha is None:
        return _failed(evidence)

    if evidence.provider_reported_sha is not None and resolved_sha != evidence.provider_reported_sha:
        return _failed(evidence)

    # Freshness: unchanged publication cannot satisfy a code-artifact handoff.
    if resolved_sha == task.expected_start_sha:
        return _failed(evidence)

    try:
        comparison = github.compare_commits(task.repo, task.expected_start_sha, resolved_sha)
    except Exception:
        return _uncertain(evidence)

    merge_base_sha = comparison.get("merge_base_sha")
    if merge_base_sha != task.expected_start_sha:
        return _failed(evidence)

    files = comparison.get("files")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes)):
        return _uncertain(evidence)

    scope_policy = {
        "allowed_paths": list(task.objective_scope.allowed_paths or ()),
        "denied_paths": list(task.objective_scope.denied_paths or ()),
        # Artifact verification is not a docs-only classifier. Permit docs-only
        # changes when they are otherwise inside the explicit path scope.
        "allow_docs_only": True,
    }
    scope_result = evaluate_scope(files, scope_policy)
    if scope_result == "VIOLATION":
        return _failed(evidence)
    if scope_result != "SATISFIED":
        return _uncertain(evidence)

    return replace(
        evidence,
        independently_verified=True,
        verification_source=VerificationSource.GITHUB,
        verified_repo=task.repo,
        verified_ref=evidence.provider_reported_ref,
        verified_sha=resolved_sha,
        verification_result=VerificationResult.PASS,
    )
