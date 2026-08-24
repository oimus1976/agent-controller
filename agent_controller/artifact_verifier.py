from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable

from agent_controller.binding_validator import validate_evidence_chain
from agent_controller.inspector import evaluate_scope
from agent_controller.provider_contract import (
    ArtifactEvidence,
    ProviderOperationRef,
    TaskBinding,
    VerificationResult,
    VerificationSource,
)


@runtime_checkable
class GitHubArtifactReadClient(Protocol):
    """Minimal read-only GitHub facts required for code artifact verification."""

    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        ...

    def compare_commits(self, repo: str, base_sha: str, head_sha: str) -> Mapping[str, Any]:
        ...


@runtime_checkable
class GitHubPullRequestReadClient(Protocol):
    """Optional read-only GitHub facts required for PR artifact verification."""

    def get_pull_request(self, repo: str, pr_number: int) -> Mapping[str, Any]:
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


def _scope(task: TaskBinding):
    allowed_paths = tuple(task.objective_scope.allowed_paths or ())
    denied_paths = tuple(task.objective_scope.denied_paths or ())
    if not allowed_paths and not denied_paths:
        return None
    return allowed_paths, denied_paths


def _verify_sha_ancestry_and_scope(
    *,
    task: TaskBinding,
    evidence: ArtifactEvidence,
    resolved_sha: str,
    github: GitHubArtifactReadClient,
) -> ArtifactEvidence:
    if resolved_sha != evidence.provider_reported_sha:
        return _failed(evidence)

    if resolved_sha == task.expected_start_sha:
        return _failed(evidence)

    try:
        comparison = github.compare_commits(task.repo, task.expected_start_sha, resolved_sha)
    except Exception:
        return _uncertain(evidence)

    if comparison.get("merge_base_sha") != task.expected_start_sha:
        return _failed(evidence)

    files = comparison.get("files")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes)):
        return _uncertain(evidence)

    scope = _scope(task)
    if scope is None:
        return _blocked(evidence)
    allowed_paths, denied_paths = scope
    scope_result = evaluate_scope(
        files,
        {
            "allowed_paths": list(allowed_paths),
            "denied_paths": list(denied_paths),
            "allow_docs_only": True,
        },
    )
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


def _verify_pull_request_artifact(
    *,
    task: TaskBinding,
    evidence: ArtifactEvidence,
    github: GitHubArtifactReadClient,
) -> ArtifactEvidence:
    if not isinstance(github, GitHubPullRequestReadClient):
        return _blocked(evidence)
    if task.expected_start_ref is None:
        return _blocked(evidence)

    try:
        pr_number = int(evidence.provider_artifact_id or "")
    except ValueError:
        return _blocked(evidence)
    if pr_number <= 0:
        return _blocked(evidence)

    try:
        pr = github.get_pull_request(task.repo, pr_number)
    except Exception:
        return _uncertain(evidence)

    if pr.get("number") != pr_number:
        return _failed(evidence)
    if pr.get("state") != "open" or pr.get("merged") is not False:
        return _failed(evidence)

    base_repo = pr.get("base_repo")
    base_ref = pr.get("base_ref")
    base_sha = pr.get("base_sha")
    if not all(isinstance(value, str) and value for value in (base_repo, base_ref, base_sha)):
        return _uncertain(evidence)
    if base_repo != task.repo:
        return _failed(evidence)
    if base_ref != task.expected_start_ref:
        return _failed(evidence)
    if base_sha != task.expected_start_sha:
        return _failed(evidence)

    if pr.get("head_ref") != evidence.provider_reported_ref:
        return _failed(evidence)

    head_sha = pr.get("head_sha")
    if not isinstance(head_sha, str) or not head_sha:
        return _uncertain(evidence)

    return _verify_sha_ancestry_and_scope(
        task=task,
        evidence=evidence,
        resolved_sha=head_sha,
        github=github,
    )


def verify_github_artifact(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    evidence: ArtifactEvidence,
    github: GitHubArtifactReadClient,
) -> ArtifactEvidence:
    """Independently verify one provider-reported GitHub artifact.

    Binding is validated before any GitHub I/O. Provider identity never changes
    the rules. Mutable refs must be paired with provider-reported immutable SHA.
    PR artifacts additionally require objective PR identity, base/head target,
    state, ancestry, and changed-file scope facts.
    """

    binding = validate_evidence_chain(task=task, operation=operation, artifact=evidence)
    if not binding.valid:
        return _blocked(evidence)

    if task.repo is None or task.expected_start_sha is None:
        return _blocked(evidence)
    if evidence.provider_reported_ref is None or evidence.provider_reported_sha is None:
        return _blocked(evidence)
    if _scope(task) is None:
        return _blocked(evidence)

    if evidence.artifact_kind.lower() in {"pull_request", "pr"}:
        return _verify_pull_request_artifact(task=task, evidence=evidence, github=github)

    try:
        resolved_sha = github.get_ref_sha(task.repo, evidence.provider_reported_ref)
    except Exception:
        return _uncertain(evidence)
    if resolved_sha is None:
        return _failed(evidence)

    return _verify_sha_ancestry_and_scope(
        task=task,
        evidence=evidence,
        resolved_sha=resolved_sha,
        github=github,
    )
