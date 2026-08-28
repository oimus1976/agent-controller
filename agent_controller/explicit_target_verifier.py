from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional, Protocol, Sequence

from agent_controller.binding_validator import (
    BindingValidation,
    validate_observation_binding,
    validate_operation_binding,
)
from agent_controller.inspector import _github_api_request, evaluate_scope
from agent_controller.provider_contract import (
    AgentObservation,
    ControllerState,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
    VerificationResult,
    VerificationSource,
)


class ObservationReader(Protocol):
    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        ...


class GitHubTargetReadClient(Protocol):
    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        ...

    def compare_commits(self, repo: str, base_sha: str, head_sha: str) -> Mapping[str, Any]:
        ...


class LiveGitHubTargetReadClient:
    """Minimal read-only GitHub REST client for explicit target verification."""

    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        owner, name = _split_repo(repo)
        data = _github_api_request(
            f"https://api.github.com/repos/{owner}/{name}/commits/{ref}"
        )
        if not isinstance(data, Mapping):
            return None
        sha = data.get("sha")
        return sha if isinstance(sha, str) and sha else None

    def compare_commits(self, repo: str, base_sha: str, head_sha: str) -> Mapping[str, Any]:
        owner, name = _split_repo(repo)
        data = _github_api_request(
            f"https://api.github.com/repos/{owner}/{name}/compare/{base_sha}...{head_sha}"
        )
        if not isinstance(data, Mapping):
            raise RuntimeError("Malformed GitHub compare response")
        merge_base = data.get("merge_base_commit")
        merge_base_sha = merge_base.get("sha") if isinstance(merge_base, Mapping) else None
        return {
            "merge_base_sha": merge_base_sha,
            "files": data.get("files"),
        }


def _split_repo(repo: str) -> tuple[str, str]:
    parts = repo.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("repo must be OWNER/REPO")
    return parts[0], parts[1]


@dataclass(frozen=True)
class ExplicitTargetEvidence:
    repo: Optional[str]
    target_ref: Optional[str]
    resolved_sha: Optional[str]
    verification_source: VerificationSource
    verification_result: VerificationResult
    reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verification_source"] = self.verification_source.value
        data["verification_result"] = self.verification_result.value
        return data


@dataclass(frozen=True)
class ExplicitTargetVerificationResult:
    binding: BindingValidation
    observation: AgentObservation | None
    evidence: ExplicitTargetEvidence
    verification_result: VerificationResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": {"valid": self.binding.valid, "reason": self.binding.reason},
            "observation": self.observation.to_dict() if self.observation else None,
            "evidence": self.evidence.to_dict(),
            "verification_result": self.verification_result.value,
        }


def _evidence(
    *,
    task: TaskBinding,
    target_ref: Optional[str],
    resolved_sha: Optional[str],
    result: VerificationResult,
    reason: str,
) -> ExplicitTargetEvidence:
    return ExplicitTargetEvidence(
        repo=task.repo,
        target_ref=target_ref,
        resolved_sha=resolved_sha,
        verification_source=VerificationSource.GITHUB,
        verification_result=result,
        reason=reason,
    )


def _scope(task: TaskBinding) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    allowed = tuple(task.objective_scope.allowed_paths or ())
    denied = tuple(task.objective_scope.denied_paths or ())
    if not allowed and not denied:
        return None
    return allowed, denied


def run_explicit_target_verification(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    target_ref: str,
    observer: ObservationReader,
    github: GitHubTargetReadClient,
) -> ExplicitTargetVerificationResult:
    """Use provider terminal success only as a trigger for fresh GitHub verification.

    The target ref is Controller-owned input. No provider-reported artifact fields,
    prose, command output, or gitInfo are used as artifact authority.
    """

    operation_binding = validate_operation_binding(task=task, operation=operation)
    if not operation_binding.valid:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=None,
            result=VerificationResult.BLOCKED,
            reason=operation_binding.reason or "OPERATION_BINDING_INVALID",
        )
        return ExplicitTargetVerificationResult(
            operation_binding, None, evidence, VerificationResult.BLOCKED
        )

    if not task.repo or not task.expected_start_sha or not target_ref:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=None,
            result=VerificationResult.BLOCKED,
            reason="TARGET_BINDING_INCOMPLETE",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), None, evidence, VerificationResult.BLOCKED
        )

    scope = _scope(task)
    if scope is None:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=None,
            result=VerificationResult.BLOCKED,
            reason="OBJECTIVE_SCOPE_MISSING",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), None, evidence, VerificationResult.BLOCKED
        )

    observation = observer.observe(operation)
    observation_binding = validate_observation_binding(
        operation=operation,
        observation=observation,
    )
    if not observation_binding.valid:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=None,
            result=VerificationResult.BLOCKED,
            reason=observation_binding.reason or "OBSERVATION_BINDING_INVALID",
        )
        return ExplicitTargetVerificationResult(
            observation_binding, observation, evidence, VerificationResult.BLOCKED
        )

    if (
        observation.mapped_state is not ControllerState.ARTIFACT_READY
        or observation.terminal_claim is not TerminalClaim.SUCCESS
    ):
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=None,
            result=VerificationResult.BLOCKED,
            reason="PROVIDER_NOT_ARTIFACT_READY_SUCCESS",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.BLOCKED
        )

    try:
        resolved_sha = github.get_ref_sha(task.repo, target_ref)
    except Exception:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=None,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_TARGET_READ_UNAVAILABLE",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.UNCERTAIN
        )

    if not resolved_sha:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=None,
            result=VerificationResult.FAIL,
            reason="GITHUB_TARGET_MISSING",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.FAIL
        )

    if resolved_sha == task.expected_start_sha:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=resolved_sha,
            result=VerificationResult.FAIL,
            reason="TARGET_UNCHANGED_FROM_EXPECTED_START",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.FAIL
        )

    try:
        comparison = github.compare_commits(
            task.repo, task.expected_start_sha, resolved_sha
        )
    except Exception:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=resolved_sha,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_COMPARE_UNAVAILABLE",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.UNCERTAIN
        )

    if comparison.get("merge_base_sha") != task.expected_start_sha:
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=resolved_sha,
            result=VerificationResult.FAIL,
            reason="TARGET_NOT_DESCENDANT_OF_EXPECTED_START",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.FAIL
        )

    files = comparison.get("files")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes)):
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=resolved_sha,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_SCOPE_EVIDENCE_UNAVAILABLE",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.UNCERTAIN
        )

    allowed, denied = scope
    scope_result = evaluate_scope(
        files,
        {
            "allowed_paths": list(allowed),
            "denied_paths": list(denied),
            "allow_docs_only": True,
        },
    )
    if scope_result == "VIOLATION":
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=resolved_sha,
            result=VerificationResult.FAIL,
            reason="OBJECTIVE_SCOPE_VIOLATION",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.FAIL
        )
    if scope_result != "SATISFIED":
        evidence = _evidence(
            task=task,
            target_ref=target_ref,
            resolved_sha=resolved_sha,
            result=VerificationResult.UNCERTAIN,
            reason="OBJECTIVE_SCOPE_UNCERTAIN",
        )
        return ExplicitTargetVerificationResult(
            BindingValidation(True), observation, evidence, VerificationResult.UNCERTAIN
        )

    evidence = _evidence(
        task=task,
        target_ref=target_ref,
        resolved_sha=resolved_sha,
        result=VerificationResult.PASS,
        reason="GITHUB_TARGET_VERIFIED",
    )
    return ExplicitTargetVerificationResult(
        BindingValidation(True), observation, evidence, VerificationResult.PASS
    )
