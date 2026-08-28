from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence

from agent_controller.binding_validator import (
    BindingValidation,
    validate_observation_binding,
    validate_operation_binding,
)
from agent_controller.inspector import evaluate_scope
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
    """Read-only GitHub facts for one Controller-specified branch target."""

    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        ...

    def compare_commits(self, repo: str, base_sha: str, head_sha: str) -> Mapping[str, Any]:
        ...


ObservedAtFactory = Callable[[], str]


@dataclass(frozen=True)
class GitHubTargetExpectation:
    """Controller-owned target identity, never a provider artifact claim."""

    repo: str
    ref: str


@dataclass(frozen=True)
class ObjectiveGitHubTargetEvidence:
    repo: str
    target_ref: str
    resolved_sha: Optional[str]
    github_observed_at: Optional[str]
    verification_source: VerificationSource
    verification_result: VerificationResult
    reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "target_ref": self.target_ref,
            "resolved_sha": self.resolved_sha,
            "github_observed_at": self.github_observed_at,
            "verification_source": self.verification_source.value,
            "verification_result": self.verification_result.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ObjectiveTargetHandoffResult:
    binding: BindingValidation
    observation: AgentObservation | None
    target_evidence: ObjectiveGitHubTargetEvidence

    @property
    def verification_result(self) -> VerificationResult:
        return self.target_evidence.verification_result

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding": {
                "valid": self.binding.valid,
                "reason": self.binding.reason,
            },
            "observation": self.observation.to_dict() if self.observation is not None else None,
            "target_evidence": self.target_evidence.to_dict(),
            "verification_result": self.verification_result.value,
        }


def _evidence(
    *,
    target: GitHubTargetExpectation,
    result: VerificationResult,
    reason: str,
    resolved_sha: str | None = None,
    github_observed_at: str | None = None,
) -> ObjectiveGitHubTargetEvidence:
    return ObjectiveGitHubTargetEvidence(
        repo=target.repo,
        target_ref=target.ref,
        resolved_sha=resolved_sha,
        github_observed_at=github_observed_at,
        verification_source=VerificationSource.GITHUB,
        verification_result=result,
        reason=reason,
    )


def _target_binding(task: TaskBinding, target: GitHubTargetExpectation) -> BindingValidation:
    if not isinstance(task.repo, str) or not task.repo:
        return BindingValidation(False, "TASK_REPO_MISSING")
    if target.repo != task.repo:
        return BindingValidation(False, "TARGET_REPO_MISMATCH")
    if not isinstance(target.ref, str) or not target.ref:
        return BindingValidation(False, "TARGET_REF_MISSING")
    if not isinstance(task.expected_start_sha, str) or not task.expected_start_sha:
        return BindingValidation(False, "EXPECTED_START_SHA_MISSING")
    allowed_paths = tuple(task.objective_scope.allowed_paths or ())
    denied_paths = tuple(task.objective_scope.denied_paths or ())
    if not allowed_paths and not denied_paths:
        return BindingValidation(False, "OBJECTIVE_SCOPE_MISSING")
    return BindingValidation(True)


def verify_explicit_github_target(
    *,
    task: TaskBinding,
    target: GitHubTargetExpectation,
    github: GitHubTargetReadClient,
    github_observed_at: str,
) -> ObjectiveGitHubTargetEvidence:
    """Verify a Controller-owned GitHub branch target using GitHub-owned facts.

    This deliberately does not create ArtifactEvidence: the target ref was not
    reported by the provider, so representing it as provider_reported_ref/sha
    would erase the authority distinction this path exists to preserve.
    """

    binding = _target_binding(task, target)
    if not binding.valid:
        return _evidence(
            target=target,
            result=VerificationResult.BLOCKED,
            reason=binding.reason or "TARGET_BINDING_INVALID",
        )
    if not isinstance(github_observed_at, str) or not github_observed_at:
        return _evidence(
            target=target,
            result=VerificationResult.BLOCKED,
            reason="GITHUB_OBSERVED_AT_MISSING",
        )

    try:
        resolved_sha = github.get_ref_sha(target.repo, target.ref)
    except Exception:
        return _evidence(
            target=target,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_REF_READ_UNAVAILABLE",
            github_observed_at=github_observed_at,
        )

    if resolved_sha is None:
        return _evidence(
            target=target,
            result=VerificationResult.FAIL,
            reason="TARGET_REF_NOT_FOUND",
            github_observed_at=github_observed_at,
        )
    if not isinstance(resolved_sha, str) or not resolved_sha:
        return _evidence(
            target=target,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_REF_RESPONSE_MALFORMED",
            github_observed_at=github_observed_at,
        )
    if resolved_sha == task.expected_start_sha:
        return _evidence(
            target=target,
            result=VerificationResult.FAIL,
            reason="TARGET_UNCHANGED_FROM_START",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )

    try:
        comparison = github.compare_commits(target.repo, task.expected_start_sha, resolved_sha)
    except Exception:
        return _evidence(
            target=target,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_COMPARE_UNAVAILABLE",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )

    if not isinstance(comparison, Mapping):
        return _evidence(
            target=target,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_COMPARE_MALFORMED",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )

    merge_base_sha = comparison.get("merge_base_sha")
    if not isinstance(merge_base_sha, str) or not merge_base_sha:
        return _evidence(
            target=target,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_MERGE_BASE_MALFORMED",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )
    if merge_base_sha != task.expected_start_sha:
        return _evidence(
            target=target,
            result=VerificationResult.FAIL,
            reason="TARGET_DIVERGED_FROM_EXPECTED_START",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )

    files = comparison.get("files")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes)):
        return _evidence(
            target=target,
            result=VerificationResult.UNCERTAIN,
            reason="GITHUB_CHANGED_FILES_MALFORMED",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )

    scope_result = evaluate_scope(
        files,
        {
            "allowed_paths": list(task.objective_scope.allowed_paths or ()),
            "denied_paths": list(task.objective_scope.denied_paths or ()),
            "allow_docs_only": True,
        },
    )
    if scope_result == "VIOLATION":
        return _evidence(
            target=target,
            result=VerificationResult.FAIL,
            reason="OBJECTIVE_SCOPE_VIOLATION",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )
    if scope_result != "SATISFIED":
        return _evidence(
            target=target,
            result=VerificationResult.UNCERTAIN,
            reason="OBJECTIVE_SCOPE_UNCERTAIN",
            resolved_sha=resolved_sha,
            github_observed_at=github_observed_at,
        )

    return _evidence(
        target=target,
        result=VerificationResult.PASS,
        reason="GITHUB_TARGET_VERIFIED",
        resolved_sha=resolved_sha,
        github_observed_at=github_observed_at,
    )


def run_objective_target_handoff(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    observer: ObservationReader,
    target: GitHubTargetExpectation,
    github: GitHubTargetReadClient,
    github_observed_at: ObservedAtFactory,
) -> ObjectiveTargetHandoffResult:
    """Use provider completion only as a trigger for objective GitHub verification."""

    operation_binding = validate_operation_binding(task=task, operation=operation)
    if not operation_binding.valid:
        return ObjectiveTargetHandoffResult(
            binding=operation_binding,
            observation=None,
            target_evidence=_evidence(
                target=target,
                result=VerificationResult.BLOCKED,
                reason=operation_binding.reason or "OPERATION_BINDING_INVALID",
            ),
        )

    target_binding = _target_binding(task, target)
    if not target_binding.valid:
        return ObjectiveTargetHandoffResult(
            binding=target_binding,
            observation=None,
            target_evidence=_evidence(
                target=target,
                result=VerificationResult.BLOCKED,
                reason=target_binding.reason or "TARGET_BINDING_INVALID",
            ),
        )

    try:
        observation = observer.observe(operation)
    except Exception:
        return ObjectiveTargetHandoffResult(
            binding=BindingValidation(True),
            observation=None,
            target_evidence=_evidence(
                target=target,
                result=VerificationResult.UNCERTAIN,
                reason="PROVIDER_OBSERVATION_UNAVAILABLE",
            ),
        )

    if not isinstance(observation, AgentObservation):
        return ObjectiveTargetHandoffResult(
            binding=BindingValidation(True),
            observation=None,
            target_evidence=_evidence(
                target=target,
                result=VerificationResult.UNCERTAIN,
                reason="PROVIDER_OBSERVATION_MALFORMED",
            ),
        )

    observation_binding = validate_observation_binding(
        operation=operation,
        observation=observation,
    )
    if not observation_binding.valid:
        return ObjectiveTargetHandoffResult(
            binding=observation_binding,
            observation=observation,
            target_evidence=_evidence(
                target=target,
                result=VerificationResult.BLOCKED,
                reason=observation_binding.reason or "OBSERVATION_BINDING_INVALID",
            ),
        )

    if (
        observation.mapped_state is not ControllerState.ARTIFACT_READY
        or observation.terminal_claim is not TerminalClaim.SUCCESS
    ):
        return ObjectiveTargetHandoffResult(
            binding=BindingValidation(True),
            observation=observation,
            target_evidence=_evidence(
                target=target,
                result=VerificationResult.BLOCKED,
                reason="OBSERVATION_NOT_ARTIFACT_READY_SUCCESS",
            ),
        )

    try:
        observed_at = github_observed_at()
    except Exception:
        return ObjectiveTargetHandoffResult(
            binding=BindingValidation(True),
            observation=observation,
            target_evidence=_evidence(
                target=target,
                result=VerificationResult.UNCERTAIN,
                reason="GITHUB_OBSERVED_AT_UNAVAILABLE",
            ),
        )

    return ObjectiveTargetHandoffResult(
        binding=BindingValidation(True),
        observation=observation,
        target_evidence=verify_explicit_github_target(
            task=task,
            target=target,
            github=github,
            github_observed_at=observed_at,
        ),
    )
