from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Sequence, runtime_checkable


class ControllerState(str, Enum):
    """Small provider-neutral state subset required by the PN1 proof slice."""

    PLANNING = "PLANNING"
    PLAN_REVIEW_REQUIRED = "PLAN_REVIEW_REQUIRED"
    EXECUTING = "EXECUTING"
    ARTIFACT_READY = "ARTIFACT_READY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REVIEW_READY = "REVIEW_READY"
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"


class AwaitingInput(str, Enum):
    NONE = "NONE"
    PLAN_APPROVAL = "PLAN_APPROVAL"
    USER_FEEDBACK = "USER_FEEDBACK"
    OTHER = "OTHER"


class TerminalClaim(str, Enum):
    NONE = "NONE"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class VerificationResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"
    NOT_RUN = "NOT_RUN"


class VerificationSource(str, Enum):
    GITHUB = "GITHUB"
    CI = "CI"
    LOCAL_DETERMINISTIC = "LOCAL_DETERMINISTIC"
    NONE = "NONE"


@dataclass(frozen=True)
class ObjectiveScope:
    allowed_paths: Optional[Sequence[str]] = None
    denied_paths: Optional[Sequence[str]] = None


@dataclass(frozen=True)
class TaskBinding:
    controller_task_id: str
    operation_id: str
    provider: str
    repo: Optional[str]
    expected_start_ref: Optional[str]
    expected_start_sha: Optional[str]
    objective_scope: ObjectiveScope
    requested_capability: str
    allowed_effects: Sequence[str]
    forbidden_effects: Sequence[str]
    approval_policy_id: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProviderOperationRef:
    provider: str
    provider_operation_id: str
    provider_url: Optional[str]
    controller_task_id: str
    operation_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AgentObservation:
    provider: str
    provider_operation_id: str
    observed_at: str
    provider_updated_at: Optional[str]
    provider_raw_state: Any
    mapped_state: ControllerState
    awaiting_input: AwaitingInput = AwaitingInput.NONE
    terminal_claim: TerminalClaim = TerminalClaim.NONE
    reported_effects: Sequence[str] = field(default_factory=tuple)
    provider_refs: Sequence[str] = field(default_factory=tuple)
    uncertainty_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["mapped_state"] = self.mapped_state.value
        data["awaiting_input"] = self.awaiting_input.value
        data["terminal_claim"] = self.terminal_claim.value
        return data


@dataclass(frozen=True)
class ArtifactEvidence:
    provider: str
    provider_operation_id: str
    artifact_kind: str
    provider_artifact_id: Optional[str]
    provider_reported_ref: Optional[str]
    provider_reported_sha: Optional[str]
    content_hash: Optional[str]
    observed_at: str
    freshness_basis: str
    independently_verified: bool = False
    verification_source: VerificationSource = VerificationSource.NONE
    verified_repo: Optional[str] = None
    verified_ref: Optional[str] = None
    verified_sha: Optional[str] = None
    verification_result: VerificationResult = VerificationResult.NOT_RUN
    replay_of_artifact_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["verification_source"] = self.verification_source.value
        data["verification_result"] = self.verification_result.value
        return data


@runtime_checkable
class AgentAdapter(Protocol):
    """Minimum provider-neutral adapter contract.

    Provider-specific lifecycle operations remain outside this protocol unless
    exposed separately as optional capabilities.
    """

    @property
    def capabilities(self) -> Sequence[str]:
        ...

    def dispatch(self, task: TaskBinding) -> ProviderOperationRef:
        ...

    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        ...

    def collect_artifacts(self, operation: ProviderOperationRef) -> List[ArtifactEvidence]:
        ...
