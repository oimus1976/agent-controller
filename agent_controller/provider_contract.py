from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from enum import Enum
import re
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, runtime_checkable


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


class PublicationClassification(str, Enum):
    WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN = "WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN"
    BOUND_BRANCH_ADVANCED = "BOUND_BRANCH_ADVANCED"
    NEW_PROVIDER_BRANCH_EXPOSED = "NEW_PROVIDER_BRANCH_EXPOSED"
    PUBLICATION_AMBIGUOUS = "PUBLICATION_AMBIGUOUS"


def _is_valid_sha(sha: Optional[str]) -> bool:
    if not isinstance(sha, str):
        return False
    return bool(re.fullmatch(r"[0-9a-f]{40}", sha))

def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_deep_freeze(item) for item in value)
    return deepcopy(value)


def _to_plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _to_plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_to_plain(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(_to_plain(item) for item in value)
    return value


@dataclass(frozen=True)
class ObjectiveScope:
    allowed_paths: Optional[Sequence[str]] = None
    denied_paths: Optional[Sequence[str]] = None

    def __post_init__(self):
        if self.allowed_paths is not None:
            object.__setattr__(self, "allowed_paths", tuple(self.allowed_paths))
        if self.denied_paths is not None:
            object.__setattr__(self, "denied_paths", tuple(self.denied_paths))


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

    def __post_init__(self):
        object.__setattr__(self, "allowed_effects", tuple(self.allowed_effects))
        object.__setattr__(self, "forbidden_effects", tuple(self.forbidden_effects))

    def to_dict(self) -> Dict[str, Any]:
        return _to_plain(asdict(self))


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

    def __post_init__(self):
        object.__setattr__(self, "provider_raw_state", _deep_freeze(self.provider_raw_state))
        object.__setattr__(self, "reported_effects", tuple(self.reported_effects))
        object.__setattr__(self, "provider_refs", tuple(self.provider_refs))

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "provider": self.provider,
            "provider_operation_id": self.provider_operation_id,
            "observed_at": self.observed_at,
            "provider_updated_at": self.provider_updated_at,
            "provider_raw_state": _to_plain(self.provider_raw_state),
            "mapped_state": self.mapped_state.value,
            "awaiting_input": self.awaiting_input.value,
            "terminal_claim": self.terminal_claim.value,
            "reported_effects": list(self.reported_effects),
            "provider_refs": list(self.provider_refs),
            "uncertainty_reason": self.uncertainty_reason,
        }
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


@dataclass(frozen=True)
class PublicationStateEvidence:
    provider: str
    operation_id: str
    repo: str
    bound_branch: str
    authoritative_baseline_bound_sha: str
    authoritative_current_bound_sha: str
    provider_reported_completion: bool = False
    provider_reported_branch: Optional[str] = None
    independently_observed_provider_sha: Optional[str] = None

    def classify(self) -> PublicationClassification:
        if not _is_valid_sha(self.authoritative_baseline_bound_sha):
            return PublicationClassification.PUBLICATION_AMBIGUOUS
        if not _is_valid_sha(self.authoritative_current_bound_sha):
            return PublicationClassification.PUBLICATION_AMBIGUOUS
        if self.independently_observed_provider_sha is not None:
            if not _is_valid_sha(self.independently_observed_provider_sha):
                return PublicationClassification.PUBLICATION_AMBIGUOUS

        if self.authoritative_current_bound_sha != self.authoritative_baseline_bound_sha:
            return PublicationClassification.BOUND_BRANCH_ADVANCED

        if self.independently_observed_provider_sha is not None:
            if self.provider_reported_branch == self.bound_branch:
                return PublicationClassification.PUBLICATION_AMBIGUOUS
            return PublicationClassification.NEW_PROVIDER_BRANCH_EXPOSED

        if self.provider_reported_completion:
            return PublicationClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN

        return PublicationClassification.PUBLICATION_AMBIGUOUS

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@runtime_checkable
class AgentAdapter(Protocol):
    """Minimum provider-neutral adapter contract.

    Provider-specific lifecycle operations and capability discovery remain
    outside this protocol unless exposed separately as optional capabilities.
    """

    def dispatch(self, task: TaskBinding) -> ProviderOperationRef:
        ...

    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        ...

    def collect_artifacts(self, operation: ProviderOperationRef) -> List[ArtifactEvidence]:
        ...
