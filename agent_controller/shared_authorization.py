from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Mapping, Optional, Protocol, runtime_checkable


CONTROLLER_STATE_REF = "controller-state"
SCHEMA_VERSION = "agent-controller-shared-authorization-v1"


class AuthorizationState(str, Enum):
    PROPOSED = "PROPOSED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    EXECUTION_CLAIMED = "EXECUTION_CLAIMED"
    EFFECT_STARTED = "EFFECT_STARTED"
    EFFECT_VERIFIED = "EFFECT_VERIFIED"
    STALE = "STALE"
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"
    FAILED_AFTER_CLAIM = "FAILED_AFTER_CLAIM"


class AuthorizationDecision(str, Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    STALE = "STALE"
    REPLAYED = "REPLAYED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class OperationAuthorizationBinding:
    approval_id: str
    approval_policy_id: str
    controller_task_id: str
    operation_id: str
    operation_version: str
    provider: Optional[str]
    requested_capability: str
    effect: str
    repo: Optional[str]
    target_kind: str
    target_id: Optional[str]
    expected_head_sha: Optional[str]


@dataclass(frozen=True)
class AuthorizationProvenance:
    assurance: str
    provenance_kind: str
    signer_key_id: str
    challenge_nonce: str
    challenge_digest: str
    signature_digest: str


@dataclass(frozen=True)
class SharedAuthorizationRecord:
    binding: OperationAuthorizationBinding
    state: AuthorizationState
    provenance: Optional[AuthorizationProvenance] = None
    execution_claim_id: Optional[str] = None
    controller_run_id: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = self.state.value
        return data


@dataclass(frozen=True)
class SharedRecordSnapshot:
    record: SharedAuthorizationRecord
    revision: str


@dataclass(frozen=True)
class BackendWriteResult:
    written: bool
    conflict: bool = False
    uncertain: bool = False
    revision: Optional[str] = None


@dataclass(frozen=True)
class SharedAuthorizationResult:
    decision: AuthorizationDecision
    snapshot: Optional[SharedRecordSnapshot] = None
    reason: Optional[str] = None


@runtime_checkable
class SharedAuthorizationBackend(Protocol):
    def read(self, *, state_ref: str, path: str) -> Optional[SharedRecordSnapshot]: ...
    def create_if_absent(
        self, *, state_ref: str, path: str, record: SharedAuthorizationRecord
    ) -> BackendWriteResult: ...
    def compare_and_swap(
        self,
        *,
        state_ref: str,
        path: str,
        expected_revision: str,
        record: SharedAuthorizationRecord,
    ) -> BackendWriteResult: ...


@dataclass(frozen=True)
class SharedAuthorizationStore:
    backend: SharedAuthorizationBackend
    state_ref: str = CONTROLLER_STATE_REF

    def __post_init__(self) -> None:
        if self.state_ref != CONTROLLER_STATE_REF:
            raise ValueError("shared authorization state ref is fixed by Controller composition")
        if not isinstance(self.backend, SharedAuthorizationBackend):
            raise TypeError("backend must satisfy SharedAuthorizationBackend")


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _valid_binding(binding: OperationAuthorizationBinding) -> bool:
    if not isinstance(binding, OperationAuthorizationBinding):
        return False
    required = (
        binding.approval_id,
        binding.approval_policy_id,
        binding.controller_task_id,
        binding.operation_id,
        binding.operation_version,
        binding.requested_capability,
        binding.effect,
        binding.target_kind,
    )
    if not all(_nonempty(value) for value in required):
        return False
    for optional in (binding.provider, binding.repo, binding.target_id, binding.expected_head_sha):
        if optional is not None and not isinstance(optional, str):
            return False
    return True


def _valid_provenance(provenance: AuthorizationProvenance) -> bool:
    if not isinstance(provenance, AuthorizationProvenance):
        return False
    fields = (
        provenance.assurance,
        provenance.provenance_kind,
        provenance.signer_key_id,
        provenance.challenge_nonce,
        provenance.challenge_digest,
        provenance.signature_digest,
    )
    return all(_nonempty(value) for value in fields)


def operation_state_path(binding: OperationAuthorizationBinding) -> str:
    if not _valid_binding(binding):
        raise ValueError("invalid operation authorization binding")
    for value in (binding.controller_task_id, binding.operation_id, binding.operation_version):
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("unsafe operation state path component")
    return (
        f"controller-state/operations/{binding.controller_task_id}/"
        f"{binding.operation_id}/{binding.operation_version}.json"
    )


def propose_operation(
    *, store: SharedAuthorizationStore, binding: OperationAuthorizationBinding
) -> SharedAuthorizationResult:
    try:
        path = operation_state_path(binding)
    except (TypeError, ValueError) as exc:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason=str(exc))

    record = SharedAuthorizationRecord(binding=binding, state=AuthorizationState.PROPOSED)
    try:
        write = store.backend.create_if_absent(
            state_ref=store.state_ref, path=path, record=record
        )
    except Exception:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CREATE_UNCERTAIN")

    if write.written:
        if not _nonempty(write.revision):
            return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_REVISION_MISSING")
        return SharedAuthorizationResult(
            AuthorizationDecision.PASS, SharedRecordSnapshot(record, write.revision)
        )
    if write.uncertain:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CREATE_UNCERTAIN")

    try:
        existing = store.backend.read(state_ref=store.state_ref, path=path)
    except Exception:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_REREAD_UNCERTAIN")
    if existing is None:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CREATE_CONFLICT_WITHOUT_RECORD")
    if existing.record.binding != binding:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, existing, "OPERATION_BINDING_CONFLICT")
    return SharedAuthorizationResult(AuthorizationDecision.REPLAYED, existing, "OPERATION_ALREADY_PROPOSED")


def approve_proposed_operation(
    *,
    store: SharedAuthorizationStore,
    binding: OperationAuthorizationBinding,
    provenance: AuthorizationProvenance,
) -> SharedAuthorizationResult:
    if not _valid_binding(binding) or not _valid_provenance(provenance):
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason="AUTHORIZATION_INPUT_INVALID")
    if provenance.assurance != "VERIFIED_EVENT_PROVENANCE":
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason="ASSURANCE_NOT_VERIFIED")
    if provenance.provenance_kind != "SIGNED_CHALLENGE":
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason="PROVENANCE_KIND_INVALID")

    try:
        path = operation_state_path(binding)
        current = store.backend.read(state_ref=store.state_ref, path=path)
    except Exception:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_READ_UNCERTAIN")
    if current is None:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason="PROPOSED_STATE_MISSING")
    if current.record.binding != binding:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, current, "OPERATION_BINDING_CONFLICT")

    if current.record.state is AuthorizationState.HUMAN_APPROVED:
        if current.record.provenance == provenance:
            return SharedAuthorizationResult(AuthorizationDecision.REPLAYED, current, "APPROVAL_ALREADY_RECORDED")
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, current, "APPROVAL_PROVENANCE_CONFLICT")
    if current.record.state is not AuthorizationState.PROPOSED:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, current, "ILLEGAL_PRIOR_STATE")

    approved = replace(current.record, state=AuthorizationState.HUMAN_APPROVED, provenance=provenance)
    try:
        write = store.backend.compare_and_swap(
            state_ref=store.state_ref,
            path=path,
            expected_revision=current.revision,
            record=approved,
        )
    except Exception:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CAS_UNCERTAIN")

    if write.written:
        if not _nonempty(write.revision):
            return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_REVISION_MISSING")
        return SharedAuthorizationResult(
            AuthorizationDecision.PASS, SharedRecordSnapshot(approved, write.revision)
        )
    if write.uncertain:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CAS_UNCERTAIN")

    try:
        winner = store.backend.read(state_ref=store.state_ref, path=path)
    except Exception:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_REREAD_UNCERTAIN")
    if winner is None:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CAS_CONFLICT_WITHOUT_RECORD")
    if winner.record.binding != binding:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, winner, "OPERATION_BINDING_CONFLICT")
    if winner.record.state is AuthorizationState.HUMAN_APPROVED and winner.record.provenance == provenance:
        return SharedAuthorizationResult(AuthorizationDecision.REPLAYED, winner, "APPROVAL_RACE_LOST_SAME_WINNER")
    if winner.record.state is AuthorizationState.HUMAN_APPROVED:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, winner, "APPROVAL_RACE_LOST_DIFFERENT_WINNER")
    return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, winner, "APPROVAL_RACE_ILLEGAL_WINNER_STATE")
