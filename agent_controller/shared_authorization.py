from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional, Protocol, runtime_checkable


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
    return all(
        _nonempty(value)
        for value in (
            provenance.assurance,
            provenance.provenance_kind,
            provenance.signer_key_id,
            provenance.challenge_nonce,
            provenance.challenge_digest,
            provenance.signature_digest,
        )
    )


def _valid_record(record: SharedAuthorizationRecord) -> bool:
    if not isinstance(record, SharedAuthorizationRecord):
        return False
    if record.schema_version != SCHEMA_VERSION or not _valid_binding(record.binding):
        return False
    if not isinstance(record.state, AuthorizationState):
        return False

    if record.state is AuthorizationState.PROPOSED:
        return (
            record.provenance is None
            and record.execution_claim_id is None
            and record.controller_run_id is None
        )

    if record.state is AuthorizationState.HUMAN_APPROVED:
        return (
            _valid_provenance(record.provenance)
            and record.execution_claim_id is None
            and record.controller_run_id is None
        )

    if record.state in {
        AuthorizationState.EXECUTION_CLAIMED,
        AuthorizationState.EFFECT_STARTED,
        AuthorizationState.EFFECT_VERIFIED,
        AuthorizationState.FAILED_AFTER_CLAIM,
    }:
        return (
            _valid_provenance(record.provenance)
            and _nonempty(record.execution_claim_id)
            and _nonempty(record.controller_run_id)
        )

    return record.execution_claim_id is None and record.controller_run_id is None


def _valid_snapshot(snapshot: object) -> bool:
    return (
        isinstance(snapshot, SharedRecordSnapshot)
        and _nonempty(snapshot.revision)
        and _valid_record(snapshot.record)
    )


def _classify_write_result(write: object) -> str:
    if not isinstance(write, BackendWriteResult):
        return "INVALID"
    outcomes = int(bool(write.written)) + int(bool(write.conflict)) + int(bool(write.uncertain))
    if outcomes != 1:
        return "INVALID"
    if write.written:
        return "WRITTEN" if _nonempty(write.revision) else "INVALID"
    if write.revision is not None:
        return "INVALID"
    return "CONFLICT" if write.conflict else "UNCERTAIN"


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


def read_operation(
    *, store: SharedAuthorizationStore, binding: OperationAuthorizationBinding
) -> SharedAuthorizationResult:
    try:
        path = operation_state_path(binding)
        snapshot = store.backend.read(state_ref=store.state_ref, path=path)
    except Exception:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_READ_UNCERTAIN")
    if snapshot is None:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason="STATE_MISSING")
    if not _valid_snapshot(snapshot):
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason="STATE_RECORD_INVALID")
    if snapshot.record.binding != binding:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, snapshot, "OPERATION_BINDING_CONFLICT")
    return SharedAuthorizationResult(AuthorizationDecision.PASS, snapshot)


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

    outcome = _classify_write_result(write)
    if outcome == "INVALID":
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_WRITE_RESULT_INVALID")
    if outcome == "WRITTEN":
        return SharedAuthorizationResult(
            AuthorizationDecision.PASS, SharedRecordSnapshot(record, write.revision)
        )
    if outcome == "UNCERTAIN":
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CREATE_UNCERTAIN")

    try:
        existing = store.backend.read(state_ref=store.state_ref, path=path)
    except Exception:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_REREAD_UNCERTAIN")
    if existing is None:
        return SharedAuthorizationResult(AuthorizationDecision.UNCERTAIN, reason="STATE_CREATE_CONFLICT_WITHOUT_RECORD")
    if not _valid_snapshot(existing):
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, reason="STATE_RECORD_INVALID")
    if existing.record.binding != binding:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, existing, "OPERATION_BINDING_CONFLICT")
    if existing.record.state is not AuthorizationState.PROPOSED:
        return SharedAuthorizationResult(AuthorizationDecision.BLOCKED, existing, "OPERATION_ALREADY_ADVANCED")
    return SharedAuthorizationResult(AuthorizationDecision.REPLAYED, existing, "OPERATION_ALREADY_PROPOSED")
