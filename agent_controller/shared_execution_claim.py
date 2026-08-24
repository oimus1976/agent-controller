from __future__ import annotations

import secrets
from dataclasses import dataclass, replace
from typing import Mapping, Optional

from agent_controller.shared_authorization import (
    AuthorizationDecision,
    AuthorizationState,
    BackendWriteResult,
    SharedAuthorizationStore,
    SharedRecordSnapshot,
    operation_state_path,
    read_operation_by_identity,
)
from agent_controller.signed_shared_approval import (
    ApprovalTargetReadClient,
    verify_stored_human_approval,
)


@dataclass(frozen=True)
class SharedExecutionClaimResult:
    decision: AuthorizationDecision
    snapshot: Optional[SharedRecordSnapshot] = None
    reason: Optional[str] = None


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _write_outcome(write: object) -> str:
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


def _verify_signed_authority(snapshot: SharedRecordSnapshot) -> bool:
    """Verify the human signature independent of the coordination lifecycle state."""
    if not isinstance(snapshot, SharedRecordSnapshot):
        return False
    record = snapshot.record
    if record.provenance is None:
        return False
    normalized = SharedRecordSnapshot(
        replace(
            record,
            state=AuthorizationState.HUMAN_APPROVED,
            execution_claim_id=None,
            controller_run_id=None,
        ),
        snapshot.revision,
    )
    return verify_stored_human_approval(normalized).decision is AuthorizationDecision.PASS


def _target_is_fresh(
    *, reader: ApprovalTargetReadClient, binding
) -> tuple[AuthorizationDecision, Optional[str]]:
    try:
        facts = reader.get_target_facts(
            repo=binding.repo,
            target_kind=binding.target_kind,
            target_id=binding.target_id,
        )
    except Exception:
        return AuthorizationDecision.UNCERTAIN, "TARGET_READ_UNCERTAIN"
    if not isinstance(facts, Mapping):
        return AuthorizationDecision.UNCERTAIN, "TARGET_FACTS_INVALID"
    expected = {
        "repo": binding.repo,
        "target_kind": binding.target_kind,
        "target_id": binding.target_id,
        "head_sha": binding.expected_head_sha,
    }
    for key in expected:
        if key not in facts:
            return AuthorizationDecision.UNCERTAIN, f"TARGET_FACT_MISSING:{key}"
    for key, value in expected.items():
        if facts[key] != value:
            return AuthorizationDecision.STALE, f"TARGET_{key.upper()}_STALE"
    return AuthorizationDecision.PASS, None


class SharedExecutionClaimController:
    """Exactly-once coordination claim; this is not an effect executor."""

    __slots__ = ("_store", "_target_reader", "_controller_run_id")

    def __init__(
        self,
        *,
        store: SharedAuthorizationStore,
        target_reader: ApprovalTargetReadClient,
        controller_run_id: str,
    ) -> None:
        if not isinstance(store, SharedAuthorizationStore):
            raise TypeError("store must be SharedAuthorizationStore")
        if not isinstance(target_reader, ApprovalTargetReadClient):
            raise TypeError("target_reader must satisfy ApprovalTargetReadClient")
        if not _nonempty(controller_run_id):
            raise ValueError("controller_run_id must be non-empty")
        self._store = store
        self._target_reader = target_reader
        self._controller_run_id = controller_run_id

    def claim(
        self,
        *,
        controller_task_id: str,
        operation_id: str,
        operation_version: str,
    ) -> SharedExecutionClaimResult:
        current = read_operation_by_identity(
            store=self._store,
            controller_task_id=controller_task_id,
            operation_id=operation_id,
            operation_version=operation_version,
        )
        if current.decision is not AuthorizationDecision.PASS or current.snapshot is None:
            return SharedExecutionClaimResult(current.decision, current.snapshot, current.reason)

        record = current.snapshot.record
        if record.state is AuthorizationState.EXECUTION_CLAIMED:
            if not _verify_signed_authority(current.snapshot):
                return SharedExecutionClaimResult(
                    AuthorizationDecision.BLOCKED,
                    current.snapshot,
                    "CLAIMED_STATE_SIGNED_AUTHORITY_INVALID",
                )
            if not _nonempty(record.execution_claim_id) or not _nonempty(record.controller_run_id):
                return SharedExecutionClaimResult(
                    AuthorizationDecision.BLOCKED,
                    current.snapshot,
                    "CLAIMED_STATE_IDENTITY_INVALID",
                )
            return SharedExecutionClaimResult(
                AuthorizationDecision.REPLAYED,
                current.snapshot,
                "EXECUTION_ALREADY_CLAIMED",
            )

        if record.state is not AuthorizationState.HUMAN_APPROVED:
            return SharedExecutionClaimResult(
                AuthorizationDecision.BLOCKED, current.snapshot, "CLAIM_REQUIRES_HUMAN_APPROVED"
            )

        verified = verify_stored_human_approval(current.snapshot)
        if verified.decision is not AuthorizationDecision.PASS:
            return SharedExecutionClaimResult(
                AuthorizationDecision.BLOCKED,
                current.snapshot,
                "HUMAN_APPROVAL_CRYPTOGRAPHIC_REVERIFY_FAILED",
            )

        target_decision, target_reason = _target_is_fresh(
            reader=self._target_reader, binding=record.binding
        )
        if target_decision is not AuthorizationDecision.PASS:
            return SharedExecutionClaimResult(
                target_decision, current.snapshot, target_reason
            )

        claim_id = "claim_" + secrets.token_urlsafe(24)
        claimed_record = replace(
            record,
            state=AuthorizationState.EXECUTION_CLAIMED,
            execution_claim_id=claim_id,
            controller_run_id=self._controller_run_id,
        )
        try:
            write = self._store.backend.compare_and_swap(
                state_ref=self._store.state_ref,
                path=operation_state_path(record.binding),
                expected_revision=current.snapshot.revision,
                record=claimed_record,
            )
        except Exception:
            return SharedExecutionClaimResult(
                AuthorizationDecision.UNCERTAIN, reason="CLAIM_CAS_UNCERTAIN"
            )

        outcome = _write_outcome(write)
        if outcome == "INVALID":
            return SharedExecutionClaimResult(
                AuthorizationDecision.UNCERTAIN, reason="CLAIM_WRITE_RESULT_INVALID"
            )

        # All outcomes, including nominal writes, are resolved by authoritative
        # reread because coordination storage is shared and Agent-writable.
        reread = read_operation_by_identity(
            store=self._store,
            controller_task_id=controller_task_id,
            operation_id=operation_id,
            operation_version=operation_version,
        )
        if reread.decision is not AuthorizationDecision.PASS or reread.snapshot is None:
            return SharedExecutionClaimResult(
                AuthorizationDecision.UNCERTAIN if outcome in {"WRITTEN", "UNCERTAIN"} else reread.decision,
                reread.snapshot,
                "CLAIM_REREAD_UNCERTAIN" if outcome in {"WRITTEN", "UNCERTAIN"} else reread.reason,
            )

        winner = reread.snapshot.record
        if winner.state is not AuthorizationState.EXECUTION_CLAIMED:
            return SharedExecutionClaimResult(
                AuthorizationDecision.UNCERTAIN if outcome in {"WRITTEN", "UNCERTAIN"} else AuthorizationDecision.BLOCKED,
                reread.snapshot,
                "CLAIM_NOT_DURABLY_PRESENT",
            )
        if not _verify_signed_authority(reread.snapshot):
            return SharedExecutionClaimResult(
                AuthorizationDecision.BLOCKED,
                reread.snapshot,
                "CLAIM_WINNER_SIGNED_AUTHORITY_INVALID",
            )
        if winner.binding != record.binding or winner.provenance != record.provenance:
            return SharedExecutionClaimResult(
                AuthorizationDecision.BLOCKED,
                reread.snapshot,
                "CLAIM_WINNER_AUTHORIZATION_CONFLICT",
            )
        if not _nonempty(winner.execution_claim_id) or not _nonempty(winner.controller_run_id):
            return SharedExecutionClaimResult(
                AuthorizationDecision.BLOCKED,
                reread.snapshot,
                "CLAIM_WINNER_IDENTITY_INVALID",
            )

        if (
            winner.execution_claim_id == claim_id
            and winner.controller_run_id == self._controller_run_id
        ):
            return SharedExecutionClaimResult(
                AuthorizationDecision.PASS,
                reread.snapshot,
                "CLAIM_CONFIRMED_AFTER_AUTHORITATIVE_REREAD",
            )

        return SharedExecutionClaimResult(
            AuthorizationDecision.REPLAYED,
            reread.snapshot,
            "CLAIM_RACE_LOST_EXISTING_WINNER",
        )
