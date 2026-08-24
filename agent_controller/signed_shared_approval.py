from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, replace
from typing import Mapping, Optional, Protocol, runtime_checkable

from agent_controller.shared_authorization import (
    AuthorizationDecision,
    AuthorizationProvenance,
    AuthorizationState,
    BackendWriteResult,
    OperationAuthorizationBinding,
    SharedAuthorizationStore,
    SharedRecordSnapshot,
    operation_state_path,
    read_operation,
    read_operation_by_identity,
)
from agent_controller.signed_approval import (
    ApprovalChallenge,
    ProvenanceAssurance,
    canonicalize_approval_challenge,
    verify_signed_approval,
)


@runtime_checkable
class ApprovalTargetReadClient(Protocol):
    def get_target_facts(
        self, *, repo: str, target_kind: str, target_id: str
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class SignedSharedApprovalResult:
    decision: AuthorizationDecision
    snapshot: Optional[SharedRecordSnapshot] = None
    reason: Optional[str] = None


def _challenge_matches_binding(
    challenge: ApprovalChallenge, binding: OperationAuthorizationBinding
) -> bool:
    if not isinstance(challenge, ApprovalChallenge) or not isinstance(
        binding, OperationAuthorizationBinding
    ):
        return False
    required_binding_strings = (binding.repo, binding.target_id, binding.expected_head_sha)
    if any(not isinstance(value, str) or not value for value in required_binding_strings):
        return False
    return (
        challenge.approval_id == binding.approval_id
        and challenge.controller_task_id == binding.controller_task_id
        and challenge.operation_id == binding.operation_id
        and challenge.operation_version == binding.operation_version
        and challenge.effect == binding.effect
        and challenge.repo == binding.repo
        and challenge.target_kind == binding.target_kind
        and challenge.target_id == binding.target_id
        and challenge.expected_head_sha == binding.expected_head_sha
    )


def _provenance_for_verified_signature(
    *, challenge: ApprovalChallenge, signature_b64: str
) -> AuthorizationProvenance:
    canonical = canonicalize_approval_challenge(challenge)
    signature_bytes = base64.b64decode(signature_b64, validate=True)
    return AuthorizationProvenance(
        assurance=ProvenanceAssurance.VERIFIED_EVENT_PROVENANCE.value,
        provenance_kind="SIGNED_CHALLENGE",
        signer_key_id=challenge.signer_key_id,
        challenge_nonce=challenge.challenge_nonce,
        challenge_digest=hashlib.sha256(canonical).hexdigest(),
        signature_digest=hashlib.sha256(signature_bytes).hexdigest(),
    )


def _write_outcome(write: object) -> str:
    if not isinstance(write, BackendWriteResult):
        return "INVALID"
    outcomes = int(bool(write.written)) + int(bool(write.conflict)) + int(bool(write.uncertain))
    if outcomes != 1:
        return "INVALID"
    if write.written:
        return "WRITTEN" if isinstance(write.revision, str) and bool(write.revision) else "INVALID"
    if write.revision is not None:
        return "INVALID"
    return "CONFLICT" if write.conflict else "UNCERTAIN"


class SignedSharedApprovalController:
    """Controller-composed signed approval transition service.

    Shared-state mutation authority and the objective target reader are fixed at
    composition. Per-call input is only the signed challenge and signature. The
    authoritative operation binding is loaded from existing shared PROPOSED
    state; callers cannot replace policy/provider/capability/binding fields.
    """

    __slots__ = ("_store", "_target_reader")

    def __init__(
        self,
        *,
        store: SharedAuthorizationStore,
        target_reader: ApprovalTargetReadClient,
    ) -> None:
        if not isinstance(store, SharedAuthorizationStore):
            raise TypeError("store must be SharedAuthorizationStore")
        if not isinstance(target_reader, ApprovalTargetReadClient):
            raise TypeError("target_reader must satisfy ApprovalTargetReadClient")
        self._store = store
        self._target_reader = target_reader

    def approve(
        self,
        *,
        challenge: ApprovalChallenge,
        signature_b64: str,
    ) -> SignedSharedApprovalResult:
        if not isinstance(challenge, ApprovalChallenge):
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED, reason="CHALLENGE_INPUT_INVALID"
            )
        if not isinstance(signature_b64, str) or not signature_b64:
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED, reason="SIGNATURE_INPUT_INVALID"
            )

        verification = verify_signed_approval(
            challenge=challenge, signature_b64=signature_b64
        )
        if (
            not verification.valid
            or verification.assurance
            is not ProvenanceAssurance.VERIFIED_EVENT_PROVENANCE
            or verification.signer_key_id != challenge.signer_key_id
        ):
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED,
                reason=verification.reason or "SIGNATURE_NOT_VERIFIED",
            )

        try:
            provenance = _provenance_for_verified_signature(
                challenge=challenge, signature_b64=signature_b64
            )
        except Exception:
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED,
                reason="VERIFIED_SIGNATURE_ENCODING_INCONSISTENT",
            )

        current = read_operation_by_identity(
            store=self._store,
            controller_task_id=challenge.controller_task_id,
            operation_id=challenge.operation_id,
            operation_version=challenge.operation_version,
        )
        if current.decision is not AuthorizationDecision.PASS or current.snapshot is None:
            return SignedSharedApprovalResult(
                current.decision, current.snapshot, current.reason
            )
        binding = current.snapshot.record.binding
        if not _challenge_matches_binding(challenge, binding):
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED,
                current.snapshot,
                "CHALLENGE_BINDING_MISMATCH",
            )

        current_record = current.snapshot.record
        if current_record.state is AuthorizationState.HUMAN_APPROVED:
            if current_record.provenance == provenance:
                return SignedSharedApprovalResult(
                    AuthorizationDecision.REPLAYED,
                    current.snapshot,
                    "APPROVAL_ALREADY_RECORDED",
                )
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED,
                current.snapshot,
                "APPROVAL_PROVENANCE_CONFLICT",
            )
        if current_record.state is not AuthorizationState.PROPOSED:
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED,
                current.snapshot,
                "ILLEGAL_PRIOR_STATE",
            )

        try:
            facts = self._target_reader.get_target_facts(
                repo=binding.repo,
                target_kind=binding.target_kind,
                target_id=binding.target_id,
            )
        except Exception:
            return SignedSharedApprovalResult(
                AuthorizationDecision.UNCERTAIN, reason="TARGET_READ_UNCERTAIN"
            )
        if not isinstance(facts, Mapping):
            return SignedSharedApprovalResult(
                AuthorizationDecision.UNCERTAIN, reason="TARGET_FACTS_INVALID"
            )
        for key in ("repo", "target_kind", "target_id", "head_sha"):
            if key not in facts:
                return SignedSharedApprovalResult(
                    AuthorizationDecision.UNCERTAIN,
                    reason=f"TARGET_FACT_MISSING:{key}",
                )
        expected = {
            "repo": binding.repo,
            "target_kind": binding.target_kind,
            "target_id": binding.target_id,
            "head_sha": binding.expected_head_sha,
        }
        for key, value in expected.items():
            if facts[key] != value:
                return SignedSharedApprovalResult(
                    AuthorizationDecision.STALE,
                    current.snapshot,
                    f"TARGET_{key.upper()}_STALE",
                )

        approved_record = replace(
            current_record,
            state=AuthorizationState.HUMAN_APPROVED,
            provenance=provenance,
        )
        try:
            write = self._store.backend.compare_and_swap(
                state_ref=self._store.state_ref,
                path=operation_state_path(binding),
                expected_revision=current.snapshot.revision,
                record=approved_record,
            )
        except Exception:
            return SignedSharedApprovalResult(
                AuthorizationDecision.UNCERTAIN, reason="STATE_CAS_UNCERTAIN"
            )

        outcome = _write_outcome(write)
        if outcome == "INVALID":
            return SignedSharedApprovalResult(
                AuthorizationDecision.UNCERTAIN, reason="STATE_WRITE_RESULT_INVALID"
            )
        if outcome == "WRITTEN":
            return SignedSharedApprovalResult(
                AuthorizationDecision.PASS,
                SharedRecordSnapshot(approved_record, write.revision),
            )

        reread = read_operation(store=self._store, binding=binding)
        if reread.decision is not AuthorizationDecision.PASS or reread.snapshot is None:
            if outcome == "UNCERTAIN":
                return SignedSharedApprovalResult(
                    AuthorizationDecision.UNCERTAIN,
                    reread.snapshot,
                    "STATE_CAS_UNCERTAIN",
                )
            return SignedSharedApprovalResult(
                reread.decision, reread.snapshot, reread.reason
            )
        winner = reread.snapshot.record
        if winner.state is AuthorizationState.HUMAN_APPROVED:
            if winner.provenance == provenance:
                if outcome == "CONFLICT":
                    return SignedSharedApprovalResult(
                        AuthorizationDecision.REPLAYED,
                        reread.snapshot,
                        "APPROVAL_RACE_LOST_SAME_WINNER",
                    )
                return SignedSharedApprovalResult(
                    AuthorizationDecision.PASS,
                    reread.snapshot,
                    "APPROVAL_CONFIRMED_AFTER_UNCERTAIN_WRITE",
                )
            return SignedSharedApprovalResult(
                AuthorizationDecision.BLOCKED,
                reread.snapshot,
                "APPROVAL_RACE_DIFFERENT_WINNER",
            )
        if outcome == "UNCERTAIN":
            return SignedSharedApprovalResult(
                AuthorizationDecision.UNCERTAIN,
                reread.snapshot,
                "STATE_CAS_UNCERTAIN",
            )
        return SignedSharedApprovalResult(
            AuthorizationDecision.BLOCKED,
            reread.snapshot,
            "APPROVAL_RACE_ILLEGAL_WINNER_STATE",
        )
