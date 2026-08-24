from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

from agent_controller.approval_contract import ApprovalReceipt
from agent_controller.execution_contract import ExecutionClaim, ExecutionClaimResult


_CLAIM_KEYS = frozenset({
    "execution_claim_id", "approval_id", "approval_receipt_id", "approval_policy_id",
    "controller_task_id", "operation_id", "provider", "requested_capability", "effect",
    "repo", "target_kind", "target_id", "expected_head_sha", "claimed_at", "status",
})


@dataclass(frozen=True)
class ExecutionClaimCommit:
    result: ExecutionClaimResult
    claim: Optional[ExecutionClaim] = None
    reason: Optional[str] = None


class _LedgerLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.fd = None

    def acquire(self) -> bool:
        try:
            self.fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            return True
        except FileExistsError:
            return False

    def release(self) -> None:
        if self.fd is None:
            return
        try:
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.remove(self.lock_path)
        except OSError:
            pass
        self.fd = None


def _validate_claims(data: object) -> bool:
    if not isinstance(data, list):
        return False
    receipt_ids = set()
    claim_ids = set()
    for item in data:
        if not isinstance(item, dict) or set(item.keys()) != _CLAIM_KEYS:
            return False
        if item.get("status") != "CLAIMED":
            return False
        receipt_id = item.get("approval_receipt_id")
        claim_id = item.get("execution_claim_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            return False
        if not isinstance(claim_id, str) or not claim_id:
            return False
        if receipt_id in receipt_ids or claim_id in claim_ids:
            return False
        receipt_ids.add(receipt_id)
        claim_ids.add(claim_id)
    return True


def _load(path: str) -> tuple[list[dict], bool]:
    if not os.path.exists(path):
        return [], False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return (data, False) if _validate_claims(data) else ([], True)
    except Exception:
        return [], True


def _save(path: str, claims: list[dict]) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(claims, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def _matches_receipt(item: dict, receipt: ApprovalReceipt) -> bool:
    return (
        item["approval_id"] == receipt.approval_id
        and item["approval_receipt_id"] == receipt.receipt_id
        and item["approval_policy_id"] == receipt.approval_policy_id
        and item["controller_task_id"] == receipt.controller_task_id
        and item["operation_id"] == receipt.operation_id
        and item["provider"] == receipt.provider
        and item["requested_capability"] == receipt.requested_capability
        and item["effect"] == receipt.effect
        and item["repo"] == receipt.repo
        and item["target_kind"] == receipt.target_kind
        and item["target_id"] == receipt.target_id
        and item["expected_head_sha"] == receipt.expected_head_sha
    )


def _claim_execution_once(
    *,
    ledger_path: str,
    receipt: ApprovalReceipt,
    execution_claim_id: str,
    claimed_at: str,
) -> ExecutionClaimCommit:
    if not ledger_path or not execution_claim_id or not claimed_at or not receipt.receipt_id:
        return ExecutionClaimCommit(ExecutionClaimResult.BLOCKED, reason="EXECUTION_CLAIM_INPUT_MISSING")

    lock_hash = hashlib.sha256(os.path.abspath(ledger_path).encode("utf-8")).hexdigest()
    lock = _LedgerLock(os.path.join(tempfile.gettempdir(), f"agent_controller_execution_{lock_hash}.lock"))
    if not lock.acquire():
        return ExecutionClaimCommit(ExecutionClaimResult.BLOCKED, reason="CONCURRENT_EXECUTION_CLAIM")

    try:
        claims, corrupt = _load(ledger_path)
        if corrupt:
            return ExecutionClaimCommit(ExecutionClaimResult.BLOCKED, reason="EXECUTION_LEDGER_CORRUPT")

        for item in claims:
            if item["execution_claim_id"] == execution_claim_id and item["approval_receipt_id"] != receipt.receipt_id:
                return ExecutionClaimCommit(ExecutionClaimResult.BLOCKED, reason="EXECUTION_CLAIM_ID_REUSED")

        for item in claims:
            if item["approval_receipt_id"] != receipt.receipt_id:
                continue
            if not _matches_receipt(item, receipt):
                return ExecutionClaimCommit(ExecutionClaimResult.BLOCKED, reason="EXECUTION_RECEIPT_BINDING_MISMATCH")
            claim = ExecutionClaim(**item)
            return ExecutionClaimCommit(
                ExecutionClaimResult.REPLAYED,
                claim=claim,
                reason="EXECUTION_ALREADY_CLAIMED",
            )

        claim = ExecutionClaim(
            execution_claim_id=execution_claim_id,
            approval_id=receipt.approval_id,
            approval_receipt_id=receipt.receipt_id,
            approval_policy_id=receipt.approval_policy_id,
            controller_task_id=receipt.controller_task_id,
            operation_id=receipt.operation_id,
            provider=receipt.provider,
            requested_capability=receipt.requested_capability,
            effect=receipt.effect,
            repo=receipt.repo,
            target_kind=receipt.target_kind,
            target_id=receipt.target_id,
            expected_head_sha=receipt.expected_head_sha,
            claimed_at=claimed_at,
        )
        claims.append(claim.to_dict())
        try:
            _save(ledger_path, claims)
        except Exception:
            return ExecutionClaimCommit(
                ExecutionClaimResult.BLOCKED,
                reason="EXECUTION_CLAIM_PERSISTENCE_FAILED",
            )
        return ExecutionClaimCommit(ExecutionClaimResult.PASS, claim=claim)
    finally:
        lock.release()
