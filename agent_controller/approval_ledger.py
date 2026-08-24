from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

from agent_controller.approval_contract import ApprovalBinding, ApprovalReceipt, ApprovalResult


@dataclass(frozen=True)
class ApprovalConsumption:
    result: ApprovalResult
    receipt: Optional[ApprovalReceipt] = None
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


def _load(path: str) -> tuple[list[dict], bool]:
    if not os.path.exists(path):
        return [], False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            return [], True
        if not all(isinstance(item, dict) for item in data):
            return [], True
        return data, False
    except Exception:
        return [], True


def _save(path: str, receipts: list[dict]) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(receipts, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def _receipt_matches_binding(receipt: dict, approval: ApprovalBinding) -> bool:
    return (
        receipt.get("approval_id") == approval.approval_id
        and receipt.get("controller_task_id") == approval.controller_task_id
        and receipt.get("operation_id") == approval.operation_id
        and receipt.get("effect") == approval.effect
        and receipt.get("repo") == approval.repo
        and receipt.get("target_kind") == approval.target_kind
        and receipt.get("target_id") == approval.target_id
        and receipt.get("expected_head_sha") == approval.expected_head_sha
        and receipt.get("status") == "CONSUMED"
    )


def consume_approval_once(
    *,
    ledger_path: str,
    approval: ApprovalBinding,
    consumed_at: str,
    receipt_id: str,
) -> ApprovalConsumption:
    """Atomically consume one already-validated approval exactly once.

    This function does not validate target freshness and does not execute the
    authorized effect. Callers must perform trusted-source validation and any
    required objective stale re-read before entering this ledger boundary.
    """

    if not ledger_path or not approval.approval_id or not consumed_at or not receipt_id:
        return ApprovalConsumption(ApprovalResult.BLOCKED, reason="CONSUMPTION_INPUT_MISSING")

    lock_hash = hashlib.sha256(os.path.abspath(ledger_path).encode("utf-8")).hexdigest()
    lock_path = os.path.join(tempfile.gettempdir(), f"agent_controller_approval_{lock_hash}.lock")
    lock = _LedgerLock(lock_path)
    if not lock.acquire():
        return ApprovalConsumption(ApprovalResult.BLOCKED, reason="CONCURRENT_CONSUMPTION")

    try:
        receipts, corrupt = _load(ledger_path)
        if corrupt:
            return ApprovalConsumption(ApprovalResult.BLOCKED, reason="APPROVAL_LEDGER_CORRUPT")

        for existing in receipts:
            if existing.get("approval_id") != approval.approval_id:
                continue
            if not _receipt_matches_binding(existing, approval):
                return ApprovalConsumption(ApprovalResult.BLOCKED, reason="APPROVAL_RECEIPT_BINDING_MISMATCH")
            receipt = ApprovalReceipt(
                approval_id=existing["approval_id"],
                controller_task_id=existing["controller_task_id"],
                operation_id=existing["operation_id"],
                effect=existing["effect"],
                repo=existing.get("repo"),
                target_kind=existing["target_kind"],
                target_id=existing.get("target_id"),
                expected_head_sha=existing.get("expected_head_sha"),
                consumed_at=existing["consumed_at"],
                receipt_id=existing["receipt_id"],
                status=existing["status"],
            )
            return ApprovalConsumption(ApprovalResult.REPLAYED, receipt=receipt, reason="APPROVAL_ALREADY_CONSUMED")

        receipt = ApprovalReceipt(
            approval_id=approval.approval_id,
            controller_task_id=approval.controller_task_id,
            operation_id=approval.operation_id,
            effect=approval.effect,
            repo=approval.repo,
            target_kind=approval.target_kind,
            target_id=approval.target_id,
            expected_head_sha=approval.expected_head_sha,
            consumed_at=consumed_at,
            receipt_id=receipt_id,
        )
        receipts.append(receipt.to_dict())
        try:
            _save(ledger_path, receipts)
        except Exception:
            return ApprovalConsumption(ApprovalResult.BLOCKED, reason="APPROVAL_RECEIPT_PERSISTENCE_FAILED")

        return ApprovalConsumption(ApprovalResult.PASS, receipt=receipt)
    finally:
        lock.release()
