from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Optional

from agent_controller.approval_contract import ApprovalBinding, ApprovalReceipt, ApprovalResult


_RECEIPT_KEYS = frozenset({
    "approval_id", "approval_policy_id", "controller_task_id", "operation_id",
    "provider", "requested_capability", "effect", "repo", "target_kind",
    "target_id", "expected_head_sha", "consumed_at", "receipt_id", "status",
})


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


def _validate_receipts(data: object) -> bool:
    if not isinstance(data, list):
        return False
    seen_approvals = set()
    seen_receipts = set()
    for item in data:
        if not isinstance(item, dict) or set(item.keys()) != _RECEIPT_KEYS:
            return False
        if item.get("status") != "CONSUMED":
            return False
        approval_id = item.get("approval_id")
        receipt_id = item.get("receipt_id")
        if not isinstance(approval_id, str) or not approval_id:
            return False
        if not isinstance(receipt_id, str) or not receipt_id:
            return False
        if approval_id in seen_approvals or receipt_id in seen_receipts:
            return False
        seen_approvals.add(approval_id)
        seen_receipts.add(receipt_id)
    return True


def _load(path: str) -> tuple[list[dict], bool]:
    if not os.path.exists(path):
        return [], False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not _validate_receipts(data):
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
        receipt["approval_id"] == approval.approval_id
        and receipt["approval_policy_id"] == approval.approval_policy_id
        and receipt["controller_task_id"] == approval.controller_task_id
        and receipt["operation_id"] == approval.operation_id
        and receipt["provider"] == approval.provider
        and receipt["requested_capability"] == approval.requested_capability
        and receipt["effect"] == approval.effect
        and receipt["repo"] == approval.repo
        and receipt["target_kind"] == approval.target_kind
        and receipt["target_id"] == approval.target_id
        and receipt["expected_head_sha"] == approval.expected_head_sha
        and receipt["status"] == "CONSUMED"
    )


def _consume_validated_approval_once(
    *,
    ledger_path: str,
    approval: ApprovalBinding,
    consumed_at: str,
    receipt_id: str,
) -> ApprovalConsumption:
    """Internal durable commit for an approval validated by the safe flow.

    This function intentionally has no public non-underscored consume entrypoint.
    `approval_consumption.validate_and_consume_human_approval` is the supported
    Controller API because it performs trusted-ingress validation and objective
    stale re-read before reaching this ledger boundary.
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
            if existing["receipt_id"] == receipt_id and existing["approval_id"] != approval.approval_id:
                return ApprovalConsumption(ApprovalResult.BLOCKED, reason="RECEIPT_ID_REUSED")

        for existing in receipts:
            if existing["approval_id"] != approval.approval_id:
                continue
            if not _receipt_matches_binding(existing, approval):
                return ApprovalConsumption(ApprovalResult.BLOCKED, reason="APPROVAL_RECEIPT_BINDING_MISMATCH")
            receipt = ApprovalReceipt(
                approval_id=existing["approval_id"],
                approval_policy_id=existing["approval_policy_id"],
                controller_task_id=existing["controller_task_id"],
                operation_id=existing["operation_id"],
                provider=existing["provider"],
                requested_capability=existing["requested_capability"],
                effect=existing["effect"],
                repo=existing["repo"],
                target_kind=existing["target_kind"],
                target_id=existing["target_id"],
                expected_head_sha=existing["expected_head_sha"],
                consumed_at=existing["consumed_at"],
                receipt_id=existing["receipt_id"],
                status=existing["status"],
            )
            return ApprovalConsumption(ApprovalResult.REPLAYED, receipt=receipt, reason="APPROVAL_ALREADY_CONSUMED")

        receipt = ApprovalReceipt(
            approval_id=approval.approval_id,
            approval_policy_id=approval.approval_policy_id,
            controller_task_id=approval.controller_task_id,
            operation_id=approval.operation_id,
            provider=approval.provider,
            requested_capability=approval.requested_capability,
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
