from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from agent_controller.approval_contract import ApprovalBinding, ApprovalReceipt, ApprovalResult
from agent_controller.approval_ledger import ApprovalConsumption, _consume_validated_approval_once, _load


@dataclass(frozen=True)
class ApprovalReceiptLookup:
    result: ApprovalResult
    receipt: Optional[ApprovalReceipt] = None
    reason: Optional[str] = None


@dataclass(frozen=True)
class ApprovalLedgerStore:
    """Controller-configured durable approval consumption domain.

    The ledger identity is fixed when Controller composition creates this store;
    supported consume calls cannot redirect one approval to an alternate ledger.
    The same configured store is also the authoritative source for consumed
    receipts handed to later Controller phases.
    """

    ledger_path: str

    def __post_init__(self) -> None:
        if not isinstance(self.ledger_path, str) or not self.ledger_path:
            raise ValueError("ledger_path is required")
        canonical = os.path.realpath(os.path.abspath(self.ledger_path))
        object.__setattr__(self, "ledger_path", canonical)

    def _consume_validated(
        self,
        *,
        approval: ApprovalBinding,
        consumed_at: str,
        receipt_id: str,
    ) -> ApprovalConsumption:
        return _consume_validated_approval_once(
            ledger_path=self.ledger_path,
            approval=approval,
            consumed_at=consumed_at,
            receipt_id=receipt_id,
        )

    def get_consumed_receipt(self, receipt_id: str) -> ApprovalReceiptLookup:
        """Read one durable consumed receipt from this configured approval domain."""

        if not isinstance(receipt_id, str) or not receipt_id:
            return ApprovalReceiptLookup(ApprovalResult.BLOCKED, reason="APPROVAL_RECEIPT_ID_MISSING")

        receipts, corrupt = _load(self.ledger_path)
        if corrupt:
            return ApprovalReceiptLookup(ApprovalResult.BLOCKED, reason="APPROVAL_LEDGER_CORRUPT")

        for item in receipts:
            if item["receipt_id"] != receipt_id:
                continue
            try:
                receipt = ApprovalReceipt(
                    approval_id=item["approval_id"],
                    approval_policy_id=item["approval_policy_id"],
                    controller_task_id=item["controller_task_id"],
                    operation_id=item["operation_id"],
                    provider=item["provider"],
                    requested_capability=item["requested_capability"],
                    effect=item["effect"],
                    repo=item["repo"],
                    target_kind=item["target_kind"],
                    target_id=item["target_id"],
                    expected_head_sha=item["expected_head_sha"],
                    consumed_at=item["consumed_at"],
                    receipt_id=item["receipt_id"],
                    status=item["status"],
                )
            except Exception:
                return ApprovalReceiptLookup(ApprovalResult.BLOCKED, reason="APPROVAL_LEDGER_CORRUPT")
            return ApprovalReceiptLookup(ApprovalResult.PASS, receipt=receipt)

        return ApprovalReceiptLookup(ApprovalResult.BLOCKED, reason="APPROVAL_RECEIPT_NOT_FOUND")
