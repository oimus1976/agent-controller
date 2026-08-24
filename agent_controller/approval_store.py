from __future__ import annotations

import os
from dataclasses import dataclass

from agent_controller.approval_contract import ApprovalBinding
from agent_controller.approval_ledger import ApprovalConsumption, _consume_validated_approval_once


@dataclass(frozen=True)
class ApprovalLedgerStore:
    """Controller-configured durable approval consumption domain.

    The ledger identity is fixed when Controller composition creates this store;
    supported consume calls cannot redirect one approval to an alternate ledger.
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
