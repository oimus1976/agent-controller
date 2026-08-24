from __future__ import annotations

import os
from dataclasses import dataclass

from agent_controller.approval_contract import ApprovalReceipt
from agent_controller.execution_ledger import ExecutionClaimCommit, _claim_execution_once


@dataclass(frozen=True)
class ExecutionClaimStore:
    """Controller-configured execution-attempt claim domain."""

    ledger_path: str

    def __post_init__(self) -> None:
        if not isinstance(self.ledger_path, str) or not self.ledger_path:
            raise ValueError("ledger_path is required")
        object.__setattr__(self, "ledger_path", os.path.realpath(os.path.abspath(self.ledger_path)))

    def _claim_validated(
        self,
        *,
        receipt: ApprovalReceipt,
        execution_claim_id: str,
        claimed_at: str,
    ) -> ExecutionClaimCommit:
        return _claim_execution_once(
            ledger_path=self.ledger_path,
            receipt=receipt,
            execution_claim_id=execution_claim_id,
            claimed_at=claimed_at,
        )
