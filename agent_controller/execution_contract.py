from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional


class ExecutionClaimResult(str, Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    STALE = "STALE"
    REPLAYED = "REPLAYED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class ExecutionClaim:
    execution_claim_id: str
    approval_id: str
    approval_receipt_id: str
    approval_policy_id: str
    controller_task_id: str
    operation_id: str
    provider: Optional[str]
    requested_capability: str
    effect: str
    repo: Optional[str]
    target_kind: str
    target_id: Optional[str]
    expected_head_sha: Optional[str]
    claimed_at: str
    status: str = "CLAIMED"

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ExecutionClaimDecision:
    valid: bool
    result: ExecutionClaimResult
    reason: Optional[str] = None
    execution_claim_id: Optional[str] = None
    claim: Optional[ExecutionClaim] = None
