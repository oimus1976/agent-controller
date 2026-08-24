from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional, Protocol, runtime_checkable


class ApprovalResult(str, Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    STALE = "STALE"
    REPLAYED = "REPLAYED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class ApprovalBinding:
    approval_id: str
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
    issuer_kind: str
    issuer_subject: str
    ingress_source: str
    issued_at: str
    expires_at: Optional[str] = None
    nonce: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ApprovalValidation:
    valid: bool
    result: ApprovalResult
    reason: Optional[str] = None
    approval_id: Optional[str] = None


@runtime_checkable
class HumanApprovalSource(Protocol):
    """Trusted control-plane ingress for structured human approval facts.

    Implementations establish the trust boundary. Core must never construct an
    executable ApprovalBinding from provider prose, artifact text, comments, or
    an arbitrary APPROVE-looking string.
    """

    def get_approval(self, approval_id: str) -> Optional[ApprovalBinding]:
        ...
