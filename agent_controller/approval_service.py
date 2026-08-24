from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from agent_controller.approval_contract import (
    ApprovalBinding,
    ApprovalResult,
    ApprovalValidation,
    HumanApprovalSource,
)
from agent_controller.approval_validator import validate_approval_binding
from agent_controller.provider_contract import TaskBinding


@dataclass(frozen=True)
class TrustedApprovalIngress:
    """Controller-configured trusted approval source.

    `source_name` is configuration owned by Controller composition, not a value
    learned from provider/agent content. The approval returned by `source` must
    claim the same ingress source before it can validate.
    """

    source_name: str
    source: HumanApprovalSource


def read_and_validate_human_approval(
    *,
    ingress: TrustedApprovalIngress,
    approval_id: str,
    task: TaskBinding,
    expected_effect: str,
    expected_target_kind: str,
    expected_target_id: Optional[str],
    expected_head_sha: Optional[str],
    now: str,
) -> tuple[Optional[ApprovalBinding], ApprovalValidation]:
    """Read one approval only through a configured trusted ingress boundary."""

    if not approval_id or not ingress.source_name:
        return None, ApprovalValidation(
            False,
            ApprovalResult.BLOCKED,
            "TRUSTED_INGRESS_BINDING_MISSING",
            approval_id or None,
        )

    try:
        approval = ingress.source.get_approval(approval_id)
    except Exception:
        return None, ApprovalValidation(
            False,
            ApprovalResult.UNCERTAIN,
            "APPROVAL_SOURCE_READ_UNCERTAIN",
            approval_id,
        )

    if approval is None:
        return None, ApprovalValidation(
            False,
            ApprovalResult.BLOCKED,
            "APPROVAL_NOT_FOUND",
            approval_id,
        )

    if approval.approval_id != approval_id:
        return approval, ApprovalValidation(
            False,
            ApprovalResult.BLOCKED,
            "APPROVAL_ID_MISMATCH",
            approval.approval_id,
        )

    if approval.ingress_source != ingress.source_name:
        return approval, ApprovalValidation(
            False,
            ApprovalResult.BLOCKED,
            "INGRESS_SOURCE_BINDING_MISMATCH",
            approval.approval_id,
        )

    validation = validate_approval_binding(
        task=task,
        approval=approval,
        expected_effect=expected_effect,
        expected_target_kind=expected_target_kind,
        expected_target_id=expected_target_id,
        expected_head_sha=expected_head_sha,
        trusted_ingress_sources=(ingress.source_name,),
        now=now,
    )
    return approval, validation
