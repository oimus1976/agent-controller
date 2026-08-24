from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Protocol, runtime_checkable

from agent_controller.approval_contract import ApprovalResult, ApprovalValidation
from agent_controller.approval_ledger import ApprovalConsumption, _consume_validated_approval_once
from agent_controller.approval_service import TrustedApprovalIngress, read_and_validate_human_approval
from agent_controller.provider_contract import TaskBinding


@runtime_checkable
class ApprovalTargetReadClient(Protocol):
    """Read-only objective facts required immediately before consumption."""

    def get_target_facts(
        self,
        *,
        repo: Optional[str],
        target_kind: str,
        target_id: Optional[str],
    ) -> Mapping[str, object]:
        ...


@dataclass(frozen=True)
class ApprovalConsumeResult:
    validation: ApprovalValidation
    consumption: Optional[ApprovalConsumption]


def validate_and_consume_human_approval(
    *,
    ingress: TrustedApprovalIngress,
    approval_id: str,
    task: TaskBinding,
    expected_effect: str,
    expected_target_kind: str,
    expected_target_id: Optional[str],
    expected_head_sha: Optional[str],
    target_reader: ApprovalTargetReadClient,
    ledger_path: str,
    now: str,
    receipt_id: str,
) -> ApprovalConsumeResult:
    """Validate trusted approval, re-read objective target, then consume once.

    This is the supported consumption API. No authorized effect is executed.
    The objective read and local ledger commit are not a distributed transaction;
    a future effect executor must independently re-read target facts again before
    applying any high-impact effect.
    """

    approval, validation = read_and_validate_human_approval(
        ingress=ingress,
        approval_id=approval_id,
        task=task,
        expected_effect=expected_effect,
        expected_target_kind=expected_target_kind,
        expected_target_id=expected_target_id,
        expected_head_sha=expected_head_sha,
        now=now,
    )
    if approval is None or not validation.valid:
        return ApprovalConsumeResult(validation, None)

    try:
        facts = target_reader.get_target_facts(
            repo=task.repo,
            target_kind=expected_target_kind,
            target_id=expected_target_id,
        )
    except Exception:
        return ApprovalConsumeResult(
            ApprovalValidation(False, ApprovalResult.UNCERTAIN, "TARGET_READ_UNCERTAIN", approval.approval_id),
            None,
        )

    if not isinstance(facts, Mapping):
        return ApprovalConsumeResult(
            ApprovalValidation(False, ApprovalResult.UNCERTAIN, "TARGET_FACTS_INVALID", approval.approval_id),
            None,
        )

    required_keys = ["repo", "target_kind", "target_id"]
    if expected_head_sha is not None:
        required_keys.append("head_sha")
    for key in required_keys:
        if key not in facts:
            return ApprovalConsumeResult(
                ApprovalValidation(False, ApprovalResult.UNCERTAIN, f"TARGET_FACT_MISSING:{key}", approval.approval_id),
                None,
            )

    if facts["repo"] != task.repo:
        return ApprovalConsumeResult(
            ApprovalValidation(False, ApprovalResult.STALE, "TARGET_REPO_STALE", approval.approval_id),
            None,
        )
    if facts["target_kind"] != expected_target_kind:
        return ApprovalConsumeResult(
            ApprovalValidation(False, ApprovalResult.STALE, "TARGET_KIND_STALE", approval.approval_id),
            None,
        )
    if facts["target_id"] != expected_target_id:
        return ApprovalConsumeResult(
            ApprovalValidation(False, ApprovalResult.STALE, "TARGET_ID_STALE", approval.approval_id),
            None,
        )
    if expected_head_sha is not None and facts["head_sha"] != expected_head_sha:
        return ApprovalConsumeResult(
            ApprovalValidation(False, ApprovalResult.STALE, "TARGET_HEAD_STALE", approval.approval_id),
            None,
        )

    consumption = _consume_validated_approval_once(
        ledger_path=ledger_path,
        approval=approval,
        consumed_at=now,
        receipt_id=receipt_id,
    )
    if consumption.result is ApprovalResult.PASS:
        return ApprovalConsumeResult(validation, consumption)

    return ApprovalConsumeResult(
        ApprovalValidation(False, consumption.result, consumption.reason, approval.approval_id),
        consumption,
    )
