from __future__ import annotations

from datetime import datetime, timezone
from typing import Collection

from agent_controller.approval_contract import (
    ApprovalBinding,
    ApprovalResult,
    ApprovalValidation,
)
from agent_controller.provider_contract import TaskBinding


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def validate_approval_binding(
    *,
    task: TaskBinding,
    approval: ApprovalBinding,
    expected_effect: str,
    expected_target_kind: str,
    expected_target_id: str | None,
    expected_head_sha: str | None,
    trusted_ingress_sources: Collection[str],
    now: str,
) -> ApprovalValidation:
    """Validate one structured human approval against one exact effect target."""

    required_fields = {
        "approval_id": approval.approval_id,
        "approval_policy_id": approval.approval_policy_id,
        "controller_task_id": approval.controller_task_id,
        "operation_id": approval.operation_id,
        "requested_capability": approval.requested_capability,
        "effect": approval.effect,
        "target_kind": approval.target_kind,
        "issuer_kind": approval.issuer_kind,
        "issuer_subject": approval.issuer_subject,
        "ingress_source": approval.ingress_source,
        "issued_at": approval.issued_at,
    }
    for field_name, value in required_fields.items():
        if not isinstance(value, str) or not value:
            return ApprovalValidation(False, ApprovalResult.BLOCKED, f"APPROVAL_FIELD_MISSING:{field_name}", approval.approval_id or None)

    if approval.issuer_kind != "HUMAN":
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "ISSUER_NOT_HUMAN", approval.approval_id)
    if approval.ingress_source not in trusted_ingress_sources:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "INGRESS_NOT_TRUSTED", approval.approval_id)
    if approval.approval_policy_id != task.approval_policy_id:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "POLICY_MISMATCH", approval.approval_id)
    if approval.controller_task_id != task.controller_task_id:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "CONTROLLER_TASK_ID_MISMATCH", approval.approval_id)
    if approval.operation_id != task.operation_id:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "OPERATION_ID_MISMATCH", approval.approval_id)
    if approval.provider is not None and approval.provider != task.provider:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "PROVIDER_MISMATCH", approval.approval_id)
    if approval.requested_capability != task.requested_capability:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "CAPABILITY_MISMATCH", approval.approval_id)
    if approval.effect != expected_effect:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "EFFECT_MISMATCH", approval.approval_id)
    if expected_effect not in task.allowed_effects:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "EFFECT_NOT_ALLOWED_BY_TASK", approval.approval_id)
    if expected_effect in task.forbidden_effects:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "EFFECT_FORBIDDEN_BY_TASK", approval.approval_id)
    if approval.repo != task.repo:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "REPO_MISMATCH", approval.approval_id)
    if approval.target_kind != expected_target_kind:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "TARGET_KIND_MISMATCH", approval.approval_id)
    if approval.target_id != expected_target_id:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "TARGET_ID_MISMATCH", approval.approval_id)
    if approval.expected_head_sha != expected_head_sha:
        return ApprovalValidation(False, ApprovalResult.STALE, "HEAD_SHA_MISMATCH", approval.approval_id)

    try:
        issued_at = _parse_time(approval.issued_at)
        now_at = _parse_time(now)
        expires_at = _parse_time(approval.expires_at) if approval.expires_at is not None else None
    except (TypeError, ValueError):
        return ApprovalValidation(False, ApprovalResult.UNCERTAIN, "APPROVAL_TIME_INVALID", approval.approval_id)

    if expires_at is not None and expires_at <= issued_at:
        return ApprovalValidation(False, ApprovalResult.UNCERTAIN, "APPROVAL_TIME_ORDER_INVALID", approval.approval_id)
    if issued_at > now_at:
        return ApprovalValidation(False, ApprovalResult.UNCERTAIN, "APPROVAL_FROM_FUTURE", approval.approval_id)
    if expires_at is not None and now_at >= expires_at:
        return ApprovalValidation(False, ApprovalResult.BLOCKED, "APPROVAL_EXPIRED", approval.approval_id)

    return ApprovalValidation(True, ApprovalResult.PASS, approval_id=approval.approval_id)
