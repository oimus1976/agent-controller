from __future__ import annotations

from typing import Mapping, Optional, Protocol, runtime_checkable

from agent_controller.approval_contract import ApprovalReceipt
from agent_controller.execution_contract import ExecutionClaimDecision, ExecutionClaimResult
from agent_controller.execution_store import ExecutionClaimStore
from agent_controller.provider_contract import TaskBinding


@runtime_checkable
class ExecutionTargetReadClient(Protocol):
    def get_target_facts(
        self,
        *,
        repo: Optional[str],
        target_kind: str,
        target_id: Optional[str],
    ) -> Mapping[str, object]:
        ...


def validate_and_claim_execution(
    *,
    receipt: ApprovalReceipt,
    task: TaskBinding,
    expected_effect: str,
    expected_target_kind: str,
    expected_target_id: Optional[str],
    expected_head_sha: Optional[str],
    target_reader: ExecutionTargetReadClient,
    execution_store: ExecutionClaimStore,
    execution_claim_id: str,
    now: str,
) -> ExecutionClaimDecision:
    """Validate a consumed approval receipt and claim one future execution attempt.

    No external effect is executed. A future executor must re-read the remote
    target again immediately before applying any high-impact mutation.
    """

    if not isinstance(receipt, ApprovalReceipt):
        return ExecutionClaimDecision(False, ExecutionClaimResult.UNCERTAIN, "APPROVAL_RECEIPT_INVALID")

    required_strings = {
        "approval_id": receipt.approval_id,
        "approval_policy_id": receipt.approval_policy_id,
        "controller_task_id": receipt.controller_task_id,
        "operation_id": receipt.operation_id,
        "requested_capability": receipt.requested_capability,
        "effect": receipt.effect,
        "target_kind": receipt.target_kind,
        "consumed_at": receipt.consumed_at,
        "receipt_id": receipt.receipt_id,
        "status": receipt.status,
    }
    for name, value in required_strings.items():
        if not isinstance(value, str) or not value:
            return ExecutionClaimDecision(False, ExecutionClaimResult.BLOCKED, f"APPROVAL_RECEIPT_FIELD_MISSING:{name}")

    if receipt.status != "CONSUMED":
        return ExecutionClaimDecision(False, ExecutionClaimResult.BLOCKED, "APPROVAL_RECEIPT_NOT_CONSUMED")

    exact_checks = (
        (receipt.approval_policy_id, task.approval_policy_id, "APPROVAL_POLICY_MISMATCH"),
        (receipt.controller_task_id, task.controller_task_id, "CONTROLLER_TASK_ID_MISMATCH"),
        (receipt.operation_id, task.operation_id, "OPERATION_ID_MISMATCH"),
        (receipt.provider, task.provider, "PROVIDER_MISMATCH"),
        (receipt.requested_capability, task.requested_capability, "CAPABILITY_MISMATCH"),
        (receipt.effect, expected_effect, "EFFECT_MISMATCH"),
        (receipt.repo, task.repo, "REPO_MISMATCH"),
        (receipt.target_kind, expected_target_kind, "TARGET_KIND_MISMATCH"),
        (receipt.target_id, expected_target_id, "TARGET_ID_MISMATCH"),
        (receipt.expected_head_sha, expected_head_sha, "EXPECTED_HEAD_MISMATCH"),
    )
    for actual, expected, reason in exact_checks:
        if actual != expected:
            return ExecutionClaimDecision(False, ExecutionClaimResult.BLOCKED, reason)

    if expected_effect not in task.allowed_effects:
        return ExecutionClaimDecision(False, ExecutionClaimResult.BLOCKED, "EFFECT_NOT_ALLOWED_BY_TASK")
    if expected_effect in task.forbidden_effects:
        return ExecutionClaimDecision(False, ExecutionClaimResult.BLOCKED, "EFFECT_FORBIDDEN_BY_TASK")

    try:
        facts = target_reader.get_target_facts(
            repo=task.repo,
            target_kind=expected_target_kind,
            target_id=expected_target_id,
        )
    except Exception:
        return ExecutionClaimDecision(False, ExecutionClaimResult.UNCERTAIN, "TARGET_READ_UNCERTAIN")

    if not isinstance(facts, Mapping):
        return ExecutionClaimDecision(False, ExecutionClaimResult.UNCERTAIN, "TARGET_FACTS_INVALID")

    required_keys = ["repo", "target_kind", "target_id"]
    if expected_head_sha is not None:
        required_keys.append("head_sha")
    for key in required_keys:
        if key not in facts:
            return ExecutionClaimDecision(False, ExecutionClaimResult.UNCERTAIN, f"TARGET_FACT_MISSING:{key}")

    if facts["repo"] != task.repo:
        return ExecutionClaimDecision(False, ExecutionClaimResult.STALE, "TARGET_REPO_STALE")
    if facts["target_kind"] != expected_target_kind:
        return ExecutionClaimDecision(False, ExecutionClaimResult.STALE, "TARGET_KIND_STALE")
    if facts["target_id"] != expected_target_id:
        return ExecutionClaimDecision(False, ExecutionClaimResult.STALE, "TARGET_ID_STALE")
    if expected_head_sha is not None and facts["head_sha"] != expected_head_sha:
        return ExecutionClaimDecision(False, ExecutionClaimResult.STALE, "TARGET_HEAD_STALE")

    committed = execution_store._claim_validated(
        receipt=receipt,
        execution_claim_id=execution_claim_id,
        claimed_at=now,
    )
    if committed.result is ExecutionClaimResult.PASS:
        return ExecutionClaimDecision(True, committed.result, execution_claim_id=execution_claim_id, claim=committed.claim)

    return ExecutionClaimDecision(
        False,
        committed.result,
        committed.reason,
        execution_claim_id=execution_claim_id,
        claim=committed.claim,
    )
