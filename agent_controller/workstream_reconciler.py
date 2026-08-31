from __future__ import annotations

from typing import Any, Sequence

from agent_controller.reconciler import reconcile_pr_once
from agent_controller.workstream import (
    WorkstreamBinding,
    validate_pr_workstream,
    validate_workstream_set,
)


def _blocked_result(
    repo: str,
    pr: int,
    *,
    reason: str,
    apply: bool,
    workstream_id: str | None = None,
) -> dict[str, Any]:
    return {
        "repo": repo,
        "pr": pr,
        "workstream_id": workstream_id,
        "observation": None,
        "transition_occurred": False,
        "transition_reasons": [],
        "is_relevant_transition": False,
        "action_plan": {
            "repo": repo,
            "pr": pr,
            "requested_action": "ENSURE_DRAFT",
            "decision": "BLOCKED",
            "reason": reason,
            "policy_provenance": None,
            "head_sha": None,
            "draft": None,
        },
        "apply": apply,
        "execution_result": None,
        "postcondition_result": None,
        "action_receipt": None,
    }


def reconcile_workstream_pr_once(
    owner: str,
    repo: str,
    pr_number: int,
    *,
    workstream_binding: WorkstreamBinding,
    state_file: str = ".pr_state.json",
    policy_file: str | None = None,
    receipts_file: str = ".action_receipts.json",
    apply: bool = False,
) -> dict[str, Any]:
    """Run the existing PR reconciler only after exact lane ownership is proven.

    This is the single-binding composition boundary. Concurrent orchestration
    should prefer `reconcile_active_workstream_pr_once`, which first validates
    the complete active binding set for overlapping ownership.
    """

    target_repo = f"{owner}/{repo}"
    if not isinstance(workstream_binding, WorkstreamBinding):
        return _blocked_result(
            target_repo,
            pr_number,
            reason="WORKSTREAM_BINDING_REQUIRED",
            apply=apply,
        )

    validation = validate_pr_workstream(
        binding=workstream_binding,
        repo=target_repo,
        pr=pr_number,
    )
    if not validation.valid:
        return _blocked_result(
            target_repo,
            pr_number,
            reason=validation.reason or "WORKSTREAM_TARGET_UNCERTAIN",
            apply=apply,
            workstream_id=workstream_binding.workstream_id,
        )

    result = reconcile_pr_once(
        owner,
        repo,
        pr_number,
        state_file=state_file,
        policy_file=policy_file,
        receipts_file=receipts_file,
        apply=apply,
    )
    result = dict(result)
    result["workstream_id"] = workstream_binding.workstream_id
    return result


def reconcile_active_workstream_pr_once(
    owner: str,
    repo: str,
    pr_number: int,
    *,
    workstream_id: str,
    bindings: Sequence[WorkstreamBinding],
    state_file: str = ".pr_state.json",
    policy_file: str | None = None,
    receipts_file: str = ".action_receipts.json",
    apply: bool = False,
) -> dict[str, Any]:
    """Concurrent-lane PR reconciliation with whole-set ownership validation."""

    target_repo = f"{owner}/{repo}"
    set_result = validate_workstream_set(bindings)
    if not set_result.valid:
        return _blocked_result(
            target_repo,
            pr_number,
            reason=set_result.reason or "WORKSTREAM_SET_INVALID",
            apply=apply,
            workstream_id=workstream_id if isinstance(workstream_id, str) else None,
        )
    if not isinstance(workstream_id, str) or not workstream_id:
        return _blocked_result(
            target_repo,
            pr_number,
            reason="WORKSTREAM_ID_REQUIRED",
            apply=apply,
        )

    binding = next(
        (candidate for candidate in bindings if candidate.workstream_id == workstream_id),
        None,
    )
    if binding is None:
        return _blocked_result(
            target_repo,
            pr_number,
            reason="UNKNOWN_WORKSTREAM_ID",
            apply=apply,
            workstream_id=workstream_id,
        )

    return reconcile_workstream_pr_once(
        owner,
        repo,
        pr_number,
        workstream_binding=binding,
        state_file=state_file,
        policy_file=policy_file,
        receipts_file=receipts_file,
        apply=apply,
    )
