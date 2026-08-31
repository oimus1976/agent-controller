from __future__ import annotations

from typing import Any

from agent_controller.reconciler import reconcile_pr_once
from agent_controller.workstream import WorkstreamBinding, validate_pr_workstream


def _blocked_result(repo: str, pr: int, *, reason: str, apply: bool) -> dict[str, Any]:
    return {
        "repo": repo,
        "pr": pr,
        "workstream_id": None,
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

    This is the mutation-capable entry point for lane-aware orchestration. The
    historical reconciler remains for compatibility, but a concurrent/lane-aware
    caller must enter here and cannot silently proceed without a valid binding.

    Membership is checked before watcher, planner, executor, or mutator work.
    Once accepted, the existing reconciler retains its own exact repo/PR state,
    head-freshness, policy, receipt, and postcondition checks for that fixed
    target.
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
