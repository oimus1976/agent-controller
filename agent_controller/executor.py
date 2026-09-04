import json
import os
from .inspector import get_pr_details
from .mutator import convert_pull_request_to_draft
from .workstream import WorkstreamBinding, validate_pr_workstream


def load_policy(policy_path):
    if not policy_path or not os.path.exists(policy_path):
        return None
    try:
        with open(policy_path, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError, UnicodeDecodeError):
        return None


def plan_action(owner, repo, pr_number, action, policy_path):
    plan = {
        "repo": f"{owner}/{repo}",
        "pr": pr_number,
        "requested_action": action,
        "decision": "BLOCKED",
        "reason": None,
        "policy_provenance": None,
        "head_sha": None,
        "draft": None
    }

    policy = load_policy(policy_path)
    if not policy:
        plan["reason"] = "MISSING_OR_MALFORMED_POLICY"
        return plan

    plan["policy_provenance"] = policy

    allowed_actions = policy.get("allowed_actions")
    if not isinstance(allowed_actions, list) or action not in allowed_actions:
        plan["reason"] = "ACTION_NOT_ALLOWLISTED"
        return plan

    try:
        pr_data = get_pr_details(owner, repo, pr_number)
    except Exception as e:
        plan["reason"] = f"EVIDENCE_FETCH_FAILED: {str(e)}"
        return plan

    head_sha = pr_data.get('head', {}).get('sha')
    is_draft = pr_data.get('draft')
    is_merged = pr_data.get('merged')
    state = pr_data.get('state')

    plan["head_sha"] = head_sha
    plan["draft"] = is_draft

    if head_sha is None or is_draft is None or is_merged is None or state is None:
        plan["reason"] = "CONTRADICTORY_OR_MISSING_EVIDENCE"
        return plan

    if state == "closed" or is_merged:
        plan["reason"] = "PR_CLOSED_OR_MERGED"
        return plan

    if is_draft:
        plan["decision"] = "NOOP"
        plan["reason"] = "ALREADY_DRAFT"
        return plan

    plan["decision"] = "EXECUTABLE"
    plan["reason"] = "READY_FOR_DRAFT_CONVERSION"
    return plan


def _execution_result(plan):
    return {
        "planned_head_sha": plan.get("head_sha"),
        "execution_head_sha": None,
        "mutation_attempted": False,
        "mutation_type": None,
        "postcondition_result": None,
        "final_outcome": "BLOCKED",
        "failure_reason": None
    }


def execute_action(
    plan,
    owner,
    repo,
    pr_number,
    apply=False,
    workstream_binding=None,
):
    result = _execution_result(plan)

    if plan.get("repo") != f"{owner}/{repo}" or plan.get("pr") != pr_number:
        result["final_outcome"] = "BLOCKED"
        result["failure_reason"] = "TARGET_MISMATCH"
        return result

    if workstream_binding is not None:
        if not isinstance(workstream_binding, WorkstreamBinding):
            result["failure_reason"] = "WORKSTREAM_BINDING_MALFORMED"
            return result
        workstream = validate_pr_workstream(
            binding=workstream_binding,
            repo=f"{owner}/{repo}",
            pr=pr_number,
        )
        if not workstream.valid:
            result["failure_reason"] = workstream.reason
            return result

    if plan.get("decision") == "NOOP":
        result["final_outcome"] = "NOOP"
        result["failure_reason"] = plan.get("reason")
        return result

    if plan.get("decision") != "EXECUTABLE":
        result["final_outcome"] = "BLOCKED"
        result["failure_reason"] = plan.get("reason")
        return result

    if plan.get("requested_action") != "ENSURE_DRAFT":
        result["final_outcome"] = "BLOCKED"
        result["failure_reason"] = "UNKNOWN_ACTION_REQUESTED"
        return result

    if not apply:
        result["final_outcome"] = "DRY_RUN"
        result["failure_reason"] = "APPLY_FLAG_NOT_SET"
        return result

    # 1. Fetch current objective PR evidence immediately before mutation
    try:
        pr_data = get_pr_details(owner, repo, pr_number)
    except Exception:
        result["failure_reason"] = "EVIDENCE_FETCH_FAILED"
        return result

    current_head_sha = pr_data.get('head', {}).get('sha')
    current_draft = pr_data.get('draft')
    current_merged = pr_data.get('merged')
    current_state = pr_data.get('state')

    result["execution_head_sha"] = current_head_sha

    # 2. Check for stale state
    if current_head_sha != plan.get("head_sha"):
        result["failure_reason"] = "STALE_HEAD_SHA"
        return result

    if current_merged or current_state == "closed":
        result["failure_reason"] = "PR_CLOSED_OR_MERGED"
        return result

    if current_draft:
        result["failure_reason"] = "ALREADY_DRAFT"
        result["final_outcome"] = "NOOP"
        return result

    # 3. We need node_id to convert to draft
    node_id = pr_data.get("node_id")
    if not node_id:
        result["failure_reason"] = "MISSING_NODE_ID"
        return result

    # 4. Perform exactly one Draft mutation
    result["mutation_attempted"] = True
    result["mutation_type"] = "ENSURE_DRAFT"

    try:
        convert_pull_request_to_draft(node_id)
    except Exception:
        result["failure_reason"] = "MUTATION_FAILED"
        return result

    # 5. Postcondition verification
    try:
        post_pr_data = get_pr_details(owner, repo, pr_number)
        is_draft = post_pr_data.get("draft")

        if is_draft is True:
            result["postcondition_result"] = True
            result["final_outcome"] = "SUCCESS"
        else:
            result["postcondition_result"] = False
            result["failure_reason"] = "POSTCONDITION_FAILED"
            result["final_outcome"] = "FAILED"
    except Exception:
        result["postcondition_result"] = None
        result["failure_reason"] = "POSTCONDITION_VERIFICATION_FETCH_FAILED"
        result["final_outcome"] = "FAILED"

    return result


def execute_workstream_action(
    plan,
    owner,
    repo,
    pr_number,
    *,
    workstream_binding,
    apply=False,
):
    """Lane-aware mutation boundary.

    Callers choosing this path must supply an explicit WorkstreamBinding. The
    binding is validated before any GitHub evidence re-read or mutation. Legacy
    execute_action remains available for pre-workstream callers, but lane-aware
    orchestration must use this explicit boundary rather than guessing target
    ownership from queue ordering or repository proximity.
    """

    if not isinstance(workstream_binding, WorkstreamBinding):
        result = _execution_result(plan)
        result["failure_reason"] = "WORKSTREAM_BINDING_REQUIRED"
        return result
    return execute_action(
        plan,
        owner,
        repo,
        pr_number,
        apply=apply,
        workstream_binding=workstream_binding,
    )
