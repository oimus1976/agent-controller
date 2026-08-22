import json
import os
from .inspector import get_pr_details, _github_graphql_request

def load_policy(policy_path):
    if not policy_path or not os.path.exists(policy_path):
        return None
    try:
        with open(policy_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
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

def execute_action(plan, owner, repo, pr_number, apply=False):
    result = {
        "planned_head_sha": plan.get("head_sha"),
        "execution_head_sha": None,
        "mutation_attempted": False,
        "mutation_type": None,
        "postcondition_result": None,
        "final_outcome": "BLOCKED",
        "failure_reason": None
    }

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
    except Exception as e:
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
    mutation = """
    mutation($prId: ID!) {
      convertPullRequestToDraft(input: {pullRequestId: $prId}) {
        pullRequest {
          isDraft
        }
      }
    }
    """

    result["mutation_attempted"] = True
    result["mutation_type"] = "ENSURE_DRAFT"

    try:
        _github_graphql_request(mutation, {"prId": node_id})
    except Exception as e:
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
    except Exception as e:
        result["postcondition_result"] = None
        result["failure_reason"] = "POSTCONDITION_VERIFICATION_FETCH_FAILED"
        result["final_outcome"] = "FAILED"

    return result
