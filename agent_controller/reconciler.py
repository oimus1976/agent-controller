import json
import os
import tempfile
from datetime import datetime, timezone
from .watcher import watch_pr_once
from .executor import plan_action, execute_action

def _load_receipts(receipts_file):
    if not receipts_file or not os.path.exists(receipts_file):
        return [], False
    try:
        with open(receipts_file, 'r') as f:
            data = json.load(f)
            if not isinstance(data, list):
                return [], True
            return data, False
    except Exception:
        return [], True

def _save_receipt(receipts_file, new_receipt):
    receipts = []
    if os.path.exists(receipts_file):
        try:
            with open(receipts_file, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    receipts = data
        except Exception:
            receipts = []

    receipts.append(new_receipt)

    dir_name = os.path.dirname(os.path.abspath(receipts_file)) if receipts_file else ""
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".")
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(receipts, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, receipts_file)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e

def reconcile_pr_once(owner, repo, pr_number, state_file=".pr_state.json", policy_file=None, receipts_file=".action_receipts.json", apply=False):
    """
    Performs a single deterministic reconciliation cycle:
    observe current PR -> compare baseline -> detect transition -> plan action -> policy gate -> optional apply -> verify postcondition -> persist receipt safely.
    """
    had_prior_baseline = False
    prior_state_corrupt = False
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict) and data:
                    had_prior_baseline = True
                else:
                    prior_state_corrupt = True
        except Exception:
            prior_state_corrupt = True

    receipts, receipts_corrupt = _load_receipts(receipts_file)

    scope_policy = None
    if policy_file and os.path.exists(policy_file):
        try:
            with open(policy_file, 'r') as f:
                scope_policy = json.load(f)
        except Exception:
            pass

    observation = watch_pr_once(owner, repo, pr_number, state_file, scope_policy=scope_policy)

    transition_occurred = observation.get("transition", False)
    transition_reasons = observation.get("transition_reasons", [])
    runtime_status = observation.get("runtime_status", "UNKNOWN")

    is_relevant_transition = False
    plan = None
    execution_result = None
    postcondition_result = None
    action_receipt = None

    if runtime_status != "OK":
        plan = {
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
            "requested_action": "ENSURE_DRAFT",
            "decision": "BLOCKED",
            "reason": f"EVIDENCE_UNAVAILABLE: {observation.get('error_reason', 'Observation error')}",
            "policy_provenance": None,
            "head_sha": None,
            "draft": None
        }
    elif prior_state_corrupt or "PRIOR_STATE_CORRUPT" in transition_reasons:
        plan = {
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
            "requested_action": "ENSURE_DRAFT",
            "decision": "BLOCKED",
            "reason": "PRIOR_STATE_CORRUPT",
            "policy_provenance": None,
            "head_sha": observation.get("current_head_sha"),
            "draft": None
        }
    elif receipts_corrupt:
        plan = {
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
            "requested_action": "ENSURE_DRAFT",
            "decision": "BLOCKED",
            "reason": "CORRUPT_RECEIPTS_FILE",
            "policy_provenance": None,
            "head_sha": observation.get("current_head_sha"),
            "draft": None
        }
    elif not had_prior_baseline:
        plan = {
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
            "requested_action": "ENSURE_DRAFT",
            "decision": "NO_ACTION",
            "reason": "BASELINE_ESTABLISHED",
            "policy_provenance": None,
            "head_sha": observation.get("current_head_sha"),
            "draft": None
        }
    elif not transition_occurred:
        plan = {
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
            "requested_action": "ENSURE_DRAFT",
            "decision": "NO_ACTION",
            "reason": "NO_TRANSITION_DETECTED",
            "policy_provenance": None,
            "head_sha": observation.get("current_head_sha"),
            "draft": None
        }
    else:
        current_head_sha = observation.get("current_head_sha")
        is_duplicate = False
        for r in receipts:
            if (r.get("repo") == f"{owner}/{repo}" and
                r.get("pr") == pr_number and
                r.get("head_sha") == current_head_sha and
                r.get("transition_reasons") == transition_reasons and
                r.get("action") == "ENSURE_DRAFT" and
                r.get("outcome") == "SUCCESS"):
                is_duplicate = True
                break

        if is_duplicate:
            plan = {
                "repo": f"{owner}/{repo}",
                "pr": pr_number,
                "requested_action": "ENSURE_DRAFT",
                "decision": "NO_ACTION",
                "reason": "DUPLICATE_TRANSITION_CONSUMED",
                "policy_provenance": None,
                "head_sha": current_head_sha,
                "draft": None
            }
        else:
            plan = plan_action(owner, repo, pr_number, "ENSURE_DRAFT", policy_file)

            if plan.get("decision") == "EXECUTABLE":
                is_relevant_transition = True
                execution_result = execute_action(plan, owner, repo, pr_number, apply=apply)
                postcondition_result = execution_result.get("postcondition_result")

                if apply and execution_result.get("final_outcome") == "SUCCESS" and postcondition_result is True:
                    action_receipt = {
                        "repo": f"{owner}/{repo}",
                        "pr": pr_number,
                        "head_sha": execution_result.get("execution_head_sha") or current_head_sha,
                        "transition_reasons": transition_reasons,
                        "action": "ENSURE_DRAFT",
                        "outcome": "SUCCESS",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    _save_receipt(receipts_file, action_receipt)

    return {
        "repo": f"{owner}/{repo}",
        "pr": pr_number,
        "observation": observation,
        "transition_occurred": transition_occurred,
        "transition_reasons": transition_reasons,
        "is_relevant_transition": is_relevant_transition,
        "action_plan": plan,
        "apply": apply,
        "execution_result": execution_result,
        "postcondition_result": postcondition_result,
        "action_receipt": action_receipt
    }
