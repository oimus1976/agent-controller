import json
import os
import tempfile
import hashlib
import shutil
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

class ReconcilerLock:
    def __init__(self, lock_file):
        self.lock_file = lock_file
        self.fd = None

    def acquire(self):
        try:
            self.fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            return True
        except FileExistsError:
            return False

    def release(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            try:
                os.remove(self.lock_file)
            except OSError:
                pass
            self.fd = None

def reconcile_pr_once(owner, repo, pr_number, state_file=".pr_state.json", policy_file=None, receipts_file=".action_receipts.json", apply=False):
    target_id = f"{owner}/{repo}#{pr_number}"
    target_hash = hashlib.sha256(target_id.encode('utf-8')).hexdigest()
    lock_file = os.path.join(tempfile.gettempdir(), f"agent_controller_pr_{target_hash}.lock")
    lock = ReconcilerLock(lock_file)

    if not lock.acquire():
        return {
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
            "observation": None,
            "transition_occurred": False,
            "transition_reasons": [],
            "is_relevant_transition": False,
            "action_plan": {
                "repo": f"{owner}/{repo}",
                "pr": pr_number,
                "requested_action": "ENSURE_DRAFT",
                "decision": "BLOCKED",
                "reason": "CONCURRENT_RECONCILIATION",
                "policy_provenance": None,
                "head_sha": None,
                "draft": None
            },
            "apply": apply,
            "execution_result": None,
            "postcondition_result": None,
            "action_receipt": None
        }

    try:
        had_prior_baseline = False
        prior_state_corrupt = False
        target_mismatch = False
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and data:
                        had_prior_baseline = True
                        if "repo" not in data or data["repo"] != f"{owner}/{repo}":
                            target_mismatch = True
                        if "pr" not in data or data["pr"] != pr_number:
                            target_mismatch = True
                    else:
                        prior_state_corrupt = True
            except Exception:
                prior_state_corrupt = True

        if prior_state_corrupt:
            return {
                "repo": f"{owner}/{repo}",
                "pr": pr_number,
                "observation": None,
                "transition_occurred": False,
                "transition_reasons": [],
                "is_relevant_transition": False,
                "action_plan": {
                    "repo": f"{owner}/{repo}",
                    "pr": pr_number,
                    "requested_action": "ENSURE_DRAFT",
                    "decision": "BLOCKED",
                    "reason": "PRIOR_STATE_CORRUPT",
                    "policy_provenance": None,
                    "head_sha": None,
                    "draft": None
                },
                "apply": apply,
                "execution_result": None,
                "postcondition_result": None,
                "action_receipt": None
            }

        if target_mismatch:
             return {
                "repo": f"{owner}/{repo}",
                "pr": pr_number,
                "observation": None,
                "transition_occurred": False,
                "transition_reasons": [],
                "is_relevant_transition": False,
                "action_plan": {
                    "repo": f"{owner}/{repo}",
                    "pr": pr_number,
                    "requested_action": "ENSURE_DRAFT",
                    "decision": "BLOCKED",
                    "reason": "TARGET_MISMATCH",
                    "policy_provenance": None,
                    "head_sha": None,
                    "draft": None
                },
                "apply": apply,
                "execution_result": None,
                "postcondition_result": None,
                "action_receipt": None
            }

        receipts, receipts_corrupt = _load_receipts(receipts_file)

        scope_policy = None
        if policy_file and os.path.exists(policy_file):
            try:
                with open(policy_file, 'r') as f:
                    scope_policy = json.load(f)
            except Exception:
                pass

        temp_state_file = state_file + ".tmp"
        if os.path.exists(state_file):
            shutil.copy2(state_file, temp_state_file)
        elif os.path.exists(temp_state_file):
            os.remove(temp_state_file)

        try:
            observation = watch_pr_once(owner, repo, pr_number, temp_state_file, scope_policy=scope_policy)
        except Exception as e:
            if os.path.exists(temp_state_file):
                os.remove(temp_state_file)
            raise e

        transition_occurred = observation.get("transition", False)
        transition_reasons = observation.get("transition_reasons", [])
        runtime_status = observation.get("runtime_status", "UNKNOWN")

        is_relevant_transition = False
        plan = None
        execution_result = None
        postcondition_result = None
        action_receipt = None
        consume_transition = False

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
        elif "PRIOR_STATE_CORRUPT" in transition_reasons:
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
            consume_transition = True
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
            consume_transition = True
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
                consume_transition = True
            else:
                plan = plan_action(owner, repo, pr_number, "ENSURE_DRAFT", policy_file)

                if plan.get("decision") == "EXECUTABLE":
                    is_relevant_transition = True
                    execution_result = execute_action(plan, owner, repo, pr_number, apply=apply)
                    postcondition_result = execution_result.get("postcondition_result")

                    if execution_result.get("final_outcome") == "NOOP" and execution_result.get("failure_reason") == "ALREADY_DRAFT":
                        consume_transition = True
                    elif apply and execution_result.get("final_outcome") == "SUCCESS" and postcondition_result is True:
                        action_receipt = {
                            "repo": f"{owner}/{repo}",
                            "pr": pr_number,
                            "head_sha": execution_result.get("execution_head_sha") or current_head_sha,
                            "transition_reasons": transition_reasons,
                            "action": "ENSURE_DRAFT",
                            "outcome": "SUCCESS",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        consume_transition = True
                elif plan.get("decision") == "NOOP" and plan.get("reason") == "ALREADY_DRAFT":
                    consume_transition = True

        # FINALIZATION ORDER: 1. Mutation 2. Save Receipt 3. Promote State
        receipt_save_success = True
        if consume_transition and action_receipt:
            try:
                _save_receipt(receipts_file, action_receipt)
            except Exception:
                receipt_save_success = False

        state_promotion_success = False
        if consume_transition and receipt_save_success and os.path.exists(temp_state_file):
            try:
                with open(temp_state_file, 'r') as f:
                    state_data = json.load(f)
                state_data["repo"] = f"{owner}/{repo}"
                state_data["pr"] = pr_number

                dir_name = os.path.dirname(os.path.abspath(state_file)) or "."
                fd, atomic_tmp = tempfile.mkstemp(dir=dir_name)
                try:
                    with os.fdopen(fd, 'w') as f:
                        json.dump(state_data, f)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(atomic_tmp, state_file)
                    state_promotion_success = True
                except Exception as e:
                    if os.path.exists(atomic_tmp):
                        os.remove(atomic_tmp)
                    raise e
            except Exception as e:
                state_promotion_success = False
        else:
            state_promotion_success = True

        if consume_transition:
            if not receipt_save_success:
                plan = {
                    "repo": f"{owner}/{repo}",
                    "pr": pr_number,
                    "requested_action": "ENSURE_DRAFT",
                    "decision": "BLOCKED",
                    "reason": "RECEIPT_PERSISTENCE_FAILED",
                    "policy_provenance": plan.get("policy_provenance") if plan else None,
                    "head_sha": plan.get("head_sha") if plan else None,
                    "draft": plan.get("draft") if plan else None
                }
                if execution_result:
                    execution_result["final_outcome"] = "FAILED"
                    execution_result["failure_reason"] = "RECEIPT_PERSISTENCE_FAILED"
                action_receipt = None
            elif not state_promotion_success:
                plan = {
                    "repo": f"{owner}/{repo}",
                    "pr": pr_number,
                    "requested_action": "ENSURE_DRAFT",
                    "decision": "BLOCKED",
                    "reason": "STATE_PROMOTION_FAILED",
                    "policy_provenance": plan.get("policy_provenance") if plan else None,
                    "head_sha": plan.get("head_sha") if plan else None,
                    "draft": plan.get("draft") if plan else None
                }
                if execution_result:
                    execution_result["final_outcome"] = "FAILED"
                    execution_result["failure_reason"] = "STATE_PROMOTION_FAILED"

        if os.path.exists(temp_state_file):
            try:
                os.remove(temp_state_file)
            except Exception:
                pass

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
    finally:
        lock.release()
