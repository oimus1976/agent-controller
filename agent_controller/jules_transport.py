import json
import os
import urllib.request
import urllib.error
import hashlib
import tempfile
import time
from datetime import datetime, timezone

JULES_API_BASE = "https://jules.googleapis.com/v1alpha"

VALID_JULES_STATES = {
    "QUEUED",
    "PLANNING",
    "AWAITING_PLAN_APPROVAL",
    "AWAITING_USER_FEEDBACK",
    "IN_PROGRESS",
    "PAUSED",
    "COMPLETED",
    "FAILED"
}

def _get_jules_api_key(env_var="JULES_API_KEY"):
    api_key = os.environ.get(env_var)
    if not api_key:
        return None
    return api_key.strip()

def _jules_api_request(endpoint, method="GET", body=None, api_key_env="JULES_API_KEY"):
    api_key = _get_jules_api_key(api_key_env)
    if not api_key:
        raise ValueError("JULES_API_KEY_MISSING")

    url = f"{JULES_API_BASE}/{endpoint.lstrip('/')}"
    req = urllib.request.Request(url, method=method)
    req.add_header("x-goog-api-key", api_key)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    data = None
    if body is not None:
        data = json.dumps(body).encode('utf-8')

    try:
        with urllib.request.urlopen(req, data=data) as response:
            res_body = response.read().decode('utf-8')
            if not res_body.strip():
                return {}
            return json.loads(res_body)
    except urllib.error.HTTPError as e:
        err_msg = f"Jules API Error: {e.code} {e.reason}"
        raise Exception(err_msg)
    except urllib.error.URLError as e:
        raise Exception("Jules Transport URL Error")

def _github_api_request(url):
    req = urllib.request.Request(url)
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        raise Exception(f"GitHub API Error: {e.code} {e.reason} for URL {url}")

def get_github_branch_head(owner, repo, branch):
    url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}"
    data = _github_api_request(url)
    head_sha = data.get("commit", {}).get("sha")
    return head_sha

def verify_github_starting_branch(owner, repo, branch, expected_starting_sha):
    actual_sha = get_github_branch_head(owner, repo, branch)
    if not actual_sha or actual_sha != expected_starting_sha:
        return False, actual_sha
    return True, actual_sha

def _load_jules_state(state_file):
    if not state_file or not os.path.exists(state_file):
        return None, False
    try:
        with open(state_file, 'r') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return None, True
            return data, False
    except Exception:
        return None, True

def _save_jules_state(state_file, state_data):
    dir_name = os.path.dirname(os.path.abspath(state_file)) if state_file else "."
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".")
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(state_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, state_file)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e

def jules_start(task_id, owner, repo, source, starting_branch, expected_starting_sha, prompt,
                state_file=".jules_state.json", require_plan_approval=True, api_key_env="JULES_API_KEY"):
    # 1. Check API key requirement before any action
    if not _get_jules_api_key(api_key_env):
        return {
            "status": "BLOCKED",
            "reason": "JULES_API_KEY_MISSING",
            "session": None
        }

    # 2. Check local state for idempotency / target mismatch / corruption
    existing_state, corrupt = _load_jules_state(state_file)
    if corrupt:
        return {
            "status": "BLOCKED",
            "reason": "CORRUPT_STATE_FILE",
            "session": None
        }

    if existing_state:
        # Check target mismatch
        if (existing_state.get("task_id") == task_id and
            existing_state.get("repo") == f"{owner}/{repo}" and
            existing_state.get("starting_branch") == starting_branch and
            existing_state.get("expected_starting_sha") == expected_starting_sha and
            existing_state.get("session_id")):
            # Session already created for this task/target -> idempotent return
            return {
                "status": "EXISTS",
                "reason": "SESSION_ALREADY_EXISTS",
                "session": existing_state
            }
        elif existing_state.get("task_id") != task_id or existing_state.get("repo") != f"{owner}/{repo}":
            return {
                "status": "BLOCKED",
                "reason": "TARGET_MISMATCH",
                "session": None
            }

    # 3. Verify starting branch SHA on GitHub independently
    try:
        valid_sha, actual_sha = verify_github_starting_branch(owner, repo, starting_branch, expected_starting_sha)
        if not valid_sha:
            return {
                "status": "BLOCKED",
                "reason": f"STARTING_SHA_MISMATCH (expected {expected_starting_sha}, got {actual_sha})",
                "session": None
            }
    except Exception as e:
        return {
            "status": "BLOCKED",
            "reason": f"GITHUB_BRANCH_VERIFICATION_FAILED: {str(e)}",
            "session": None
        }

    # 4. Create Jules session via REST API
    payload = {
        "source": source,
        "startingBranch": starting_branch,
        "prompt": prompt,
        "requirePlanApproval": require_plan_approval
    }

    try:
        res = _jules_api_request("sessions", method="POST", body=payload, api_key_env=api_key_env)
    except ValueError as e:
        return {
            "status": "BLOCKED",
            "reason": str(e),
            "session": None
        }
    except Exception as e:
        return {
            "status": "BLOCKED",
            "reason": f"JULES_API_CREATE_FAILED: {str(e)}",
            "session": None
        }

    session_name = res.get("name") or res.get("id") or f"sessions/{res.get('sessionId', 'unknown')}"
    session_id = session_name.split('/')[-1] if '/' in session_name else session_name
    initial_state = res.get("state", "QUEUED")

    if initial_state not in VALID_JULES_STATES:
        return {
            "status": "BLOCKED",
            "reason": f"UNKNOWN_JULES_STATE: {initial_state}",
            "session": None
        }

    state_data = {
        "task_id": task_id,
        "repo": f"{owner}/{repo}",
        "source": source,
        "starting_branch": starting_branch,
        "expected_starting_sha": expected_starting_sha,
        "session_id": session_id,
        "session_name": session_name,
        "session_url": res.get("url"),
        "require_plan_approval": require_plan_approval,
        "current_state": initial_state,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sent_messages": [],
        "plan_approved": False,
        "outputs": res.get("outputs", []),
        "handoff_result": None
    }

    _save_jules_state(state_file, state_data)

    return {
        "status": "SUCCESS",
        "reason": "SESSION_CREATED",
        "session": state_data
    }

def jules_status(state_file=".jules_state.json", api_key_env="JULES_API_KEY"):
    if not _get_jules_api_key(api_key_env):
        return {
            "status": "BLOCKED",
            "reason": "JULES_API_KEY_MISSING",
            "session": None
        }

    state_data, corrupt = _load_jules_state(state_file)
    if corrupt or not state_data:
        return {
            "status": "BLOCKED",
            "reason": "STATE_FILE_NOT_FOUND_OR_CORRUPT",
            "session": None
        }

    session_name = state_data.get("session_name") or f"sessions/{state_data.get('session_id')}"

    try:
        res = _jules_api_request(session_name, method="GET", api_key_env=api_key_env)
    except ValueError as e:
        return {
            "status": "BLOCKED",
            "reason": str(e),
            "session": state_data
        }
    except Exception as e:
        return {
            "status": "BLOCKED",
            "reason": f"JULES_API_STATUS_FAILED: {str(e)}",
            "session": state_data
        }

    new_state = res.get("state")
    if not new_state or new_state not in VALID_JULES_STATES:
        return {
            "status": "BLOCKED",
            "reason": f"UNKNOWN_JULES_STATE: {new_state}",
            "session": state_data
        }

    state_data["current_state"] = new_state
    state_data["last_updated"] = datetime.now(timezone.utc).isoformat()
    if "outputs" in res:
        state_data["outputs"] = res.get("outputs")

    _save_jules_state(state_file, state_data)

    return {
        "status": "OK",
        "reason": "STATUS_UPDATED",
        "session": state_data
    }

def jules_approve_plan(state_file=".jules_state.json", api_key_env="JULES_API_KEY"):
    if not _get_jules_api_key(api_key_env):
        return {
            "status": "BLOCKED",
            "reason": "JULES_API_KEY_MISSING",
            "session": None
        }

    state_data, corrupt = _load_jules_state(state_file)
    if corrupt or not state_data:
        return {
            "status": "BLOCKED",
            "reason": "STATE_FILE_NOT_FOUND_OR_CORRUPT",
            "session": None
        }

    # Idempotency check: if plan already approved
    if state_data.get("plan_approved"):
        return {
            "status": "EXISTS",
            "reason": "PLAN_ALREADY_APPROVED",
            "session": state_data
        }

    session_name = state_data.get("session_name") or f"sessions/{state_data.get('session_id')}"
    endpoint = f"{session_name}:approvePlan"

    try:
        res = _jules_api_request(endpoint, method="POST", body={}, api_key_env=api_key_env)
    except ValueError as e:
        return {
            "status": "BLOCKED",
            "reason": str(e),
            "session": state_data
        }
    except Exception as e:
        return {
            "status": "BLOCKED",
            "reason": f"JULES_API_APPROVE_FAILED: {str(e)}",
            "session": state_data
        }

    state_data["plan_approved"] = True
    state_data["plan_approval_timestamp"] = datetime.now(timezone.utc).isoformat()

    if isinstance(res, dict) and "state" in res:
        new_state = res.get("state")
        if new_state in VALID_JULES_STATES:
            state_data["current_state"] = new_state

    _save_jules_state(state_file, state_data)

    return {
        "status": "SUCCESS",
        "reason": "PLAN_APPROVED",
        "session": state_data
    }

def jules_send(message, state_file=".jules_state.json", api_key_env="JULES_API_KEY"):
    if not _get_jules_api_key(api_key_env):
        return {
            "status": "BLOCKED",
            "reason": "JULES_API_KEY_MISSING",
            "session": None
        }

    state_data, corrupt = _load_jules_state(state_file)
    if corrupt or not state_data:
        return {
            "status": "BLOCKED",
            "reason": "STATE_FILE_NOT_FOUND_OR_CORRUPT",
            "session": None
        }

    # Hash message for receipt idempotency without secret content
    msg_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
    sent_messages = state_data.get("sent_messages", [])

    for receipt in sent_messages:
        if receipt.get("message_hash") == msg_hash and receipt.get("status") == "SUCCESS":
            return {
                "status": "EXISTS",
                "reason": "MESSAGE_ALREADY_SENT",
                "session": state_data
            }

    session_name = state_data.get("session_name") or f"sessions/{state_data.get('session_id')}"
    endpoint = f"{session_name}:sendMessage"
    payload = {"message": message}

    try:
        res = _jules_api_request(endpoint, method="POST", body=payload, api_key_env=api_key_env)
    except ValueError as e:
        return {
            "status": "BLOCKED",
            "reason": str(e),
            "session": state_data
        }
    except Exception as e:
        return {
            "status": "BLOCKED",
            "reason": f"JULES_API_SEND_FAILED: {str(e)}",
            "session": state_data
        }

    new_receipt = {
        "message_hash": msg_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "SUCCESS"
    }
    sent_messages.append(new_receipt)
    state_data["sent_messages"] = sent_messages

    if isinstance(res, dict) and "state" in res:
        new_state = res.get("state")
        if new_state in VALID_JULES_STATES:
            state_data["current_state"] = new_state

    _save_jules_state(state_file, state_data)

    return {
        "status": "SUCCESS",
        "reason": "MESSAGE_SENT",
        "session": state_data
    }

def jules_wait(state_file=".jules_state.json", interval=5, max_attempts=10, clock=time.time, sleeper=time.sleep, api_key_env="JULES_API_KEY"):
    attempts = 0

    while attempts < max_attempts:
        status_res = jules_status(state_file, api_key_env=api_key_env)
        if status_res.get("status") == "BLOCKED":
            return status_res

        session_data = status_res.get("session", {})
        current_state = session_data.get("current_state")

        if current_state in {"COMPLETED", "FAILED", "AWAITING_PLAN_APPROVAL", "AWAITING_USER_FEEDBACK", "PAUSED"}:
            return status_res

        attempts += 1
        if attempts < max_attempts and sleeper:
            sleeper(interval)

    return {
        "status": "TIMEOUT",
        "reason": f"WAIT_MAX_ATTEMPTS_EXCEEDED ({max_attempts} attempts)",
        "session": session_data if 'session_data' in locals() else None
    }

def verify_github_artifact(owner, repo, target_branch, expected_starting_sha, allowed_paths=None, pr_number=None):
    """
    Independent GitHub verification step.
    Verifies that publication occurred on GitHub matching objective bounds.
    """
    # 1. Fetch branch head SHA
    try:
        head_sha = get_github_branch_head(owner, repo, target_branch)
    except Exception as e:
        return {
            "verified": False,
            "reason": f"BRANCH_FETCH_FAILED: {str(e)}",
            "head_sha": None
        }

    if not head_sha:
        return {
            "verified": False,
            "reason": "GITHUB_BRANCH_NOT_FOUND",
            "head_sha": None
        }

    # 2. Check if head SHA has moved from starting SHA
    if head_sha == expected_starting_sha:
        return {
            "verified": False,
            "reason": "GITHUB_ARTIFACT_NOT_PUBLISHED",
            "head_sha": head_sha
        }

    # 3. Check commit ancestry / compare starting_sha with head_sha
    compare_url = f"https://api.github.com/repos/{owner}/{repo}/compare/{expected_starting_sha}...{head_sha}"
    try:
        compare_data = _github_api_request(compare_url)
    except Exception as e:
        return {
            "verified": False,
            "reason": f"ANCESTRY_CHECK_FAILED: {str(e)}",
            "head_sha": head_sha
        }

    status = compare_data.get("status") # e.g. "ahead", "identical"
    if status not in {"ahead", "identical"}:
        return {
            "verified": False,
            "reason": f"INVALID_COMMIT_ANCESTRY: compare status is '{status}'",
            "head_sha": head_sha
        }

    # 4. Check changed file allowlist if provided
    files = compare_data.get("files", [])
    if allowed_paths is not None:
        import fnmatch
        for f in files:
            filename = f.get("filename", "")
            matched = False
            for pattern in allowed_paths:
                if fnmatch.fnmatch(filename, pattern):
                    matched = True
                    break
            if not matched:
                return {
                    "verified": False,
                    "reason": f"FILE_NOT_ALLOWLISTED: {filename}",
                    "head_sha": head_sha
                }

    # 5. Verify PR identity if expected
    pr_details = None
    if pr_number is not None:
        pr_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
        try:
            pr_details = _github_api_request(pr_url)
            pr_head_sha = pr_details.get("head", {}).get("sha")
            if pr_head_sha != head_sha:
                return {
                    "verified": False,
                    "reason": f"PR_HEAD_SHA_MISMATCH (PR head is {pr_head_sha}, branch head is {head_sha})",
                    "head_sha": head_sha
                }
        except Exception as e:
            return {
                "verified": False,
                "reason": f"PR_VERIFICATION_FAILED: {str(e)}",
                "head_sha": head_sha
            }

    return {
        "verified": True,
        "reason": "VERIFIED_SUCCESSFULLY",
        "head_sha": head_sha,
        "changed_files_count": len(files),
        "pr_number": pr_number
    }
