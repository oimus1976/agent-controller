import json
import os
import tempfile
import time
from datetime import datetime, timezone
from .inspector import inspect_pr

def watch_pr_once(owner, repo, pr_number, state_file, scope_policy=None):
    """
    Performs a deterministic single-cycle observation of a PR.
    """
    previous_state = {}
    prior_state_corrupt = False
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                previous_state = json.load(f)
        except (json.JSONDecodeError, IOError):
            prior_state_corrupt = True
            previous_state = {}

    error_occurred = False
    try:
        current_evidence = inspect_pr(owner, repo, pr_number, scope_policy=scope_policy)
        runtime_status = 'OK'
        error_reason = None
    except Exception as e:
        error_occurred = True
        runtime_status = 'EVIDENCE_UNAVAILABLE'
        error_reason = str(e)
        current_evidence = {
            'head_sha': previous_state.get('head_sha'),
            'classification': 'NEEDS_REVIEW',
            'draft': None,
            'merged': None,
            'state': None,
            'graphql_error': True,
            'actions_ci_status': 'UNAVAILABLE',
            'check_runs_error': True,
            'scope_status': 'UNKNOWN'
        }

    current_head_sha = current_evidence.get('head_sha')
    current_classification = current_evidence.get('classification')

    current_draft = current_evidence.get('draft')
    current_merged = current_evidence.get('merged')
    current_state_enum = current_evidence.get('state')

    current_graphql_error = current_evidence.get('graphql_error', False)
    current_actions_ci_status = current_evidence.get('actions_ci_status', 'UNAVAILABLE')
    current_check_runs_error = current_evidence.get('check_runs_error', current_actions_ci_status == 'UNAVAILABLE')
    current_scope_status = current_evidence.get('scope_status', 'UNKNOWN')

    transition_reasons = set()

    if prior_state_corrupt:
        transition_reasons.add('PRIOR_STATE_CORRUPT')

    if previous_state and not prior_state_corrupt:
        if previous_state.get('head_sha') != current_head_sha:
            transition_reasons.add('HEAD_CHANGED')

        if previous_state.get('classification') != current_classification:
            transition_reasons.add('CLASSIFICATION_CHANGED')

        if (previous_state.get('draft') != current_draft or
            previous_state.get('merged') != current_merged or
            previous_state.get('state_enum') != current_state_enum):
            transition_reasons.add('PR_STATE_CHANGED')

        previous_actions_ci_status = previous_state.get('actions_ci_status', 'UNAVAILABLE')
        if previous_actions_ci_status != current_actions_ci_status:
            transition_reasons.add('CI_STATUS_CHANGED')

        if (previous_state.get('graphql_error') != current_graphql_error or
            previous_state.get('check_runs_error') != current_check_runs_error or
            previous_state.get('scope_status') != current_scope_status):
            transition_reasons.add('EVIDENCE_AVAILABILITY_CHANGED')

    new_state = {
        'repo': f"{owner}/{repo}",
        'pr': pr_number,
        'head_sha': current_head_sha,
        'classification': current_classification,
        'draft': current_draft,
        'merged': current_merged,
        'state_enum': current_state_enum,
        'graphql_error': current_graphql_error,
        'actions_ci_status': current_actions_ci_status,
        'check_runs_error': current_check_runs_error,
        'scope_status': current_scope_status
    }

    observation = {
        "repo": f"{owner}/{repo}",
        "pr": pr_number,
        "previous_head_sha": previous_state.get('head_sha'),
        "current_head_sha": current_head_sha,
        "previous_classification": previous_state.get('classification'),
        "current_classification": current_classification,
        "current_draft": current_draft,
        "current_merged": current_merged,
        "current_state_enum": current_state_enum,
        "scope_status": current_scope_status,
        "graphql_error": current_graphql_error,
        "actions_ci_status": current_actions_ci_status,
        "check_runs_error": current_check_runs_error,
        "runtime_status": runtime_status,
        "transition": bool(transition_reasons),
        "transition_reasons": sorted(list(transition_reasons)),
        "observed_at": datetime.now(timezone.utc).isoformat()
    }

    if error_reason:
        observation["error_reason"] = error_reason

    if not error_occurred:
        dir_name = os.path.dirname(os.path.abspath(state_file))
        os.makedirs(dir_name, exist_ok=True)

        fd, temp_path = tempfile.mkstemp(dir=dir_name)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(new_state, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, state_file)
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e

    return observation

def watch_pr_loop(owner, repo, pr_number, state_file, interval, scope_policy=None):
    """
    Continuous polling loop wrapping the deterministic core.
    """
    while True:
        try:
            observation = watch_pr_once(owner, repo, pr_number, state_file, scope_policy)
            if observation.get("transition"):
                print(json.dumps(observation))
        except Exception as e:
            print(json.dumps({"error": str(e)}))
        time.sleep(interval)
