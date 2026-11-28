"""On-demand Draft advancement; existing primitives own all provider mutations."""
import copy
from datetime import datetime, timezone
import json
import math
import re
import time
from typing import Mapping

from .capacity_collect import DEFAULT_CODEX_TIMEOUT_SECONDS, read_codex_rate_limits_result
from .codex_capacity import parse_codex_rate_limits_capacity
from .executor import load_policy
from .inspector import inspect_pr, get_pr_details
from .provider_capacity import (
    ProviderAvailability, CapacityObservationSource, ProviderCapacityObservation,
    ProviderCandidate, _parse_aware_iso8601, recommend_provider,
)
from .reconciler import ReconcilerLock, pr_lock_path
from .remediation_request import (
    _validate_safe_pr_snapshot, plan_codex_remediation_request,
    execute_codex_remediation_request, remediation_findings_sha256,
    standalone_codex_blockers,
)
from .review_request import _safe_scope_status, plan_codex_review_request, execute_codex_review_request
from .review_evidence import canonical_review_from_mapping


_REMEDIATION = re.compile(
    r"<!-- agent-controller:codex-remediation-request source_head=([0-9a-f]{40}) -->"
)

_CAPACITY_FAILURE_REASONS = frozenset({
    "PAID_USAGE_NOT_AUTHORIZED",
    "ORDINARY_USAGE_NOT_ALLOWED",
    "CAPACITY_COLLECTION_FAILED",
    "CAPACITY_POOL_AMBIGUOUS",
    "CAPACITY_POOL_MISSING",
    "CAPACITY_EXHAUSTED",
    "PROVIDER_UNAVAILABLE",
    "CAPACITY_REOBSERVATION_REQUIRED",
    "INSUFFICIENT_CAPABILITY",
    "PRESERVE_SCARCE_REVIEW_PROVIDER",
})


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _requests(comments, authors):
    return {
        match.group(1)
        for comment in comments
        if (comment.get("user") or {}).get("login") in authors
        and "@codex address that feedback" in (comment.get("body") or "").lower()
        for match in _REMEDIATION.finditer(comment.get("body") or "")
    }


def _evaluate_observations(
    config,
    observations,
    target,
    *,
    observed_monotonic=None,
    require_reset_at=False,
):
    """Evaluate all relevant Codex capacity observations via provider_capacity."""
    # Absence of a price observation must not silently authorize paid routing.
    if config.get("additional_paid_usage_required") is not False:
        return "PAID_USAGE_NOT_AUTHORIZED"
    if not observations:
        return "CAPACITY_REOBSERVATION_REQUIRED"
    if observed_monotonic is not None and (time.monotonic() - observed_monotonic) >= 300:
        return "CAPACITY_REOBSERVATION_REQUIRED"
    try:
        decision_at = _utc_now_iso()
        decision_dt = _parse_aware_iso8601("decision_at", decision_at)
        for observation in observations:
            observed_dt = _parse_aware_iso8601("observed_at", observation.observed_at)
            if decision_dt < observed_dt:
                return "CAPACITY_REOBSERVATION_REQUIRED"
            if require_reset_at and observation.reset_at is None:
                return "CAPACITY_REOBSERVATION_REQUIRED"
            recommendation = recommend_provider(
                controller_task_id=target, workstream_id=target, operation_id=target,
                operation_version="1", decision_at=decision_at,
                candidates=[ProviderCandidate("codex", True)],
                capacity_observations=[observation], max_observation_validity_seconds=300,
            )
            if recommendation.deferred:
                return recommendation.deferred[0].reason.value
            if (observation.provider != "codex"
                    or observation.source == CapacityObservationSource.UNKNOWN
                    or observation.availability not in {
                        ProviderAvailability.AVAILABLE, ProviderAvailability.DEGRADED}):
                return "CAPACITY_REOBSERVATION_REQUIRED"
    except (KeyError, ValueError, TypeError):
        return "CAPACITY_REOBSERVATION_REQUIRED"
    return None


def _make_capacity_gate(
    expected_policy,
    observations,
    target,
    *,
    observed_monotonic=None,
    require_reset_at=False,
):
    policy_snapshot = copy.deepcopy(expected_policy)

    def gate(current_policy=None):
        active_policy = policy_snapshot if current_policy is None else current_policy
        if not isinstance(active_policy, Mapping):
            return "POLICY_CHANGED"
        active_config = active_policy.get("advance_pr", {})
        if not isinstance(active_config, Mapping):
            return "POLICY_CHANGED"
        if active_config.get("additional_paid_usage_required") is not False:
            return "PAID_USAGE_NOT_AUTHORIZED"
        if dict(active_policy) != policy_snapshot:
            return "POLICY_CHANGED"
        return _evaluate_observations(
            active_config,
            observations,
            target,
            observed_monotonic=observed_monotonic,
            require_reset_at=require_reset_at,
        )

    return gate


def _manual_capacity_gate(policy, config, target):
    """Reuse capacity policy from local config without modifying it."""
    if config.get("additional_paid_usage_required") is not False:
        return "PAID_USAGE_NOT_AUTHORIZED", None
    data = config.get("capacity", {})
    if not isinstance(data, dict):
        return "CAPACITY_REOBSERVATION_REQUIRED", None
    try:
        observation = ProviderCapacityObservation(
            controller_task_id=target, workstream_id=target, operation_id=target,
            operation_version="1", provider="codex",
            observed_at=data["observed_at"],
            availability=ProviderAvailability(data["availability"]),
            source=CapacityObservationSource(data["source"]),
            reset_at=data.get("reset_at"),
        )
    except (KeyError, ValueError, TypeError):
        return "CAPACITY_REOBSERVATION_REQUIRED", None

    gate = _make_capacity_gate(
        policy,
        (observation,),
        target,
        require_reset_at=False,
    )
    return gate(), gate


def _live_capacity_gate(policy, config, target, *, codex_command, codex_timeout):
    """Collect and validate live Codex 5-hour and weekly pools without fallback."""
    if config.get("additional_paid_usage_required") is not False:
        return "PAID_USAGE_NOT_AUTHORIZED", None
    if (
        not isinstance(codex_command, str)
        or not codex_command.strip()
        or isinstance(codex_timeout, bool)
        or not isinstance(codex_timeout, (int, float))
        or not math.isfinite(float(codex_timeout))
        or float(codex_timeout) <= 0
    ):
        return "CAPACITY_COLLECTION_FAILED", None

    observed_at = _utc_now_iso()
    observed_monotonic = time.monotonic()
    try:
        payload = read_codex_rate_limits_result(codex_command, float(codex_timeout))
        pools = parse_codex_rate_limits_capacity(
            payload,
            controller_task_id=target,
            workstream_id=target,
            operation_id=target,
            operation_version="1",
            observed_at=observed_at,
        )
    except Exception:
        return "CAPACITY_COLLECTION_FAILED", None

    try:
        root = json.loads(payload)
    except Exception:
        return "CAPACITY_COLLECTION_FAILED", None
    if not isinstance(root, dict):
        return "CAPACITY_COLLECTION_FAILED", None

    if "ordinaryUsageAllowed" in root:
        ordinary_allowed = root["ordinaryUsageAllowed"]
        if ordinary_allowed is False:
            return "ORDINARY_USAGE_NOT_ALLOWED", None
        if ordinary_allowed is None:
            return "CAPACITY_REOBSERVATION_REQUIRED", None
        if not isinstance(ordinary_allowed, bool):
            return "CAPACITY_COLLECTION_FAILED", None

    by_limit_id = root.get("rateLimitsByLimitId")
    if isinstance(by_limit_id, dict) and by_limit_id and set(by_limit_id) != {"codex"}:
        return "CAPACITY_POOL_AMBIGUOUS", None
    single = root.get("rateLimits")
    if not by_limit_id and isinstance(single, dict) and single.get("limitId") not in (None, "codex"):
        return "CAPACITY_POOL_AMBIGUOUS", None

    if any(item.observation.provider != "codex" for item in pools):
        return "CAPACITY_POOL_AMBIGUOUS", None
    five_hour = [item.observation for item in pools if item.capacity_pool == "codex-five-hour"]
    weekly = [item.observation for item in pools if item.capacity_pool == "codex-weekly"]
    unexpected = [
        item.capacity_pool
        for item in pools
        if item.capacity_pool not in {"codex-five-hour", "codex-weekly"}
    ]
    if unexpected or len(five_hour) > 1 or len(weekly) > 1:
        return "CAPACITY_POOL_AMBIGUOUS", None
    if len(five_hour) != 1 or len(weekly) != 1:
        return "CAPACITY_POOL_MISSING", None

    observations = (five_hour[0], weekly[0])
    if any(obs.reset_at is None for obs in observations):
        return "CAPACITY_REOBSERVATION_REQUIRED", None

    gate = _make_capacity_gate(
        policy,
        observations,
        target,
        observed_monotonic=observed_monotonic,
        require_reset_at=True,
    )
    return gate(), gate


def _finding_gate(inspection, head, requests):
    current, previous = set(), set()
    # Match the canonical inspector: threads of dismissed reviews are not findings.
    dismissed = {review.get("id") for review in inspection.get("reviews") or []
                 if str(review.get("state", "")).upper() == "DISMISSED"}
    for thread in inspection.get("review_threads_graphql") or []:
        root = thread["comments"]["nodes"][0]
        if (root.get("author") or {}).get("login") not in {
                "chatgpt-codex-connector[bot]", "chatgpt-codex-connector"}:
            continue
        if (root.get("pullRequestReview") or {}).get("databaseId") in dismissed:
            continue
        source = (root.get("originalCommit") or {}).get("oid")
        body = root.get("body", "")
        fingerprint = " ".join(body.lower().split())
        if source in requests:
            previous.add(fingerprint)
        if source != head or thread.get("isResolved") is not False:
            continue
        # P0/P1 are the first slice's conservative BLOCKER/MAJOR candidates.
        severity = re.search(r"\[P([0-3])(?: Badge)?\]|\b(BLOCKER|MAJOR|MINOR)\b", body)
        if not severity or not (severity.group(1) in {"0", "1"} or severity.group(2) in {"BLOCKER", "MAJOR"}):
            return "FINDING_SEVERITY_REQUIRES_HUMAN"
        current.add(fingerprint)
    # A standalone CHANGES_REQUESTED review blocks canonically but has no
    # classifiable thread, so it can never be scope-confirmed here.
    if standalone_codex_blockers(inspection, head):
        return "FINDING_SEVERITY_REQUIRES_HUMAN"
    if not current:
        return "FINDING_CLASSIFICATION_UNAVAILABLE"
    if current & previous:
        return "INEFFECTIVE_REMEDIATION"
    return None


def advance_pr_once(*, owner, repo, pr_number, policy_path=None, scope_policy=None,
                    apply=False, task_observation=None, live_capacity=False,
                    codex_command="codex", codex_timeout=DEFAULT_CODEX_TIMEOUT_SECONDS):
    """Run one step, taking the shared per-PR lock for any apply."""
    kwargs = dict(owner=owner, repo=repo, pr_number=pr_number, policy_path=policy_path,
                  scope_policy=scope_policy, apply=apply, task_observation=task_observation,
                  live_capacity=live_capacity, codex_command=codex_command, codex_timeout=codex_timeout)
    if not apply:
        return _advance_pr_step(**kwargs)
    lock = ReconcilerLock(pr_lock_path(owner, repo, pr_number))
    if not lock.acquire():
        return _advance_conflict(owner, repo, pr_number, lock.lock_file)
    try:
        return _advance_pr_step(**kwargs)
    finally:
        lock.release()


def _advance_target(owner, repo, pr_number):
    full_repo = f"{owner}/{repo}"
    return {"repo": full_repo, "pr": pr_number,
            "pr_url": f"https://github.com/{full_repo}/pull/{pr_number}",
            "head_sha": None, "actions_ci_status": None, "review_verdict": None}


def _advance_conflict(owner, repo, pr_number, lock_path):
    return dict(_advance_target(owner, repo, pr_number), state="STOP_CONFLICT",
                reason="CONCURRENT_PR_ADVANCE", lock_path=lock_path,
                next_action="Read the other process's result before retrying.")


def _advance_pr_step(*, owner, repo, pr_number, policy_path, scope_policy, apply,
                     task_observation, live_capacity, codex_command, codex_timeout,
                     expected_head=None, review_requested=False, step_deadline=None, report_head=None):
    """Run under the caller's lock for apply; follow binds the head before any write."""
    result = _advance_target(owner, repo, pr_number)
    full_repo = result["repo"]

    def finish(state, reason, action):
        return dict(result, state=state, reason=reason, next_action=action)

    def late_stop(reason, evidence):
        """Keep the single-shot outcome contract, with more specific follow stops."""
        if step_deadline is None or not isinstance(reason, str):
            return None
        reason = reason.removeprefix("POSTCONDITION_")
        if reason in {"PR_CLOSED_OR_MERGED", "PR_STATE_NOT_OPEN", "PR_NOT_DRAFT"}:
            return finish("STOP_TARGET", reason, "Check that the PR is still open and Draft.")
        if reason == "EXACT_HEAD_CI_NOT_PASS":
            result["actions_ci_status"] = evidence.get("actions_ci_status")
            if result["actions_ci_status"] in {"PENDING", "MISSING"}:
                return finish("WAIT_CI", reason, "Wait for this head's CI.")
            return finish("STOP_CI", reason, "Inspect this head's CI failure/unavailable evidence.")
        if reason in {"REVIEW_EVIDENCE_UNAVAILABLE", "REVIEW_EVIDENCE_MALFORMED"}:
            return finish("STOP_REVIEW_EVIDENCE", reason, "Wait for readable canonical review evidence.")
        if reason in {"EVIDENCE_FETCH_FAILED", "PRE_MUTATION_TARGET_READ_FAILED", "FINAL_TARGET_READ_FAILED",
                      "TARGET_READ_FAILED", "VERIFICATION_FETCH_FAILED"}:
            return finish("STOP_EVIDENCE", reason, "Check the PR and any request before resuming.")
        return None

    if not isinstance(live_capacity, bool):
        return finish("STOP_POLICY", "MALFORMED_POLICY", "Pass a boolean live_capacity option.")

    scope_policy = scope_policy or {}
    policy = load_policy(policy_path) or {}
    if not isinstance(policy, dict):
        return finish("STOP_POLICY", "MALFORMED_POLICY", "Correct the local policy file.")
    config = policy.get("advance_pr", {})
    if not isinstance(config, dict):
        return finish("STOP_POLICY", "MALFORMED_POLICY", "Correct advance_pr in the local policy.")
    try:
        inspection = inspect_pr(owner, repo, pr_number, scope_policy=scope_policy)
        head = inspection["head_sha"]
        result["head_sha"] = head
        if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
            raise ValueError("HEAD_SHA_MALFORMED")
        if step_deadline is not None:
            result["initial_head_sha"] = expected_head or head
        if report_head is not None:
            report_head(head)
        if expected_head is not None and head != expected_head:
            return finish("STOP_HEAD_CHANGED", "STALE_HEAD_SHA", "Inspect the new HEAD before starting another follow.")
        after_head = inspection.get("head_after_collection")
        if step_deadline is not None and isinstance(after_head, str) and after_head != head:
            result["head_sha"] = after_head
            return finish("STOP_HEAD_CHANGED", "STALE_HEAD_SHA", "Inspect the new HEAD before starting another follow.")
        pr = get_pr_details(owner, repo, pr_number)
        error = _validate_safe_pr_snapshot(pr, head, full_repo)
        if error:
            if error == "STALE_HEAD_SHA":
                result["head_sha"] = pr["head"]["sha"]
            return finish("STOP_HEAD_CHANGED" if error == "STALE_HEAD_SHA" else "STOP_TARGET",
                          error, "Rerun advance-pr against the current open Draft PR.")
    except Exception:
        return finish("STOP_EVIDENCE", "EVIDENCE_FETCH_FAILED", "Rerun advance-pr after GitHub evidence is readable.")

    canonical = canonical_review_from_mapping(inspection.get("canonical_review_evidence"),
                                              repo=full_repo, pr=pr_number, head_sha=head)
    if canonical is None or not canonical.collection_complete:
        return finish("STOP_REVIEW_EVIDENCE", "REVIEW_EVIDENCE_UNAVAILABLE", "Rerun advance-pr after complete review evidence is available.")
    result["review_verdict"] = canonical.verdict
    result["actions_ci_status"] = inspection.get("actions_ci_status")
    try:
        requests = _requests(inspection["issue_comments"], policy.get("trusted_review_request_authors", []))
    except (TypeError, AttributeError):
        return finish("STOP_REVIEW_EVIDENCE", "REQUEST_EVIDENCE_MALFORMED", "Correct the request evidence/policy.")

    if head in requests:
        # Never infer task failure or duplicate implementation from unchanged HEAD.
        observation = task_observation or {}
        if (observation.get("repo"), observation.get("pr"), observation.get("source_head_sha")) == (full_repo, pr_number, head):
            if observation.get("status") == "complete_pending_apply":
                return finish("STOP_FOR_HUMAN_APPLY", "CODEX_COMPLETE_PENDING_APPLY", "View Task → Update branch; then rerun advance-pr.")
            if observation.get("status") == "running":
                return finish("WAIT_REMEDIATION", "CODEX_TASK_RUNNING", "Rerun advance-pr after the Codex task completes.")
            if observation.get("status") == "failed":
                return finish("STOP_PROVIDER", "CODEX_TASK_FAILED", "Inspect the failed Codex task before choosing a recovery.")
        return finish("STOP_TASK_OBSERVATION_REQUIRED", "CODEX_PUBLICATION_UNKNOWN", "Open View Task and check task completion / Update branch availability.")

    ci = inspection.get("actions_ci_status")
    if ci in {"PENDING", "MISSING"}:
        return finish("WAIT_CI", "EXACT_HEAD_CI_NOT_PASS", "Rerun advance-pr when this head's CI completes.")
    if ci != "PASS":
        return finish("STOP_CI", "EXACT_HEAD_CI_NOT_PASS", "Inspect this head's CI failure/unavailable evidence.")
    if _safe_scope_status(inspection, scope_policy) != "SATISFIED":
        return finish("STOP_SCOPE", "SCOPE_NOT_SATISFIED", "Check this PR's changed files against the Issue scope.")
    if canonical.verdict == "CLEAN":
        return finish("HUMAN_GATE_READY", "EXACT_HEAD_CI_AND_REVIEW_CLEAN", f"Human: decide whether to mark {result['pr_url']} Ready for review.")
    if canonical.verdict in {"PENDING", "UNCERTAIN"}:
        return finish("WAIT_CURRENT_HEAD_REVIEW" if canonical.verdict == "PENDING" else "STOP_REVIEW_EVIDENCE",
                      "CURRENT_HEAD_REVIEW_" + canonical.verdict, "Rerun advance-pr after the current-head review completes.")
    if canonical.verdict == "BLOCKING":
        try:
            finding_error = _finding_gate(inspection, head, requests)
        except (KeyError, IndexError, TypeError, AttributeError):
            finding_error = "FINDING_CLASSIFICATION_UNAVAILABLE"
        if finding_error:
            return finish("STOP_FINDINGS", finding_error, "Human: inspect the current findings before another remediation.")
        result["finding_set_sha256"] = remediation_findings_sha256(inspection)
        # Existing path checks cannot prove that semantic changes fit the Issue.
        # Require a concise human scope confirmation for this exact finding set.
        if (config.get("bounded_remediation_head") != head or
                config.get("bounded_remediation_findings") != result["finding_set_sha256"]):
            return finish("STOP_REMEDIATION_SCOPE", "REMEDIATION_SCOPE_REVIEW_REQUIRED", "Confirm these findings are bounded to the Issue, then set advance_pr.bounded_remediation_head and bounded_remediation_findings.")
        rounds = config.get("max_remediation_rounds")
        if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 0:
            return finish("STOP_POLICY", "FINITE_REMEDIATION_BUDGET_REQUIRED", "Set advance_pr.max_remediation_rounds to a finite nonnegative integer.")
        if len(requests) >= rounds:
            return finish("STOP_BUDGET", "REMEDIATION_BUDGET_EXHAUSTED", "Human: decide whether another bounded remediation is justified.")
        planner, executor = plan_codex_remediation_request, execute_codex_remediation_request
        state, key = "REMEDIATE_SCOPED", "source_head_sha"
    elif canonical.verdict == "ABSENT":
        if review_requested:
            return finish("WAIT_CURRENT_HEAD_REVIEW", "REVIEW_ALREADY_REQUESTED_FOR_HEAD",
                          "Wait for current-head review evidence.")
        planner, executor = plan_codex_review_request, execute_codex_review_request
        state, key = "REQUEST_REVIEW", "head_sha"
    else:
        return finish("STOP_REVIEW_EVIDENCE", "UNKNOWN_REVIEW_VERDICT", "Inspect canonical review evidence.")

    plan = planner(owner=owner, repo=repo, pr_number=pr_number, policy_path=policy_path,
                   scope_policy=scope_policy)
    planned_head = plan.get("head_after_collection") or plan.get(key)
    if planned_head is not None and planned_head != head:
        result["head_sha"] = planned_head
        return finish("STOP_HEAD_CHANGED", "STALE_HEAD_SHA", "Rerun advance-pr; prior-head CI/review is invalid.")
    if plan.get("decision") == "NOOP":
        return finish("WAIT_CURRENT_HEAD_REVIEW" if state == "REQUEST_REVIEW" else "STOP_TASK_OBSERVATION_REQUIRED",
                      plan.get("reason"), "Rerun advance-pr to observe the pending operation.")
    if plan.get("decision") != "EXECUTABLE":
        return late_stop(plan.get("reason"), plan) or finish(
            "STOP_PROVIDER", plan.get("reason"), "Resolve the existing request primitive's refusal.")
    # A policy edit during the fresh planner must not reuse stale policy
    # authorization or skip paid-usage checks before live observation.
    if apply and load_policy(policy_path) != policy:
        return finish("STOP_POLICY", "POLICY_CHANGED", "Rerun advance-pr with the current policy.")
    capacity_action = (
        "Verify local Codex capacity and advance_pr paid-usage policy, then rerun advance-pr; no manual or paid fallback."
        if live_capacity
        else "Observe Codex capacity/cost and update advance_pr policy; no paid fallback."
    )
    target = f"{full_repo}#{pr_number}"
    if live_capacity:
        if step_deadline is not None:
            remaining = step_deadline - time.monotonic()
            if remaining <= 0:
                return finish("STOP_WAIT_LIMIT", "STEP_TIMEOUT", "Check the PR before another follow.")
            # Reserve time for shutdown, even in a follow with a short deadline.
            codex_timeout = min(codex_timeout, max(remaining - 10, remaining / 2))
        reason, capacity_gate = _live_capacity_gate(
            policy,
            config,
            target,
            codex_command=codex_command,
            codex_timeout=codex_timeout,
        )
    else:
        reason, capacity_gate = _manual_capacity_gate(policy, config, target)
    if reason:
        return finish("WAIT_CAPACITY", reason, capacity_action)
    if not apply:
        return finish(state, "DRY_RUN", "Rerun the same advance-pr command with --apply.")
    # A policy edit during capacity observation must not reuse our old capacity
    # or scope confirmation. The executor retains its own pre-effect checks too.
    current_policy = load_policy(policy_path)
    if current_policy != policy:
        return finish("STOP_POLICY", "POLICY_CHANGED", "Rerun advance-pr with the current policy.")
    reason = capacity_gate(current_policy)
    if reason:
        return finish("WAIT_CAPACITY", reason, capacity_action)

    def final_gate(final_policy):
        if step_deadline is not None and time.monotonic() >= step_deadline:
            return "FOLLOW_STEP_DEADLINE"
        return capacity_gate(final_policy)

    extra = {}
    if state == "REMEDIATE_SCOPED":
        extra["expected_findings_sha256"] = result["finding_set_sha256"]
    elif step_deadline is not None:
        extra["recheck_follow_evidence"] = True
    execution = executor(plan=plan, owner=owner, repo=repo, pr_number=pr_number,
                         policy_path=policy_path, apply=True,
                         pre_mutation_check=final_gate, **extra)
    result["execution"] = execution
    success = "PASS" if state == "REMEDIATE_SCOPED" else "SUCCESS"
    if execution.get("final_outcome") != success:
        if step_deadline is not None:
            observed_head = execution.get("observed_head_sha") or execution.get("execution_head_sha")
            failure = execution.get("failure_reason")
            if failure == "FOLLOW_STEP_DEADLINE":
                return finish("STOP_WAIT_LIMIT", "STEP_TIMEOUT", "Check the PR before another follow.")
            if failure in {"STALE_HEAD_SHA", "POSTCONDITION_STALE_HEAD_SHA"}:
                result["head_sha"] = observed_head if observed_head != head else None
                return finish("STOP_HEAD_CHANGED", "STALE_HEAD_SHA",
                              "Inspect the new HEAD and any posted request before another follow.")
            stopped = late_stop(failure, execution)
            if stopped is not None:
                return stopped
            if execution.get("final_outcome") == "NOOP":
                if failure in {"REVIEW_ALREADY_REQUESTED_FOR_HEAD", "CODEX_REVIEW_ALREADY_PRESENT_ON_HEAD"}:
                    return finish("WAIT_CURRENT_HEAD_REVIEW", failure, "Wait for current-head review evidence.")
                if failure == "REMEDIATION_ALREADY_REQUESTED_FOR_SOURCE_HEAD":
                    return finish("STOP_TASK_OBSERVATION_REQUIRED", failure, "Check View Task → Update branch.")
        if not execution.get("mutation_attempted"):
            failure = execution.get("failure_reason")
            if failure in _CAPACITY_FAILURE_REASONS:
                return finish("WAIT_CAPACITY", failure, capacity_action)
            if failure in {"POLICY_CHANGED", "POLICY_CHANGED_BEFORE_MUTATION"}:
                return finish("STOP_POLICY", "POLICY_CHANGED", "Rerun advance-pr with the current policy.")
        return finish("STOP_PROVIDER", execution.get("failure_reason"), "Inspect the request result before retrying.")
    # Publication may race provider execution; never carry evidence across heads.
    try:
        fresh = get_pr_details(owner, repo, pr_number)
    except Exception:
        return finish("STOP_EVIDENCE", "POST_REQUEST_READ_FAILED", "Rerun advance-pr to verify the request; do not post a duplicate.")
    fresh_error = _validate_safe_pr_snapshot(fresh, head, full_repo)
    if fresh_error:
        if fresh_error == "STALE_HEAD_SHA":
            result["head_sha"] = fresh["head"]["sha"]
        if step_deadline is not None and fresh_error != "STALE_HEAD_SHA":
            return finish("STOP_TARGET", fresh_error, "Check the target and the request that was already posted.")
        return finish("STOP_HEAD_CHANGED", "TARGET_CHANGED_AFTER_REQUEST", "Rerun advance-pr for fresh-head CI and review.")
    return finish("WAIT_REMEDIATION" if state == "REMEDIATE_SCOPED" else "WAIT_CURRENT_HEAD_REVIEW",
                  "REQUEST_POSTED", "Rerun advance-pr after the requested operation completes.")
