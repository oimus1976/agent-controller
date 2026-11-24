"""On-demand Draft advancement; existing primitives own all provider mutations."""
from datetime import datetime, timezone
import json
import math
import re
import time

from .capacity_collect import DEFAULT_CODEX_TIMEOUT_SECONDS, read_codex_rate_limits_result
from .codex_capacity import parse_codex_rate_limits_capacity
from .executor import load_policy
from .inspector import inspect_pr, get_pr_details
from .provider_capacity import (
    ProviderAvailability, CapacityObservationSource, ProviderCapacityObservation,
    ProviderCandidate, _parse_aware_iso8601, recommend_provider,
)
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


def _evaluate_observations(config, observations, target, *, observed_monotonic=None):
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


def _manual_capacity_gate(config, target):
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

    def gate():
        return _evaluate_observations(config, (observation,), target)

    return gate(), gate


def _live_capacity_gate(config, target, *, codex_command, codex_timeout):
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
        root = None
    if isinstance(root, dict):
        by_limit_id = root.get("rateLimitsByLimitId")
        if isinstance(by_limit_id, dict) and by_limit_id and set(by_limit_id) != {"codex"}:
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

    def gate():
        return _evaluate_observations(
            config,
            observations,
            target,
            observed_monotonic=observed_monotonic,
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
    """Fresh inspect, then at most one existing review/remediation request.

    Task observations are operator-reported Cloud UI facts, used only to stop;
    they never establish publication, readiness, or permission to retry.
    """
    full_repo = f"{owner}/{repo}"
    result = {"repo": full_repo, "pr": pr_number,
              "pr_url": f"https://github.com/{full_repo}/pull/{pr_number}",
              "head_sha": None, "actions_ci_status": None, "review_verdict": None}

    def finish(state, reason, action):
        return dict(result, state=state, reason=reason, next_action=action)

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
        pr = get_pr_details(owner, repo, pr_number)
        error = _validate_safe_pr_snapshot(pr, head, full_repo)
        if error:
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
        planner, executor = plan_codex_review_request, execute_codex_review_request
        state, key = "REQUEST_REVIEW", "head_sha"
    else:
        return finish("STOP_REVIEW_EVIDENCE", "UNKNOWN_REVIEW_VERDICT", "Inspect canonical review evidence.")

    plan = planner(owner=owner, repo=repo, pr_number=pr_number, policy_path=policy_path,
                   scope_policy=scope_policy)
    if plan.get(key) is not None and plan.get(key) != head:
        return finish("STOP_HEAD_CHANGED", "STALE_HEAD_SHA", "Rerun advance-pr; prior-head CI/review is invalid.")
    if plan.get("decision") == "NOOP":
        return finish("WAIT_CURRENT_HEAD_REVIEW" if state == "REQUEST_REVIEW" else "STOP_TASK_OBSERVATION_REQUIRED",
                      plan.get("reason"), "Rerun advance-pr to observe the pending operation.")
    if plan.get("decision") != "EXECUTABLE":
        return finish("STOP_PROVIDER", plan.get("reason"), "Resolve the existing request primitive's refusal.")
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
        reason, capacity_gate = _live_capacity_gate(
            config,
            target,
            codex_command=codex_command,
            codex_timeout=codex_timeout,
        )
    else:
        reason, capacity_gate = _manual_capacity_gate(config, target)
    if reason:
        return finish("WAIT_CAPACITY", reason, capacity_action)
    if not apply:
        return finish(state, "DRY_RUN", "Rerun the same advance-pr command with --apply.")
    # A policy edit during capacity observation must not reuse our old capacity
    # or scope confirmation. The executor retains its own pre-effect checks too.
    if load_policy(policy_path) != policy:
        return finish("STOP_POLICY", "POLICY_CHANGED", "Rerun advance-pr with the current policy.")
    reason = capacity_gate()
    if reason:
        return finish("WAIT_CAPACITY", reason, capacity_action)
    extra = {"expected_findings_sha256": result["finding_set_sha256"]} if state == "REMEDIATE_SCOPED" else {}
    execution = executor(plan=plan, owner=owner, repo=repo, pr_number=pr_number,
                         policy_path=policy_path, apply=True,
                         pre_mutation_check=capacity_gate, **extra)
    result["execution"] = execution
    success = "PASS" if state == "REMEDIATE_SCOPED" else "SUCCESS"
    if execution.get("final_outcome") != success:
        if (not execution.get("mutation_attempted")
                and execution.get("failure_reason") in _CAPACITY_FAILURE_REASONS):
            return finish("WAIT_CAPACITY", execution.get("failure_reason"), capacity_action)
        return finish("STOP_PROVIDER", execution.get("failure_reason"), "Inspect the request result before retrying.")
    # Publication may race provider execution; never carry evidence across heads.
    try:
        fresh = get_pr_details(owner, repo, pr_number)
    except Exception:
        return finish("STOP_EVIDENCE", "POST_REQUEST_READ_FAILED", "Rerun advance-pr to verify the request; do not post a duplicate.")
    if _validate_safe_pr_snapshot(fresh, head, full_repo):
        return finish("STOP_HEAD_CHANGED", "TARGET_CHANGED_AFTER_REQUEST", "Rerun advance-pr for fresh-head CI and review.")
    return finish("WAIT_REMEDIATION" if state == "REMEDIATE_SCOPED" else "WAIT_CURRENT_HEAD_REVIEW",
                  "REQUEST_POSTED", "Rerun advance-pr after the requested operation completes.")
