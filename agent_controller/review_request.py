from __future__ import annotations

from typing import Any, Mapping

from .executor import load_policy
from .inspector import evaluate_scope, get_pr_issue_comments, inspect_pr
from .review_request_mutator import (
    codex_review_request_marker,
    post_codex_review_request,
)
from .scope_evidence import normalize_github_scope_files


ACTION = "REQUEST_CODEX_REVIEW"
_CODEX_BOT_LOGINS = {
    "chatgpt-codex-connector[bot]",
    "chatgpt-codex-connector",
}


def _is_codex_bot(user: Any) -> bool:
    return isinstance(user, Mapping) and user.get("login") in _CODEX_BOT_LOGINS


def _body_mentions_head(body: Any, head_sha: str) -> bool:
    return isinstance(body, str) and (head_sha in body or head_sha[:10] in body)


def _has_same_head_request(issue_comments: list[Mapping[str, Any]], head_sha: str) -> bool:
    marker = codex_review_request_marker(head_sha)
    for comment in issue_comments:
        if not isinstance(comment, Mapping):
            raise ValueError("issue comment evidence is malformed")
        body = comment.get("body")
        if (
            isinstance(body, str)
            and "@codex review" in body.lower()
            and marker in body
        ):
            return True
    return False


def _has_codex_review_on_head(inspection: Mapping[str, Any], head_sha: str) -> bool:
    issue_comments = inspection.get("issue_comments")
    reviews = inspection.get("reviews")
    threads = inspection.get("review_threads_graphql")

    if not isinstance(issue_comments, list) or not isinstance(reviews, list):
        raise ValueError("review evidence lists are malformed")
    if threads is not None and not isinstance(threads, list):
        raise ValueError("review thread evidence is malformed")

    for comment in issue_comments:
        if not isinstance(comment, Mapping):
            raise ValueError("issue comment evidence is malformed")
        if _is_codex_bot(comment.get("user")) and _body_mentions_head(
            comment.get("body"), head_sha
        ):
            return True

    for review in reviews:
        if not isinstance(review, Mapping):
            raise ValueError("review evidence is malformed")
        if not _is_codex_bot(review.get("user")):
            continue
        if review.get("commit_id") == head_sha or _body_mentions_head(
            review.get("body"), head_sha
        ):
            return True

    for thread in threads or []:
        if not isinstance(thread, Mapping):
            raise ValueError("review thread evidence is malformed")
        comments_container = thread.get("comments")
        if not isinstance(comments_container, Mapping):
            raise ValueError("review thread comments are malformed")
        comments = comments_container.get("nodes")
        if not isinstance(comments, list):
            raise ValueError("review thread comments are malformed")
        for comment in comments:
            if not isinstance(comment, Mapping):
                raise ValueError("review thread comment is malformed")
            if not _is_codex_bot(comment.get("author")):
                continue
            original_commit = comment.get("originalCommit") or {}
            if isinstance(original_commit, Mapping) and original_commit.get("oid") == head_sha:
                return True

    return False


def _safe_scope_status(
    inspection: Mapping[str, Any], scope_policy: Mapping[str, Any]
) -> str:
    files = inspection.get("files")
    if not isinstance(files, list):
        return "MALFORMED"
    normalized = normalize_github_scope_files(files)
    if normalized is None:
        return "MALFORMED"
    return evaluate_scope(normalized, dict(scope_policy))


def plan_codex_review_request(
    *,
    owner: str,
    repo: str,
    pr_number: int,
    policy_path: str | None,
    scope_policy: Mapping[str, Any],
    inspection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "repo": f"{owner}/{repo}",
        "pr": pr_number,
        "requested_action": ACTION,
        "decision": "BLOCKED",
        "reason": None,
        "head_sha": None,
        "draft": None,
        "scope_status": None,
        "actions_ci_status": None,
        "scope_policy": dict(scope_policy),
        "policy_provenance": None,
    }

    policy = load_policy(policy_path)
    if not policy:
        plan["reason"] = "MISSING_OR_MALFORMED_POLICY"
        return plan
    plan["policy_provenance"] = policy

    allowed_actions = policy.get("allowed_actions")
    if not isinstance(allowed_actions, list) or ACTION not in allowed_actions:
        plan["reason"] = "ACTION_NOT_ALLOWLISTED"
        return plan

    if inspection is None:
        try:
            inspection = inspect_pr(
                owner,
                repo,
                pr_number,
                scope_policy=dict(scope_policy),
            )
        except Exception:
            plan["reason"] = "EVIDENCE_FETCH_FAILED"
            return plan

    if not isinstance(inspection, Mapping):
        plan["reason"] = "EVIDENCE_MALFORMED"
        return plan

    head_sha = inspection.get("head_sha")
    draft = inspection.get("draft")
    merged = inspection.get("merged")
    state = inspection.get("state")
    actions_ci_status = inspection.get("actions_ci_status")
    graphql_error = inspection.get("graphql_error")
    issue_comments = inspection.get("issue_comments")

    plan["head_sha"] = head_sha
    plan["draft"] = draft
    plan["actions_ci_status"] = actions_ci_status

    if (
        not isinstance(head_sha, str)
        or len(head_sha) != 40
        or draft is None
        or merged is None
        or state is None
        or graphql_error is None
        or not isinstance(issue_comments, list)
    ):
        plan["reason"] = "CONTRADICTORY_OR_MISSING_EVIDENCE"
        return plan

    try:
        codex_review_request_marker(head_sha)
    except (TypeError, ValueError):
        plan["reason"] = "HEAD_SHA_MALFORMED"
        return plan

    if merged or state == "closed":
        plan["reason"] = "PR_CLOSED_OR_MERGED"
        return plan
    if state != "open":
        plan["reason"] = "PR_STATE_NOT_OPEN"
        return plan

    try:
        if _has_same_head_request(issue_comments, head_sha):
            plan["decision"] = "NOOP"
            plan["reason"] = "REVIEW_ALREADY_REQUESTED_FOR_HEAD"
            return plan
        if _has_codex_review_on_head(inspection, head_sha):
            plan["decision"] = "NOOP"
            plan["reason"] = "CODEX_REVIEW_ALREADY_PRESENT_ON_HEAD"
            return plan
    except (TypeError, ValueError):
        plan["reason"] = "REVIEW_EVIDENCE_MALFORMED"
        return plan

    if graphql_error:
        plan["reason"] = "REVIEW_EVIDENCE_UNAVAILABLE"
        return plan
    if draft is not True:
        plan["reason"] = "PR_NOT_DRAFT"
        return plan

    scope_status = _safe_scope_status(inspection, scope_policy)
    plan["scope_status"] = scope_status
    if scope_status == "MALFORMED":
        plan["reason"] = "SCOPE_EVIDENCE_MALFORMED"
        return plan
    if scope_status != "SATISFIED":
        plan["reason"] = "SCOPE_NOT_SATISFIED"
        return plan
    if actions_ci_status != "PASS":
        plan["reason"] = "EXACT_HEAD_CI_NOT_PASS"
        return plan

    plan["decision"] = "EXECUTABLE"
    plan["reason"] = "READY_TO_REQUEST_CODEX_REVIEW"
    return plan


def execute_codex_review_request(
    *,
    plan: Mapping[str, Any],
    owner: str,
    repo: str,
    pr_number: int,
    policy_path: str | None,
    apply: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "planned_head_sha": plan.get("head_sha"),
        "execution_head_sha": None,
        "mutation_attempted": False,
        "mutation_type": None,
        "postcondition_result": None,
        "final_outcome": "BLOCKED",
        "failure_reason": None,
    }

    if plan.get("repo") != f"{owner}/{repo}" or plan.get("pr") != pr_number:
        result["failure_reason"] = "TARGET_MISMATCH"
        return result

    if plan.get("decision") == "NOOP":
        result["final_outcome"] = "NOOP"
        result["failure_reason"] = plan.get("reason")
        return result
    if plan.get("decision") != "EXECUTABLE":
        result["failure_reason"] = plan.get("reason")
        return result
    if plan.get("requested_action") != ACTION:
        result["failure_reason"] = "UNKNOWN_ACTION_REQUESTED"
        return result
    if not apply:
        result["final_outcome"] = "DRY_RUN"
        result["failure_reason"] = "APPLY_FLAG_NOT_SET"
        return result

    scope_policy = plan.get("scope_policy")
    if not isinstance(scope_policy, Mapping):
        result["failure_reason"] = "SCOPE_POLICY_MISSING"
        return result

    fresh_plan = plan_codex_review_request(
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        policy_path=policy_path,
        scope_policy=scope_policy,
    )
    result["execution_head_sha"] = fresh_plan.get("head_sha")

    if fresh_plan.get("head_sha") != plan.get("head_sha"):
        result["failure_reason"] = "STALE_HEAD_SHA"
        return result
    if fresh_plan.get("decision") == "NOOP":
        result["final_outcome"] = "NOOP"
        result["failure_reason"] = fresh_plan.get("reason")
        return result
    if fresh_plan.get("decision") != "EXECUTABLE":
        result["failure_reason"] = fresh_plan.get("reason")
        return result

    result["mutation_attempted"] = True
    result["mutation_type"] = ACTION
    try:
        post_codex_review_request(owner, repo, pr_number, plan["head_sha"])
    except Exception:
        result["failure_reason"] = "MUTATION_FAILED"
        return result

    try:
        comments = get_pr_issue_comments(owner, repo, pr_number)
        if not isinstance(comments, list):
            raise ValueError("comments response malformed")
        marker = codex_review_request_marker(plan["head_sha"])
        found = any(
            isinstance(comment, Mapping)
            and isinstance(comment.get("body"), str)
            and "@codex review" in comment["body"].lower()
            and marker in comment["body"]
            for comment in comments
        )
        result["postcondition_result"] = found
        if found:
            result["final_outcome"] = "SUCCESS"
        else:
            result["final_outcome"] = "FAILED"
            result["failure_reason"] = "POSTCONDITION_FAILED"
    except Exception:
        result["final_outcome"] = "FAILED"
        result["failure_reason"] = "POSTCONDITION_VERIFICATION_FETCH_FAILED"

    return result
