from __future__ import annotations

from typing import Any, Mapping

from .executor import load_policy
from .inspector import (
    evaluate_actions_ci,
    evaluate_scope,
    get_actions_runs,
    get_pr_details,
    get_pr_files,
    get_pr_issue_comments,
    get_pr_reviews,
    get_pr_review_threads_graphql,
)
from .review_request_mutator import (
    codex_review_request_marker,
    get_authenticated_github_login,
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


def _trusted_request_authors(policy: Mapping[str, Any]) -> tuple[str, ...] | None:
    value = policy.get("trusted_review_request_authors")
    if not isinstance(value, list) or not value:
        return None
    if any(not isinstance(item, str) or not item for item in value):
        return None
    if len(set(value)) != len(value):
        return None
    return tuple(value)


def _has_same_head_request(
    issue_comments: list[Mapping[str, Any]],
    head_sha: str,
    trusted_authors: tuple[str, ...],
) -> bool:
    marker = codex_review_request_marker(head_sha)
    trusted = set(trusted_authors)
    for comment in issue_comments:
        if not isinstance(comment, Mapping):
            raise ValueError("issue comment evidence is malformed")
        user = comment.get("user")
        if not isinstance(user, Mapping):
            raise ValueError("issue comment user evidence is malformed")
        login = user.get("login")
        body = comment.get("body")
        if (
            login in trusted
            and isinstance(body, str)
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
    changed_files = inspection.get("changed_files")
    if not isinstance(files, list):
        return "MALFORMED"
    if (
        isinstance(changed_files, bool)
        or not isinstance(changed_files, int)
        or changed_files < 0
        or changed_files != len(files)
    ):
        return "MALFORMED"
    normalized = normalize_github_scope_files(files)
    if normalized is None:
        return "MALFORMED"
    return evaluate_scope(normalized, dict(scope_policy))


def _validate_exact_pr_snapshot(
    pr_data: Any,
    expected_head_sha: str,
) -> str | None:
    if not isinstance(pr_data, Mapping):
        return "PR_SNAPSHOT_MALFORMED"
    head = pr_data.get("head")
    if not isinstance(head, Mapping):
        return "PR_SNAPSHOT_MALFORMED"
    head_sha = head.get("sha")
    draft = pr_data.get("draft")
    merged = pr_data.get("merged")
    state = pr_data.get("state")
    if (
        not isinstance(head_sha, str)
        or not isinstance(draft, bool)
        or not isinstance(merged, bool)
        or not isinstance(state, str)
    ):
        return "PR_SNAPSHOT_MALFORMED"
    if head_sha != expected_head_sha:
        return "STALE_HEAD_SHA"
    if merged or state == "closed":
        return "PR_CLOSED_OR_MERGED"
    if state != "open":
        return "PR_STATE_NOT_OPEN"
    if draft is not True:
        return "PR_NOT_DRAFT"
    return None


def _inspect_review_request(owner: str, repo: str, pr_number: int) -> dict[str, Any]:
    """Collect only the GitHub facts required for review-request eligibility.

    This deliberately avoids the general inspector's per-comment reaction reads.
    Review-request eligibility does not consume reactions, and comment-count fan-out
    would make an untrusted comment flood a GitHub API quota amplifier.
    """

    pr_data = get_pr_details(owner, repo, pr_number)
    if not isinstance(pr_data, Mapping):
        raise ValueError("PR details malformed")

    head = pr_data.get("head")
    head_sha = head.get("sha") if isinstance(head, Mapping) else None

    reviews = get_pr_reviews(owner, repo, pr_number)
    issue_comments = get_pr_issue_comments(owner, repo, pr_number)
    files = get_pr_files(owner, repo, pr_number)

    graphql_error = False
    try:
        review_threads_graphql = get_pr_review_threads_graphql(owner, repo, pr_number)
    except Exception:
        review_threads_graphql = None
        graphql_error = True

    actions_ci_status = "UNAVAILABLE"
    try:
        actions_response = get_actions_runs(owner, repo, head_sha)
        actions_ci_status = evaluate_actions_ci(actions_response, head_sha)
    except Exception:
        actions_ci_status = "UNAVAILABLE"

    return {
        "head_sha": head_sha,
        "draft": pr_data.get("draft"),
        "merged": pr_data.get("merged"),
        "state": pr_data.get("state"),
        "changed_files": pr_data.get("changed_files"),
        "files": files,
        "actions_ci_status": actions_ci_status,
        "graphql_error": graphql_error,
        "issue_comments": issue_comments,
        "reviews": reviews,
        "review_threads_graphql": review_threads_graphql,
    }


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
        "trusted_review_request_authors": None,
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

    trusted_authors = _trusted_request_authors(policy)
    if trusted_authors is None:
        plan["reason"] = "TRUSTED_REQUEST_AUTHORS_MISSING_OR_MALFORMED"
        return plan
    plan["trusted_review_request_authors"] = list(trusted_authors)

    if inspection is None:
        try:
            inspection = _inspect_review_request(owner, repo, pr_number)
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
        if _has_same_head_request(issue_comments, head_sha, trusted_authors):
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
    fresh_head = fresh_plan.get("head_sha")
    result["execution_head_sha"] = fresh_head

    # Only call a head stale if a fresh objective head was actually observed.
    # A policy or evidence gate can block before any GitHub read; None in that
    # case is not evidence that the head changed.
    if fresh_head is not None and fresh_head != plan.get("head_sha"):
        result["failure_reason"] = "STALE_HEAD_SHA"
        return result
    if fresh_plan.get("decision") == "NOOP":
        result["final_outcome"] = "NOOP"
        result["failure_reason"] = fresh_plan.get("reason")
        return result
    if fresh_plan.get("decision") != "EXECUTABLE":
        result["failure_reason"] = fresh_plan.get("reason")
        return result
    if fresh_head != plan.get("head_sha"):
        result["failure_reason"] = "STALE_HEAD_SHA"
        return result

    # Keep the existing early fail-closed target/policy checks so obvious drift
    # avoids an unnecessary identity lookup.
    try:
        pre_mutation_pr = get_pr_details(owner, repo, pr_number)
    except Exception:
        result["failure_reason"] = "PRE_MUTATION_TARGET_READ_FAILED"
        return result
    pre_mutation_error = _validate_exact_pr_snapshot(pre_mutation_pr, plan["head_sha"])
    if pre_mutation_error is not None:
        result["failure_reason"] = pre_mutation_error
        return result

    pre_identity_policy = load_policy(policy_path)
    if (
        not isinstance(pre_identity_policy, Mapping)
        or pre_identity_policy != fresh_plan.get("policy_provenance")
    ):
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    pre_identity_trusted_authors = _trusted_request_authors(pre_identity_policy)
    if pre_identity_trusted_authors is None:
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    allowed_actions = pre_identity_policy.get("allowed_actions")
    if not isinstance(allowed_actions, list) or ACTION not in allowed_actions:
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result

    # Resolve the exact token principal before the final target/policy gate. The
    # identity lookup is a network read and therefore cannot sit after the last
    # mutable-state validation.
    try:
        posting_login = get_authenticated_github_login()
    except Exception:
        result["failure_reason"] = "POSTING_IDENTITY_READ_FAILED"
        return result

    # Final mutation gate: after every other network read, re-read the mutable PR
    # target and local authorization consecutively, then POST without another
    # pre-effect network operation.
    try:
        final_pr = get_pr_details(owner, repo, pr_number)
    except Exception:
        result["failure_reason"] = "PRE_MUTATION_TARGET_READ_FAILED"
        return result
    final_pr_error = _validate_exact_pr_snapshot(final_pr, plan["head_sha"])
    if final_pr_error is not None:
        result["failure_reason"] = final_pr_error
        return result

    final_policy = load_policy(policy_path)
    if not isinstance(final_policy, Mapping) or final_policy != fresh_plan.get("policy_provenance"):
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    final_trusted_authors = _trusted_request_authors(final_policy)
    if final_trusted_authors is None:
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    allowed_actions = final_policy.get("allowed_actions")
    if not isinstance(allowed_actions, list) or ACTION not in allowed_actions:
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    if posting_login not in set(final_trusted_authors):
        result["failure_reason"] = "UNTRUSTED_POSTING_IDENTITY"
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

        post_pr = get_pr_details(owner, repo, pr_number)
        post_pr_error = _validate_exact_pr_snapshot(post_pr, plan["head_sha"])
        if post_pr_error is not None:
            result["postcondition_result"] = False
            result["final_outcome"] = "FAILED"
            result["failure_reason"] = f"POSTCONDITION_{post_pr_error}"
            return result

        found = _has_same_head_request(comments, plan["head_sha"], final_trusted_authors)
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
