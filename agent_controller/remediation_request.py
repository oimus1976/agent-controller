from __future__ import annotations

from typing import Any, Mapping

from .executor import load_policy
from .inspector import (
    evaluate_actions_ci,
    get_actions_runs,
    get_pr_details,
    get_pr_files,
    get_pr_issue_comments,
    get_pr_reviews,
    get_pr_review_threads_graphql,
)
from .remediation_request_mutator import (
    codex_remediation_request_marker,
    post_codex_remediation_request,
)
from .review_request import _safe_scope_status, _trusted_request_authors
from .review_request_mutator import get_authenticated_github_login


ACTION = "REQUEST_CODEX_REMEDIATION"
_CODEX_BOT_LOGINS = {
    "chatgpt-codex-connector[bot]",
    "chatgpt-codex-connector",
}


def _is_codex_login(login: Any) -> bool:
    return isinstance(login, str) and login in _CODEX_BOT_LOGINS


def _repo_full_name(repo_data: Any) -> str | None:
    if not isinstance(repo_data, Mapping):
        return None
    full_name = repo_data.get("full_name")
    return full_name if isinstance(full_name, str) and full_name else None


def _default_branch(repo_data: Any) -> str | None:
    if not isinstance(repo_data, Mapping):
        return None
    branch = repo_data.get("default_branch")
    return branch if isinstance(branch, str) and branch else None


def _has_same_source_head_request(
    issue_comments: list[Mapping[str, Any]],
    source_head_sha: str,
    trusted_authors: tuple[str, ...],
) -> bool:
    marker = codex_remediation_request_marker(source_head_sha)
    trusted = set(trusted_authors)
    for comment in issue_comments:
        if not isinstance(comment, Mapping):
            raise ValueError("issue comment evidence is malformed")
        user = comment.get("user")
        if not isinstance(user, Mapping):
            raise ValueError("issue comment user evidence is malformed")
        body = comment.get("body")
        if (
            user.get("login") in trusted
            and isinstance(body, str)
            and "@codex address that feedback" in body.lower()
            and marker in body
        ):
            return True
    return False


def _thread_has_current_head_codex_finding(
    thread: Mapping[str, Any], head_sha: str
) -> bool:
    resolved = thread.get("isResolved")
    if resolved is None:
        resolved = thread.get("is_resolved")
    if not isinstance(resolved, bool):
        raise ValueError("review thread resolved state is malformed")
    if resolved:
        return False

    comments_container = thread.get("comments")
    if not isinstance(comments_container, Mapping):
        raise ValueError("review thread comments are malformed")
    comments = comments_container.get("nodes")
    if not isinstance(comments, list) or not comments:
        raise ValueError("review thread comments are malformed")

    for comment in comments:
        if not isinstance(comment, Mapping):
            raise ValueError("review thread comment is malformed")
        author = comment.get("author")
        if not isinstance(author, Mapping) or not _is_codex_login(author.get("login")):
            continue
        original_commit = comment.get("originalCommit") or {}
        if isinstance(original_commit, Mapping) and original_commit.get("oid") == head_sha:
            return True
    return False


def _review_is_current_head_codex_finding(
    review: Mapping[str, Any], head_sha: str
) -> bool:
    user = review.get("user")
    if not isinstance(user, Mapping) or not _is_codex_login(user.get("login")):
        return False
    if review.get("commit_id") != head_sha:
        return False
    state = review.get("state")
    return isinstance(state, str) and state.upper() in {
        "CHANGES_REQUESTED",
        "REQUEST_CHANGES",
    }


def _has_current_head_codex_finding(
    inspection: Mapping[str, Any], head_sha: str
) -> bool:
    reviews = inspection.get("reviews")
    threads = inspection.get("review_threads_graphql")
    if not isinstance(reviews, list) or not isinstance(threads, list):
        raise ValueError("review evidence is malformed")

    for thread in threads:
        if not isinstance(thread, Mapping):
            raise ValueError("review thread evidence is malformed")
        if _thread_has_current_head_codex_finding(thread, head_sha):
            return True

    # A submitted CHANGES_REQUESTED review remains in that state after all of
    # its conversations are resolved. Only use review-level evidence when no
    # thread evidence exists; otherwise the threads are authoritative for the
    # finding's current resolution state.
    if threads:
        return False

    for review in reviews:
        if not isinstance(review, Mapping):
            raise ValueError("review evidence is malformed")
        if _review_is_current_head_codex_finding(review, head_sha):
            return True
    return False


def _validate_safe_pr_snapshot(
    pr_data: Any,
    expected_head_sha: str,
    expected_repo: str,
) -> str | None:
    if not isinstance(pr_data, Mapping):
        return "PR_SNAPSHOT_MALFORMED"
    head = pr_data.get("head")
    base = pr_data.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        return "PR_SNAPSHOT_MALFORMED"

    head_sha = head.get("sha")
    head_ref = head.get("ref")
    base_ref = base.get("ref")
    head_repo = _repo_full_name(head.get("repo"))
    base_repo_data = base.get("repo")
    base_repo = _repo_full_name(base_repo_data)
    default_branch = _default_branch(base_repo_data)
    draft = pr_data.get("draft")
    merged = pr_data.get("merged")
    state = pr_data.get("state")

    if (
        not isinstance(head_sha, str)
        or not isinstance(head_ref, str)
        or not head_ref
        or not isinstance(base_ref, str)
        or not base_ref
        or head_repo is None
        or base_repo is None
        or default_branch is None
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
    if head_repo != expected_repo or base_repo != expected_repo:
        return "UNSAFE_IMPLEMENTATION_REPOSITORY"
    if head_ref in {base_ref, default_branch}:
        return "UNSAFE_IMPLEMENTATION_BRANCH"
    return None


def _validate_planned_base_snapshot(
    pr_data: Mapping[str, Any],
    planned_base_ref: Any,
    planned_base_repo: Any,
    planned_base_sha: Any,
) -> str | None:
    base = pr_data.get("base")
    if not isinstance(base, Mapping):
        return "PR_SNAPSHOT_MALFORMED"
    if (
        base.get("ref") != planned_base_ref
        or _repo_full_name(base.get("repo")) != planned_base_repo
        or base.get("sha") != planned_base_sha
    ):
        return "STALE_BASE_TARGET"
    return None


def _inspect_remediation_request(
    owner: str, repo: str, pr_number: int
) -> dict[str, Any]:
    pr_data = get_pr_details(owner, repo, pr_number)
    if not isinstance(pr_data, Mapping):
        raise ValueError("PR details malformed")
    head = pr_data.get("head")
    base = pr_data.get("base")
    head_repo_data = head.get("repo") if isinstance(head, Mapping) else None
    base_repo_data = base.get("repo") if isinstance(base, Mapping) else None
    head_sha = head.get("sha") if isinstance(head, Mapping) else None

    reviews = get_pr_reviews(owner, repo, pr_number)
    issue_comments = get_pr_issue_comments(owner, repo, pr_number)
    files = get_pr_files(owner, repo, pr_number)
    try:
        threads = get_pr_review_threads_graphql(owner, repo, pr_number)
        graphql_error = False
    except Exception:
        threads = None
        graphql_error = True

    try:
        actions_response = get_actions_runs(owner, repo, head_sha)
        actions_ci_status = evaluate_actions_ci(actions_response, head_sha)
    except Exception:
        actions_ci_status = "UNAVAILABLE"

    return {
        "head_sha": head_sha,
        "head_ref": head.get("ref") if isinstance(head, Mapping) else None,
        "head_repo": _repo_full_name(head_repo_data),
        "base_ref": base.get("ref") if isinstance(base, Mapping) else None,
        "base_sha": base.get("sha") if isinstance(base, Mapping) else None,
        "base_repo": _repo_full_name(base_repo_data),
        "default_branch": _default_branch(base_repo_data),
        "draft": pr_data.get("draft"),
        "merged": pr_data.get("merged"),
        "state": pr_data.get("state"),
        "changed_files": pr_data.get("changed_files"),
        "files": files,
        "actions_ci_status": actions_ci_status,
        "graphql_error": graphql_error,
        "issue_comments": issue_comments,
        "reviews": reviews,
        "review_threads_graphql": threads,
    }


def plan_codex_remediation_request(
    *,
    owner: str,
    repo: str,
    pr_number: int,
    policy_path: str | None,
    scope_policy: Mapping[str, Any],
    inspection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    expected_repo = f"{owner}/{repo}"
    plan: dict[str, Any] = {
        "repo": expected_repo,
        "pr": pr_number,
        "requested_action": ACTION,
        "decision": "BLOCKED",
        "reason": None,
        "source_head_sha": None,
        "head_ref": None,
        "head_repo": None,
        "base_ref": None,
        "base_sha": None,
        "base_repo": None,
        "default_branch": None,
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
            inspection = _inspect_remediation_request(owner, repo, pr_number)
        except Exception:
            plan["reason"] = "EVIDENCE_FETCH_FAILED"
            return plan
    if not isinstance(inspection, Mapping):
        plan["reason"] = "EVIDENCE_MALFORMED"
        return plan

    head_sha = inspection.get("head_sha")
    head_ref = inspection.get("head_ref")
    head_repo = inspection.get("head_repo")
    base_ref = inspection.get("base_ref")
    base_sha = inspection.get("base_sha")
    base_repo = inspection.get("base_repo")
    default_branch = inspection.get("default_branch")
    draft = inspection.get("draft")
    merged = inspection.get("merged")
    state = inspection.get("state")
    issue_comments = inspection.get("issue_comments")
    graphql_error = inspection.get("graphql_error")
    actions_ci_status = inspection.get("actions_ci_status")

    plan["source_head_sha"] = head_sha
    plan["head_ref"] = head_ref
    plan["head_repo"] = head_repo
    plan["base_ref"] = base_ref
    plan["base_sha"] = base_sha
    plan["base_repo"] = base_repo
    plan["default_branch"] = default_branch
    plan["draft"] = draft
    plan["actions_ci_status"] = actions_ci_status

    if (
        not isinstance(head_sha, str)
        or len(head_sha) != 40
        or not isinstance(head_ref, str)
        or not head_ref
        or not isinstance(head_repo, str)
        or not head_repo
        or not isinstance(base_ref, str)
        or not base_ref
        or not isinstance(base_sha, str)
        or len(base_sha) != 40
        or not isinstance(base_repo, str)
        or not base_repo
        or not isinstance(default_branch, str)
        or not default_branch
        or not isinstance(draft, bool)
        or not isinstance(merged, bool)
        or not isinstance(state, str)
        or not isinstance(graphql_error, bool)
        or not isinstance(issue_comments, list)
    ):
        plan["reason"] = "CONTRADICTORY_OR_MISSING_EVIDENCE"
        return plan

    try:
        codex_remediation_request_marker(head_sha)
    except (TypeError, ValueError):
        plan["reason"] = "HEAD_SHA_MALFORMED"
        return plan

    if merged or state == "closed":
        plan["reason"] = "PR_CLOSED_OR_MERGED"
        return plan
    if state != "open":
        plan["reason"] = "PR_STATE_NOT_OPEN"
        return plan
    if draft is not True:
        plan["reason"] = "PR_NOT_DRAFT"
        return plan
    if head_repo != expected_repo or base_repo != expected_repo:
        plan["reason"] = "UNSAFE_IMPLEMENTATION_REPOSITORY"
        return plan
    if head_ref in {base_ref, default_branch}:
        plan["reason"] = "UNSAFE_IMPLEMENTATION_BRANCH"
        return plan
    if graphql_error:
        plan["reason"] = "REVIEW_EVIDENCE_UNAVAILABLE"
        return plan

    try:
        if _has_same_source_head_request(issue_comments, head_sha, trusted_authors):
            plan["decision"] = "NOOP"
            plan["reason"] = "REMEDIATION_ALREADY_REQUESTED_FOR_SOURCE_HEAD"
            return plan
        if not _has_current_head_codex_finding(inspection, head_sha):
            plan["decision"] = "NOOP"
            plan["reason"] = "NO_UNRESOLVED_CURRENT_HEAD_CODEX_FINDING"
            return plan
    except (TypeError, ValueError):
        plan["reason"] = "REVIEW_EVIDENCE_MALFORMED"
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
    plan["reason"] = "READY_TO_REQUEST_CODEX_REMEDIATION"
    return plan


def execute_codex_remediation_request(
    *,
    plan: Mapping[str, Any],
    owner: str,
    repo: str,
    pr_number: int,
    policy_path: str | None,
    apply: bool = False,
) -> dict[str, Any]:
    expected_repo = f"{owner}/{repo}"
    source_head = plan.get("source_head_sha")
    result: dict[str, Any] = {
        "planned_source_head_sha": source_head,
        "execution_head_sha": None,
        "mutation_attempted": False,
        "mutation_type": None,
        "postcondition_result": None,
        "final_outcome": "BLOCKED",
        "failure_reason": None,
    }

    if plan.get("repo") != expected_repo or plan.get("pr") != pr_number:
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

    fresh_plan = plan_codex_remediation_request(
        owner=owner,
        repo=repo,
        pr_number=pr_number,
        policy_path=policy_path,
        scope_policy=scope_policy,
    )
    fresh_head = fresh_plan.get("source_head_sha")
    result["execution_head_sha"] = fresh_head
    if fresh_head is not None and fresh_head != source_head:
        result["failure_reason"] = "STALE_HEAD_SHA"
        return result
    if fresh_plan.get("decision") == "NOOP":
        result["final_outcome"] = "NOOP"
        result["failure_reason"] = fresh_plan.get("reason")
        return result
    if fresh_plan.get("decision") != "EXECUTABLE" or fresh_head != source_head:
        result["failure_reason"] = fresh_plan.get("reason") or "STALE_HEAD_SHA"
        return result

    fresh_base_ref = fresh_plan.get("base_ref")
    fresh_base_repo = fresh_plan.get("base_repo")
    fresh_base_sha = fresh_plan.get("base_sha")
    if (
        fresh_base_ref != plan.get("base_ref")
        or fresh_base_repo != plan.get("base_repo")
        or fresh_base_sha != plan.get("base_sha")
    ):
        result["failure_reason"] = "STALE_BASE_TARGET"
        return result

    try:
        pre_identity_pr = get_pr_details(owner, repo, pr_number)
    except Exception:
        result["failure_reason"] = "PRE_MUTATION_TARGET_READ_FAILED"
        return result
    snapshot_error = _validate_safe_pr_snapshot(
        pre_identity_pr, source_head, expected_repo
    )
    if snapshot_error is not None:
        result["failure_reason"] = snapshot_error
        return result
    base_error = _validate_planned_base_snapshot(
        pre_identity_pr, fresh_base_ref, fresh_base_repo, fresh_base_sha
    )
    if base_error is not None:
        result["failure_reason"] = base_error
        return result

    pre_identity_policy = load_policy(policy_path)
    if (
        not isinstance(pre_identity_policy, Mapping)
        or pre_identity_policy != fresh_plan.get("policy_provenance")
    ):
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    trusted_authors = _trusted_request_authors(pre_identity_policy)
    if trusted_authors is None:
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    allowed_actions = pre_identity_policy.get("allowed_actions")
    if not isinstance(allowed_actions, list) or ACTION not in allowed_actions:
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result

    try:
        posting_login = get_authenticated_github_login()
    except Exception:
        result["failure_reason"] = "GITHUB_POSTING_IDENTITY_UNAVAILABLE"
        return result
    if posting_login not in trusted_authors:
        result["failure_reason"] = "GITHUB_POSTING_IDENTITY_NOT_TRUSTED"
        return result

    # Review-thread resolution is mutable independently of the PR head. Refresh
    # it after identity lookup so a finding resolved since the evidence sweep no
    # longer authorizes the write-triggering request.
    try:
        final_reviews = get_pr_reviews(owner, repo, pr_number)
        final_threads = get_pr_review_threads_graphql(owner, repo, pr_number)
        final_review_inspection = {
            "reviews": final_reviews,
            "review_threads_graphql": final_threads,
        }
        if not _has_current_head_codex_finding(
            final_review_inspection, source_head
        ):
            result["final_outcome"] = "NOOP"
            result["failure_reason"] = "NO_UNRESOLVED_CURRENT_HEAD_CODEX_FINDING"
            return result
    except (TypeError, ValueError):
        result["failure_reason"] = "REVIEW_EVIDENCE_MALFORMED"
        return result
    except Exception:
        result["failure_reason"] = "REVIEW_EVIDENCE_UNAVAILABLE"
        return result

    # Final target/policy gate follows the refreshed review evidence.
    try:
        final_pr = get_pr_details(owner, repo, pr_number)
    except Exception:
        result["failure_reason"] = "FINAL_TARGET_READ_FAILED"
        return result
    snapshot_error = _validate_safe_pr_snapshot(final_pr, source_head, expected_repo)
    if snapshot_error is not None:
        result["failure_reason"] = snapshot_error
        return result
    base_error = _validate_planned_base_snapshot(
        final_pr, fresh_base_ref, fresh_base_repo, fresh_base_sha
    )
    if base_error is not None:
        result["failure_reason"] = base_error
        return result

    final_policy = load_policy(policy_path)
    if not isinstance(final_policy, Mapping) or final_policy != pre_identity_policy:
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result
    final_trusted = _trusted_request_authors(final_policy)
    final_allowed = final_policy.get("allowed_actions")
    if (
        final_trusted is None
        or posting_login not in final_trusted
        or not isinstance(final_allowed, list)
        or ACTION not in final_allowed
    ):
        result["failure_reason"] = "POLICY_CHANGED_BEFORE_MUTATION"
        return result

    # Actions runs can be re-run without changing the PR head. Refresh the
    # exact-head pull_request evidence at the final mutation gate so a run that
    # has become pending or failed cannot leave stale PASS authorization.
    try:
        final_actions = get_actions_runs(owner, repo, source_head)
        final_actions_ci_status = evaluate_actions_ci(final_actions, source_head)
    except Exception:
        final_actions_ci_status = "UNAVAILABLE"
    if final_actions_ci_status != "PASS":
        result["failure_reason"] = "EXACT_HEAD_CI_NOT_PASS"
        return result

    try:
        result["mutation_attempted"] = True
        result["mutation_type"] = ACTION
        post_codex_remediation_request(owner, repo, pr_number, source_head)
    except Exception:
        result["failure_reason"] = "REMEDIATION_REQUEST_POST_FAILED"
        return result

    try:
        comments = get_pr_issue_comments(owner, repo, pr_number)
        if not isinstance(comments, list):
            raise ValueError("issue comments malformed")
        if not _has_same_source_head_request(comments, source_head, (posting_login,)):
            result["failure_reason"] = "POSTCONDITION_NOT_OBSERVED"
            result["postcondition_result"] = "FAILED"
            return result
    except Exception:
        result["failure_reason"] = "POSTCONDITION_READ_FAILED"
        result["postcondition_result"] = "UNCERTAIN"
        return result

    # Observing the marker proves publication only for the target state that was
    # authorized. Revalidate that state after the POST so head/base/state drift
    # during the mutation is not reported as a successful request publication.
    try:
        postcondition_pr = get_pr_details(owner, repo, pr_number)
    except Exception:
        result["failure_reason"] = "POSTCONDITION_TARGET_READ_FAILED"
        result["postcondition_result"] = "UNCERTAIN"
        return result
    snapshot_error = _validate_safe_pr_snapshot(
        postcondition_pr, source_head, expected_repo
    )
    if snapshot_error is not None:
        result["failure_reason"] = snapshot_error
        result["postcondition_result"] = "FAILED"
        return result
    base_error = _validate_planned_base_snapshot(
        postcondition_pr, fresh_base_ref, fresh_base_repo, fresh_base_sha
    )
    if base_error is not None:
        result["failure_reason"] = base_error
        result["postcondition_result"] = "FAILED"
        return result

    result["postcondition_result"] = "REQUEST_PUBLISHED"
    result["final_outcome"] = "PASS"
    return result
