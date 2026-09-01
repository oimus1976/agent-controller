import fnmatch
import json
import math
import os
import urllib.error
import urllib.request


DEFAULT_GITHUB_REQUEST_TIMEOUT_SECONDS = 30.0


def _validated_request_timeout(timeout=DEFAULT_GITHUB_REQUEST_TIMEOUT_SECONDS):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("GitHub request timeout must be a finite positive number")
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("GitHub request timeout must be a finite positive number")
    return timeout


def _github_api_request_paginated(url, headers=None, timeout=DEFAULT_GITHUB_REQUEST_TIMEOUT_SECONDS):
    """Make a paginated request to the GitHub API with a finite per-request timeout."""
    request_timeout = _validated_request_timeout(timeout)
    results = []
    current_url = url

    while current_url:
        req = urllib.request.Request(current_url)
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github.v3+json")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=request_timeout) as response:
                data = json.loads(response.read().decode())
                if isinstance(data, list):
                    results.extend(data)
                else:
                    return data

                link_header = response.headers.get("Link")
                current_url = None
                if link_header:
                    links = link_header.split(",")
                    for link in links:
                        parts = link.split(";")
                        if len(parts) == 2 and 'rel="next"' in parts[1]:
                            current_url = parts[0].strip("<> ")
                            break
        except urllib.error.HTTPError as e:
            raise Exception(
                f"GitHub API Error: {e.code} {e.reason} for URL {current_url or url}"
            )

    return results


def _github_api_request(url, timeout=DEFAULT_GITHUB_REQUEST_TIMEOUT_SECONDS):
    """Make a request to the GitHub API."""
    return _github_api_request_paginated(url, timeout=timeout)


def _github_graphql_request(
    query, variables=None, timeout=DEFAULT_GITHUB_REQUEST_TIMEOUT_SECONDS
):
    """Make a request to the GitHub GraphQL API with a finite timeout."""
    request_timeout = _validated_request_timeout(timeout)
    url = "https://api.github.com/graphql"
    req = urllib.request.Request(url, method="POST")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    data = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    try:
        with urllib.request.urlopen(req, data=data, timeout=request_timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        raise Exception(f"GitHub GraphQL API Error: {e.code} {e.reason}")


def get_pr_review_threads_graphql(owner, repo, pr_number):
    query = """
    query($owner: String!, $repo: String!, $pr: Int!, $cursor: String) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $pr) {
          reviewThreads(first: 100, after: $cursor) {
            pageInfo { hasNextPage, endCursor }
            nodes {
              id
              isResolved
              comments(first: 100) {
                pageInfo { hasNextPage, endCursor }
                nodes {
                  author { login }
                  originalCommit { oid }
                  pullRequestReview { databaseId }
                  body
                }
              }
            }
          }
        }
      }
    }
    """

    comment_query = """
    query($threadId: ID!, $cursor: String) {
      node(id: $threadId) {
        ... on PullRequestReviewThread {
          comments(first: 100, after: $cursor) {
            pageInfo { hasNextPage, endCursor }
            nodes {
              author { login }
              originalCommit { oid }
              pullRequestReview { databaseId }
              body
            }
          }
        }
      }
    }
    """

    all_threads = []
    has_next_thread = True
    thread_cursor = None

    while has_next_thread:
        variables = {
            "owner": owner,
            "repo": repo,
            "pr": pr_number,
            "cursor": thread_cursor,
        }
        response = _github_graphql_request(query, variables)

        try:
            threads_data = response["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes = threads_data["nodes"]
            for thread in nodes:
                has_next_comment = thread["comments"]["pageInfo"]["hasNextPage"]
                comment_cursor = thread["comments"]["pageInfo"]["endCursor"]

                while has_next_comment:
                    c_vars = {"threadId": thread["id"], "cursor": comment_cursor}
                    c_resp = _github_graphql_request(comment_query, c_vars)
                    c_data = c_resp["data"]["node"]["comments"]
                    thread["comments"]["nodes"].extend(c_data["nodes"])
                    has_next_comment = c_data["pageInfo"]["hasNextPage"]
                    comment_cursor = c_data["pageInfo"]["endCursor"]

                all_threads.append(thread)

            has_next_thread = threads_data["pageInfo"]["hasNextPage"]
            thread_cursor = threads_data["pageInfo"]["endCursor"]
        except (KeyError, TypeError) as e:
            raise Exception("GraphQL response structure unexpected: " + str(e))

    return all_threads


def get_pr_details(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    return _github_api_request(url)


def get_pr_files(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files?per_page=100"
    return _github_api_request_paginated(url)


def get_pr_reviews(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews?per_page=100"
    return _github_api_request(url)


def get_pr_review_comments(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments?per_page=100"
    return _github_api_request_paginated(
        url, headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"}
    )


def get_pr_issue_comments(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments?per_page=100"
    return _github_api_request_paginated(
        url, headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"}
    )


def get_pr_commits(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/commits"
    return _github_api_request(url)


def get_issue_comment_reactions(owner, repo, comment_id):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/comments/{comment_id}/reactions?per_page=100"
    return _github_api_request_paginated(
        url, headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"}
    )


def get_actions_runs(owner, repo, ref):
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
        f"?head_sha={ref}&event=pull_request&per_page=100"
    )
    return _github_api_request(url)


def evaluate_actions_ci(actions_response, expected_head_sha):
    """Return PASS/FAIL/PENDING/MISSING/UNAVAILABLE for exact-head PR Actions runs."""
    if not isinstance(actions_response, dict):
        return "UNAVAILABLE"

    runs = actions_response.get("workflow_runs")
    total_count = actions_response.get("total_count")
    if not isinstance(runs, list) or not isinstance(total_count, int) or total_count < 0:
        return "UNAVAILABLE"
    if total_count != len(runs):
        return "UNAVAILABLE"
    if not runs:
        return "MISSING"

    saw_pending = False
    saw_failure = False
    for run in runs:
        if not isinstance(run, dict):
            return "UNAVAILABLE"
        if run.get("head_sha") != expected_head_sha or run.get("event") != "pull_request":
            return "UNAVAILABLE"

        status = run.get("status")
        if not isinstance(status, str):
            return "UNAVAILABLE"
        if status != "completed":
            saw_pending = True
            continue

        conclusion = run.get("conclusion")
        if conclusion != "success":
            saw_failure = True

    if saw_failure:
        return "FAIL"
    if saw_pending:
        return "PENDING"
    return "PASS"


def evaluate_scope(files, policy):
    if not policy or (
        policy.get("allowed_paths") is None
        and policy.get("denied_paths") is None
        and not policy.get("allow_docs_only")
    ):
        return "UNKNOWN"

    if not files:
        return "UNKNOWN"

    allowed_paths = policy.get("allowed_paths") or []
    denied_paths = policy.get("denied_paths") or []
    allow_docs_only = policy.get("allow_docs_only", False)

    docs_extensions = [".md", ".txt", ".json", ".yml", ".yaml", ".ini", ".cfg", ".toml"]
    has_non_doc_change = False

    for f in files:
        filename = f.get("filename", "")

        for pattern in denied_paths:
            if fnmatch.fnmatch(filename, pattern):
                return "VIOLATION"

        if allowed_paths:
            matched = False
            for pattern in allowed_paths:
                if fnmatch.fnmatch(filename, pattern):
                    matched = True
                    break
            if not matched:
                return "VIOLATION"

        if f.get("changes", 0) > 0:
            _, ext = os.path.splitext(filename)
            if ext.lower() not in docs_extensions:
                has_non_doc_change = True

    if not allowed_paths and not allow_docs_only and not has_non_doc_change:
        return "VIOLATION"

    return "SATISFIED"


def inspect_pr(owner, repo, pr_number, scope_policy=None):
    """Inspects a GitHub PR for objective evidence and classifies its state."""
    if scope_policy is None:
        scope_policy = {}

    pr_data = get_pr_details(owner, repo, pr_number)

    head_sha = pr_data.get("head", {}).get("sha")
    base_branch = pr_data.get("base", {}).get("ref")
    is_draft = pr_data.get("draft")
    is_merged = pr_data.get("merged")
    state = pr_data.get("state")
    changed_files = pr_data.get("changed_files", 0)

    reviews = get_pr_reviews(owner, repo, pr_number)
    review_comments = get_pr_review_comments(owner, repo, pr_number)
    issue_comments = get_pr_issue_comments(owner, repo, pr_number)

    for comment in issue_comments:
        comment_id = comment.get("id")
        if comment_id:
            try:
                reactions = get_issue_comment_reactions(owner, repo, comment_id)
                comment["reactions"] = reactions
            except Exception:
                comment["reactions"] = []

    files = get_pr_files(owner, repo, pr_number)

    diff_summary = []
    if isinstance(files, list):
        for f in files:
            filename = f.get("filename", "")
            status = f.get("status", "")
            changes = f.get("changes", 0)
            diff_summary.append(
                {
                    "filename": filename,
                    "status": status,
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "changes": changes,
                }
            )

    scope_status = evaluate_scope(files, scope_policy)

    graphql_error = False
    try:
        review_threads_graphql = get_pr_review_threads_graphql(owner, repo, pr_number)
    except Exception:
        review_threads_graphql = None
        graphql_error = True

    actions_ci_status = "UNAVAILABLE"
    actions_runs = None
    try:
        actions_runs = get_actions_runs(owner, repo, head_sha)
        actions_ci_status = evaluate_actions_ci(actions_runs, head_sha)
    except Exception:
        actions_runs = None
        actions_ci_status = "UNAVAILABLE"

    evidence = {
        "head_sha": head_sha,
        "base_branch": base_branch,
        "draft": is_draft,
        "merged": is_merged,
        "state": state,
        "changed_files": changed_files,
        "files": files,
        "diff_summary": diff_summary,
        "scope_status": scope_status,
        "reviews": reviews,
        "review_comments": review_comments,
        "issue_comments": issue_comments,
        "review_threads_graphql": review_threads_graphql,
        "graphql_error": graphql_error,
        "actions_runs": actions_runs,
        "actions_ci_status": actions_ci_status,
        "check_runs_error": actions_ci_status == "UNAVAILABLE",
        "check_runs": None,
    }

    evidence["classification"] = classify_pr(evidence)
    return evidence


def classify_pr(evidence):
    head_sha = evidence.get("head_sha")

    has_clean_codex_review_on_head = False
    has_unresolved_codex_findings_on_head = False
    has_changes_requested_on_head = False

    issue_comments = evidence.get("issue_comments", [])
    has_any_review = False

    for comment in issue_comments:
        body = comment.get("body", "")
        user = comment.get("user", {}).get("login", "")
        reactions = comment.get("reactions", [])

        if user == "chatgpt-codex-connector[bot]":
            has_any_review = True
            if head_sha and (head_sha in body or head_sha[:10] in body):
                if "Didn't find any major issues" in body:
                    has_clean_codex_review_on_head = True
        elif "@codex review" in body.lower():
            for reaction in reactions:
                reaction_user = reaction.get("user", {}).get("login")
                if reaction_user == "chatgpt-codex-connector[bot]" and reaction.get(
                    "content"
                ) in ["+1", "thumbsup", "👍"]:
                    has_any_review = True

    reviews = evidence.get("reviews", [])
    for review in reviews:
        user = review.get("user", {}).get("login", "")
        commit_id = review.get("commit_id")
        state = review.get("state")
        body = review.get("body", "")

        if user == "chatgpt-codex-connector[bot]":
            has_any_review = True
            if commit_id == head_sha or (
                head_sha and (head_sha in body or head_sha[:10] in body)
            ):
                if state == "APPROVED" or "Didn't find any major issues" in body:
                    has_clean_codex_review_on_head = True
                elif state == "CHANGES_REQUESTED":
                    has_changes_requested_on_head = True

    if not evidence.get("graphql_error"):
        review_threads_graphql = evidence.get("review_threads_graphql")
        if review_threads_graphql is not None:
            for thread in review_threads_graphql:
                if not thread.get("isResolved"):
                    comments = thread.get("comments", {}).get("nodes", [])
                    for comment in comments:
                        author = comment.get("author") or {}
                        login = author.get("login")
                        if login == "chatgpt-codex-connector[bot]":
                            original_commit_oid = comment.get("originalCommit", {}).get("oid")
                            if original_commit_oid == head_sha:
                                has_unresolved_codex_findings_on_head = True
                                break
        else:
            review_comments = evidence.get("review_comments", [])
            for comment in review_comments:
                user = comment.get("user", {}).get("login", "")
                commit_id = comment.get("commit_id")

                if user == "chatgpt-codex-connector[bot]" and commit_id == head_sha:
                    has_unresolved_codex_findings_on_head = True

    if evidence.get("merged") or evidence.get("state") == "closed":
        return "CLOSED"

    if evidence.get("scope_status") != "SATISFIED":
        return "NEEDS_REVIEW"

    if has_unresolved_codex_findings_on_head or has_changes_requested_on_head:
        return "NEEDS_REVIEW"

    if evidence.get("graphql_error"):
        return "NEEDS_REVIEW"

    ci_status = evidence.get("actions_ci_status")
    if ci_status is None:
        ci_status = "UNAVAILABLE" if evidence.get("check_runs_error") else "PASS"

    if ci_status != "PASS":
        return "NEEDS_REVIEW"

    if has_clean_codex_review_on_head:
        return "REVIEW_READY"

    if evidence.get("state") == "open" and not evidence.get("merged"):
        if not has_any_review:
            return "IMPLEMENTATION_READY"

    return "NEEDS_REVIEW"
