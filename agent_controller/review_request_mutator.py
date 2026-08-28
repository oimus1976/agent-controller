from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request


_HEAD_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def codex_review_request_marker(head_sha: str) -> str:
    if not isinstance(head_sha, str) or not _HEAD_SHA_RE.fullmatch(head_sha):
        raise ValueError("head_sha must be a 40-character lowercase hex SHA")
    return f"<!-- agent-controller:codex-review-request head={head_sha} -->"


def codex_review_request_body(head_sha: str) -> str:
    """Return the only comment body this capability is allowed to post."""

    return f"@codex review\n\n{codex_review_request_marker(head_sha)}"


def get_authenticated_github_login() -> str:
    """Return the login bound to the exact GITHUB_TOKEN used for the write path.

    Review-request dedup trusts only explicitly allowlisted Controller posting
    identities. Verify the actual token principal before the quota-consuming POST
    instead of discovering an identity mismatch after the side effect.
    """

    token = os.environ.get("GITHUB_TOKEN")
    if not isinstance(token, str) or not token:
        raise RuntimeError("GITHUB_TOKEN_REQUIRED")

    req = urllib.request.Request("https://api.github.com/user", method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    try:
        with urllib.request.urlopen(req) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"GitHub API Error: {exc.code} {exc.reason} while reading authenticated identity"
        ) from exc

    if not isinstance(payload, dict):
        raise RuntimeError("GITHUB_AUTH_IDENTITY_MALFORMED")
    login = payload.get("login")
    if not isinstance(login, str) or not login:
        raise RuntimeError("GITHUB_AUTH_IDENTITY_MALFORMED")
    return login


def post_codex_review_request(owner: str, repo: str, pr_number: int, head_sha: str):
    """Post exactly one narrow Codex review-trigger comment.

    This function intentionally exposes no generic comment body parameter. The
    Controller binds the request to an immutable head with a deterministic HTML
    marker so later instances can deduplicate from GitHub-authoritative evidence.
    Caller must verify the actual authenticated posting identity immediately
    before entering this quota-consuming mutation boundary.
    """

    if not isinstance(owner, str) or not owner:
        raise ValueError("owner must be nonempty")
    if not isinstance(repo, str) or not repo:
        raise ValueError("repo must be nonempty")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        raise ValueError("pr_number must be a positive integer")

    body = codex_review_request_body(head_sha)
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    req = urllib.request.Request(url, method="POST")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", "application/json")

    data = json.dumps({"body": body}).encode("utf-8")
    try:
        with urllib.request.urlopen(req, data=data) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise Exception(
            f"GitHub API Error: {exc.code} {exc.reason} while requesting Codex review"
        ) from exc
