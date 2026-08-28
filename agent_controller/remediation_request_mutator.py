from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request


_HEAD_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def codex_remediation_request_marker(source_head_sha: str) -> str:
    if not isinstance(source_head_sha, str) or not _HEAD_SHA_RE.fullmatch(source_head_sha):
        raise ValueError("source_head_sha must be a 40-character lowercase hex SHA")
    return (
        "<!-- agent-controller:codex-remediation-request "
        f"source_head={source_head_sha} -->"
    )


def codex_remediation_request_body(source_head_sha: str) -> str:
    """Return the only remediation comment body this capability may post."""

    return (
        "@codex address that feedback\n\n"
        f"{codex_remediation_request_marker(source_head_sha)}"
    )


def post_codex_remediation_request(
    owner: str,
    repo: str,
    pr_number: int,
    source_head_sha: str,
):
    """Post one fixed, source-head-bound Codex remediation command.

    This intentionally exposes no caller-controlled comment body. Authentication
    identity must be resolved and allowlisted by the caller immediately before
    entering this mutation boundary.
    """

    if not isinstance(owner, str) or not owner:
        raise ValueError("owner must be nonempty")
    if not isinstance(repo, str) or not repo:
        raise ValueError("repo must be nonempty")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        raise ValueError("pr_number must be a positive integer")

    body = codex_remediation_request_body(source_head_sha)
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
        raise RuntimeError(
            f"GitHub API Error: {exc.code} {exc.reason} while requesting Codex remediation"
        ) from exc
