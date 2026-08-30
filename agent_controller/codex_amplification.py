from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from typing import Any, Iterable, Mapping

from .executor import load_policy
from .inspector import get_pr_issue_comments, get_pr_reviews
from .review_request import _trusted_request_authors


_REVIEW_MARKER_RE = re.compile(
    r"<!--\s*agent-controller:codex-review-request\s+head=([0-9a-f]{40})\s*-->"
)
_REMEDIATION_MARKER_RE = re.compile(
    r"<!--\s*agent-controller:codex-remediation-request\s+source_head=([0-9a-f]{40})\s*-->"
)
_CODEX_BOT_LOGINS = {
    "chatgpt-codex-connector[bot]",
    "chatgpt-codex-connector",
}


def _login(item: Mapping[str, Any]) -> str | None:
    user = item.get("user")
    if not isinstance(user, Mapping):
        return None
    login = user.get("login")
    return login if isinstance(login, str) and login else None


def _body(item: Mapping[str, Any]) -> str | None:
    body = item.get("body")
    return body if isinstance(body, str) else None


def _marker_shas(body: str, pattern: re.Pattern[str]) -> list[str]:
    return pattern.findall(body)


def _duplicate_count(counter: Counter[str]) -> int:
    return sum(max(0, count - 1) for count in counter.values())


def analyze_codex_request_amplification(
    *,
    issue_comments: Iterable[Mapping[str, Any]],
    reviews: Iterable[Mapping[str, Any]],
    trusted_request_authors: tuple[str, ...],
) -> dict[str, Any]:
    """Summarize GitHub-observable Codex request amplification for one PR.

    This reports trigger/request history only. It intentionally does not convert
    request counts into provider turns, tokens, allowance units, or cost.
    """

    if not isinstance(trusted_request_authors, tuple) or not trusted_request_authors:
        raise ValueError("trusted_request_authors must be a nonempty tuple")
    if any(not isinstance(author, str) or not author for author in trusted_request_authors):
        raise ValueError("trusted_request_authors is malformed")

    trusted = set(trusted_request_authors)
    review_requests: Counter[str] = Counter()
    remediation_requests: Counter[str] = Counter()
    codex_reviews: Counter[str] = Counter()
    uncertainties: list[str] = []

    request_surfaces = (
        ("issue_comment", list(issue_comments)),
        ("review", list(reviews)),
    )

    for surface_name, items in request_surfaces:
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                uncertainties.append(f"{surface_name}[{index}]:MALFORMED_ITEM")
                continue
            login = _login(item)
            body = _body(item)
            if login is None:
                uncertainties.append(f"{surface_name}[{index}]:MISSING_AUTHOR")
                continue
            if body is None:
                # Empty review bodies are legitimate for non-request reviews.
                body = ""

            if login in trusted:
                review_shas = _marker_shas(body, _REVIEW_MARKER_RE)
                remediation_shas = _marker_shas(body, _REMEDIATION_MARKER_RE)
                for sha in review_shas:
                    if "@codex review" not in body.lower():
                        uncertainties.append(
                            f"{surface_name}[{index}]:REVIEW_MARKER_WITHOUT_COMMAND"
                        )
                        continue
                    review_requests[sha] += 1
                for sha in remediation_shas:
                    if "@codex address that feedback" not in body.lower():
                        uncertainties.append(
                            f"{surface_name}[{index}]:REMEDIATION_MARKER_WITHOUT_COMMAND"
                        )
                        continue
                    remediation_requests[sha] += 1

    for index, review in enumerate(list(reviews)):
        if not isinstance(review, Mapping):
            continue
        login = _login(review)
        if login not in _CODEX_BOT_LOGINS:
            continue
        commit_id = review.get("commit_id")
        if not isinstance(commit_id, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_id):
            uncertainties.append(f"review[{index}]:CODEX_REVIEW_MISSING_EXACT_COMMIT")
            continue
        codex_reviews[commit_id] += 1

    all_heads = sorted(
        set(review_requests) | set(remediation_requests) | set(codex_reviews)
    )
    by_head = []
    for sha in all_heads:
        by_head.append(
            {
                "head_sha": sha,
                "review_request_count": review_requests.get(sha, 0),
                "remediation_request_count": remediation_requests.get(sha, 0),
                "codex_review_submission_count": codex_reviews.get(sha, 0),
            }
        )

    return {
        "status": "UNCERTAIN" if uncertainties else "OBSERVED",
        "semantics": "GITHUB_REQUEST_AMPLIFICATION_NOT_PROVIDER_USAGE",
        "review_request_count": sum(review_requests.values()),
        "remediation_request_count": sum(remediation_requests.values()),
        "codex_review_submission_count": sum(codex_reviews.values()),
        "distinct_reviewed_head_count": len(codex_reviews),
        "distinct_loop_head_count": len(all_heads),
        "same_head_duplicate_review_request_count": _duplicate_count(review_requests),
        "same_head_duplicate_remediation_request_count": _duplicate_count(
            remediation_requests
        ),
        "same_head_duplicate_codex_review_submission_count": _duplicate_count(
            codex_reviews
        ),
        "by_head": by_head,
        "uncertainties": uncertainties,
        "provider_turn_count": None,
        "token_fields": None,
        "allowance_units": None,
    }


def collect_codex_request_amplification(
    *, owner: str, repo: str, pr_number: int, policy_path: str
) -> dict[str, Any]:
    if not owner or not repo:
        raise ValueError("owner and repo must be nonempty")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
        raise ValueError("pr_number must be a positive integer")

    policy = load_policy(policy_path)
    if not isinstance(policy, Mapping):
        return {
            "status": "UNCERTAIN",
            "reason": "MISSING_OR_MALFORMED_POLICY",
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
        }
    trusted = _trusted_request_authors(policy)
    if trusted is None:
        return {
            "status": "UNCERTAIN",
            "reason": "MISSING_OR_MALFORMED_TRUSTED_REQUEST_AUTHORS",
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
        }

    try:
        issue_comments = get_pr_issue_comments(owner, repo, pr_number)
        reviews = get_pr_reviews(owner, repo, pr_number)
    except Exception as exc:
        return {
            "status": "UNCERTAIN",
            "reason": f"EVIDENCE_FETCH_FAILED: {exc}",
            "repo": f"{owner}/{repo}",
            "pr": pr_number,
        }

    observation = analyze_codex_request_amplification(
        issue_comments=issue_comments,
        reviews=reviews,
        trusted_request_authors=trusted,
    )
    observation["repo"] = f"{owner}/{repo}"
    observation["pr"] = pr_number
    return observation


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report GitHub-observable Codex request amplification for one PR"
    )
    parser.add_argument("--repo", required=True, help="Repository in OWNER/REPO form")
    parser.add_argument("--pr", required=True, type=int, help="Pull request number")
    parser.add_argument(
        "--policy",
        required=True,
        help="Policy JSON containing trusted_review_request_authors",
    )
    args = parser.parse_args()

    parts = args.repo.split("/")
    if len(parts) != 2 or not all(parts):
        parser.error("--repo must be in OWNER/REPO format")

    result = collect_codex_request_amplification(
        owner=parts[0], repo=parts[1], pr_number=args.pr, policy_path=args.policy
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
