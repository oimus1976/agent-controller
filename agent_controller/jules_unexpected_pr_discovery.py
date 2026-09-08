from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Protocol, Sequence
from urllib.parse import urlparse


class JulesPRDiscoveryClassification(str, Enum):
    WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN = "WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN"
    BOUND_BRANCH_ADVANCED = "BOUND_BRANCH_ADVANCED"
    UNEXPECTED_PROVIDER_PR_EXPOSED = "UNEXPECTED_PROVIDER_PR_EXPOSED"
    PUBLICATION_AMBIGUOUS = "PUBLICATION_AMBIGUOUS"


@dataclass(frozen=True)
class PullRequestFact:
    repo: str
    number: int
    base_ref: str
    head_ref: str
    head_sha: str
    draft: bool
    open: bool
    merged: bool
    head_repo: str | None = None


@dataclass(frozen=True)
class JulesPRDiscoveryResult:
    classification: JulesPRDiscoveryClassification
    guidance: str
    pull_request: PullRequestFact | None = None


class JulesPRDiscoveryClient(Protocol):
    def get_pull_request(self, repo: str, pr_number: int) -> PullRequestFact:
        ...

    def find_pull_requests_by_head(self, repo: str, head_ref: str) -> Sequence[PullRequestFact]:
        ...

    def is_ancestor(self, repo: str, ancestor_sha: str, descendant_sha: str) -> bool:
        ...


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PR_PATH_RE = re.compile(r"^/([^/]+)/([^/]+)/pull/(\d+)/?$")


def _valid_sha(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA_RE.fullmatch(value))


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _normalize_ref(value: str) -> str:
    for prefix in ("refs/heads/", "heads/"):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _valid_pr_fact(fact: PullRequestFact) -> bool:
    return (
        _nonempty(fact.repo)
        and type(fact.number) is int
        and fact.number > 0
        and _nonempty(fact.base_ref)
        and _nonempty(fact.head_ref)
        and _valid_sha(fact.head_sha)
        and _nonempty(fact.head_repo)
        and type(fact.draft) is bool
        and type(fact.open) is bool
        and type(fact.merged) is bool
        and not (fact.open and fact.merged)
        and not (fact.merged and fact.draft)
    )


def _parse_exact_github_pr_url(url: str, expected_repo: str) -> int | None:
    if not _nonempty(url):
        return None
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        return None
    if parsed.query or parsed.fragment or parsed.params:
        return None
    match = _PR_PATH_RE.fullmatch(parsed.path)
    if match is None:
        return None
    owner, name, number_text = match.groups()
    if f"{owner}/{name}" != expected_repo:
        return None
    number = int(number_text)
    return number if number > 0 else None


def _verify_candidate(
    *,
    fact: PullRequestFact,
    repo: str,
    expected_base_ref: str,
    expected_start_sha: str,
    client: JulesPRDiscoveryClient,
    expected_head_ref: str | None = None,
) -> JulesPRDiscoveryResult | None:
    if not isinstance(fact, PullRequestFact) or not _valid_pr_fact(fact):
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "malformed GitHub PR evidence; fail closed.",
        )
    if fact.repo != repo:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "cross-repository PR evidence cannot be adopted.",
        )
    if fact.head_repo != repo:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "foreign head-repository PR evidence cannot establish Jules publication identity; fail closed.",
        )
    if expected_head_ref is not None and _normalize_ref(fact.head_ref) != _normalize_ref(expected_head_ref):
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "provider-reported PR identity disagrees with provider-reported branch; fail closed.",
        )
    if _normalize_ref(fact.base_ref) != _normalize_ref(expected_base_ref):
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "provider-created PR is attached to an unexpected PR base; fail closed.",
        )
    try:
        ancestry_ok = client.is_ancestor(repo, expected_start_sha, fact.head_sha)
    except Exception:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "GitHub ancestry verification failed; publication remains ambiguous.",
        )
    if ancestry_ok is not True:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "provider-created PR head is not proven to descend from the bound starting SHA.",
        )
    return None


def _exposed_result(fact: PullRequestFact, source: str) -> JulesPRDiscoveryResult:
    ready_note = (
        "observed non-Draft provider effect; this is not Controller-authorized Ready"
        if not fact.draft
        else "observed Draft PR"
    )
    return JulesPRDiscoveryResult(
        JulesPRDiscoveryClassification.UNEXPECTED_PROVIDER_PR_EXPOSED,
        f"unexpected provider-created PR discovered from {source} ({ready_note}); treat its head as new untrusted evidence and restart scope/CI/review from scratch; no adoption or mutation.",
        pull_request=fact,
    )


def discover_unexpected_jules_pr(
    *,
    provider: str,
    repo: str,
    bound_branch: str,
    authoritative_baseline_bound_sha: str,
    authoritative_current_bound_sha: str,
    expected_base_ref: str,
    expected_start_sha: str,
    provider_reported_completion: bool,
    provider_reported_branch: str | None,
    provider_reported_pull_request_url: str | None = None,
    client: JulesPRDiscoveryClient,
) -> JulesPRDiscoveryResult:
    """Discover a distinct Jules-created PR without confusing provider and GitHub readiness.

    Prefer the official terminal Session.outputs.pullRequest identity when present,
    then verify that exact PR independently in GitHub. Exact provider-branch search is
    only a bounded fallback when no terminal pullRequest output exists. This function
    is observation-only; provider completion/UI readiness never authorizes GitHub
    Draft=false, Ready, merge, or adoption.
    """

    if provider != "jules":
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "provider boundary mismatch; no PR adoption or mutation recommendation.",
        )

    identities = (repo, bound_branch, expected_base_ref)
    if not all(_nonempty(value) for value in identities):
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "malformed repository/ref binding; fail closed.",
        )
    if not all(
        _valid_sha(value)
        for value in (
            authoritative_baseline_bound_sha,
            authoritative_current_bound_sha,
            expected_start_sha,
        )
    ):
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "malformed SHA binding; fail closed.",
        )
    if type(provider_reported_completion) is not bool:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "malformed provider completion evidence; fail closed.",
        )

    if authoritative_current_bound_sha != authoritative_baseline_bound_sha:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.BOUND_BRANCH_ADVANCED,
            "bound branch advanced; treat the new head as untrusted and restart scope/CI/review evidence.",
        )

    if provider_reported_pull_request_url is not None:
        pr_number = _parse_exact_github_pr_url(provider_reported_pull_request_url, repo)
        if pr_number is None:
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                "malformed or cross-repository Jules terminal pullRequest output; fail closed instead of guessing by branch.",
            )
        try:
            fact = client.get_pull_request(repo, pr_number)
        except Exception:
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                "GitHub read of Jules terminal pullRequest output failed; publication remains ambiguous.",
            )
        if not isinstance(fact, PullRequestFact) or not _valid_pr_fact(fact):
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                "malformed GitHub PR evidence from Jules terminal pullRequest; fail closed.",
            )
        if _normalize_ref(fact.head_ref) == _normalize_ref(bound_branch):
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                "Jules terminal pullRequest resolves to the Controller-bound branch; it is not an unexpected provider PR and must be reconciled through bound-branch observation.",
            )
        mismatch = _verify_candidate(
            fact=fact,
            repo=repo,
            expected_base_ref=expected_base_ref,
            expected_start_sha=expected_start_sha,
            client=client,
            expected_head_ref=provider_reported_branch,
        )
        if mismatch is not None:
            return mismatch
        return _exposed_result(fact, "Jules terminal Session.outputs.pullRequest")

    if provider_reported_branch is None:
        if provider_reported_completion:
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
                "provider workspace may be complete, but terminal PR output and bounded GitHub publication identity are unknown; unchanged bound PR is not evidence of empty work.",
            )
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "no terminal PR output or exact distinct provider branch is available for bounded PR discovery.",
        )

    if not _nonempty(provider_reported_branch):
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "malformed provider branch evidence; fail closed.",
        )

    if _normalize_ref(provider_reported_branch) == _normalize_ref(bound_branch):
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "provider-reported branch is not distinct from the Controller-bound branch.",
        )

    try:
        candidates = tuple(client.find_pull_requests_by_head(repo, provider_reported_branch))
    except Exception:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "GitHub PR discovery failed; publication remains ambiguous.",
        )

    exact: list[PullRequestFact] = []
    for fact in candidates:
        if not isinstance(fact, PullRequestFact) or not _valid_pr_fact(fact):
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                "malformed GitHub PR evidence; fail closed.",
            )
        if fact.repo != repo:
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                "cross-repository PR evidence cannot be adopted.",
            )
        if _normalize_ref(fact.head_ref) != _normalize_ref(provider_reported_branch):
            continue
        mismatch = _verify_candidate(
            fact=fact,
            repo=repo,
            expected_base_ref=expected_base_ref,
            expected_start_sha=expected_start_sha,
            client=client,
            expected_head_ref=provider_reported_branch,
        )
        if mismatch is not None:
            return mismatch
        exact.append(fact)

    if len(exact) == 1:
        return _exposed_result(exact[0], "bounded provider-branch fallback")

    if len(exact) > 1:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "multiple exact provider-branch PR candidates exist; fail closed.",
        )

    if provider_reported_completion:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
            "provider workspace may be complete, but no terminal PR output or exactly bound distinct PR was discovered; unchanged bound PR is not evidence of empty work.",
        )

    return JulesPRDiscoveryResult(
        JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        "no terminal PR output or exactly bound distinct PR was discovered and provider completion is not established.",
    )
