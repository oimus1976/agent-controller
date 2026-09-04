from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Protocol, Sequence


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


@dataclass(frozen=True)
class JulesPRDiscoveryResult:
    classification: JulesPRDiscoveryClassification
    guidance: str
    pull_request: PullRequestFact | None = None


class JulesPRDiscoveryClient(Protocol):
    def find_pull_requests_by_head(self, repo: str, head_ref: str) -> Sequence[PullRequestFact]:
        ...

    def is_ancestor(self, repo: str, ancestor_sha: str, descendant_sha: str) -> bool:
        ...


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


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
        and type(fact.draft) is bool
        and type(fact.open) is bool
        and type(fact.merged) is bool
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
    client: JulesPRDiscoveryClient,
) -> JulesPRDiscoveryResult:
    """Discover a distinct Jules-created PR without confusing provider and GitHub readiness.

    This function is observation-only. Provider completion / UI readiness is advisory
    and never authorizes or infers GitHub Draft=false, Ready, merge, or adoption.
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

    if provider_reported_branch is None:
        if provider_reported_completion:
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
                "provider workspace may be complete, but bounded GitHub publication identity is unknown; unchanged bound PR is not evidence of empty work.",
            )
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "no exact distinct provider branch is available for bounded PR discovery.",
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
        if _normalize_ref(fact.base_ref) != _normalize_ref(expected_base_ref):
            return JulesPRDiscoveryResult(
                JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
                "exact provider branch is attached to an unexpected PR base; fail closed.",
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
        exact.append(fact)

    if len(exact) == 1:
        fact = exact[0]
        ready_note = (
            "observed non-Draft provider effect; this is not Controller-authorized Ready"
            if not fact.draft
            else "observed Draft PR"
        )
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.UNEXPECTED_PROVIDER_PR_EXPOSED,
            f"unexpected provider-created PR discovered ({ready_note}); treat its head as new untrusted evidence and restart scope/CI/review from scratch; no adoption or mutation.",
            pull_request=fact,
        )

    if len(exact) > 1:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
            "multiple exact provider-branch PR candidates exist; fail closed.",
        )

    if provider_reported_completion:
        return JulesPRDiscoveryResult(
            JulesPRDiscoveryClassification.WORKSPACE_COMPLETE_PUBLICATION_UNKNOWN,
            "provider workspace may be complete, but no exactly bound distinct PR was discovered; unchanged bound PR is not evidence of empty work.",
        )

    return JulesPRDiscoveryResult(
        JulesPRDiscoveryClassification.PUBLICATION_AMBIGUOUS,
        "no exactly bound distinct PR was discovered and provider completion is not established.",
    )
