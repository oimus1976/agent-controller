from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Callable, Mapping, Optional, Sequence

from agent_controller.workstream import WorkstreamBinding, validate_workstream_set


_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class CleanupCandidate:
    target_kind: str
    status: str
    reason: str
    repo: str
    pr_number: int
    branch: Optional[str] = None
    merged_pr_head: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LocalCloseoutEvidence:
    valid: bool
    reason: str
    task_head: Optional[str] = None


PrReader = Callable[[str, int], Mapping[str, Any]]
BranchReader = Callable[[str, str], Optional[str]]
OpenPrReader = Callable[[str], Sequence[Mapping[str, Any]]]
DefaultBranchReader = Callable[[str], str]
BranchProtectionReader = Callable[[str, str], bool]


def _normalize_branch(ref: str) -> str:
    if ref.startswith("refs/heads/"):
        return ref[len("refs/heads/") :]
    if ref.startswith("heads/"):
        return ref[len("heads/") :]
    return ref


def _active_branch_owner(
    *, repo: str, branch: str, active_workstreams: Sequence[WorkstreamBinding]
) -> bool:
    normalized = _normalize_branch(branch)
    for binding in active_workstreams:
        if binding.repo.casefold() != repo.casefold():
            continue
        for candidate in binding.branch_refs:
            if _normalize_branch(candidate) == normalized:
                return True
    return False


def _validate_active_set(active_workstreams: Sequence[WorkstreamBinding]) -> Optional[str]:
    validation = validate_workstream_set(active_workstreams)
    return None if validation.valid else validation.reason or "ACTIVE_WORKSTREAM_SET_INVALID"


def _extract_merged_pr_anchor(
    snapshot: Mapping[str, Any], *, repo: str, pr_number: int
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if not isinstance(snapshot, Mapping):
        return None, None, "PR_SNAPSHOT_MALFORMED"
    if snapshot.get("number") != pr_number:
        return None, None, "PR_NUMBER_MISMATCH"
    if snapshot.get("merged") is not True or snapshot.get("state") != "closed":
        return None, None, "PR_NOT_MERGED"

    if isinstance(snapshot.get("head"), Mapping):
        head = snapshot["head"]
        branch = head.get("ref")
        sha = head.get("sha")
        head_repo = head.get("repo")
        full_name = head_repo.get("full_name") if isinstance(head_repo, Mapping) else None
    else:
        branch = snapshot.get("head")
        sha = snapshot.get("head_sha")
        full_name = snapshot.get("head_repo_full_name")

    if not isinstance(branch, str) or not branch.strip():
        return None, None, "PR_HEAD_BRANCH_MISSING"
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        return None, None, "PR_HEAD_SHA_MALFORMED"
    if not isinstance(full_name, str) or full_name.casefold() != repo.casefold():
        return None, None, "PR_HEAD_REPO_MISMATCH"
    return _normalize_branch(branch.strip()), sha.lower(), None


def _open_pr_head_identity(item: Mapping[str, Any]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if item.get("state") != "open":
        return None, None, "OPEN_PR_EVIDENCE_MALFORMED"
    if isinstance(item.get("head"), Mapping):
        head = item["head"]
        branch = head.get("ref")
        head_repo = head.get("repo")
        repo = head_repo.get("full_name") if isinstance(head_repo, Mapping) else None
    else:
        branch = item.get("head")
        repo = item.get("head_repo_full_name")
    if not isinstance(branch, str) or not branch.strip() or not isinstance(repo, str) or not repo.strip():
        return None, None, "OPEN_PR_EVIDENCE_MALFORMED"
    return _normalize_branch(branch.strip()), repo, None


def assess_remote_branch_cleanup_candidate(
    *,
    repo: str,
    pr_number: int,
    active_workstreams: Sequence[WorkstreamBinding],
    read_pr: PrReader,
    read_branch_sha: BranchReader,
    list_open_prs: OpenPrReader,
    read_default_branch: DefaultBranchReader,
    read_branch_protected: BranchProtectionReader,
) -> CleanupCandidate:
    """Surface advisory remote-branch cleanup evidence; never delete anything."""
    try:
        active_error = _validate_active_set(active_workstreams)
        if active_error:
            return CleanupCandidate("remote_branch", "UNCERTAIN", active_error, repo, pr_number)

        snapshot = read_pr(repo, pr_number)
        branch, merged_head, error = _extract_merged_pr_anchor(snapshot, repo=repo, pr_number=pr_number)
        if error:
            status = "NOT_SAFE" if error == "PR_NOT_MERGED" else "UNCERTAIN"
            return CleanupCandidate("remote_branch", status, error, repo, pr_number)
        assert branch is not None and merged_head is not None

        default_branch = read_default_branch(repo)
        if not isinstance(default_branch, str) or not default_branch.strip():
            return CleanupCandidate("remote_branch", "UNCERTAIN", "DEFAULT_BRANCH_UNAVAILABLE", repo, pr_number, branch, merged_head)
        if _normalize_branch(default_branch.strip()) == branch or branch.casefold() in {"head", ".", ".."}:
            return CleanupCandidate("remote_branch", "NOT_SAFE", "CANONICAL_BRANCH", repo, pr_number, branch, merged_head)

        protected = read_branch_protected(repo, branch)
        if not isinstance(protected, bool):
            return CleanupCandidate("remote_branch", "UNCERTAIN", "BRANCH_PROTECTION_UNAVAILABLE", repo, pr_number, branch, merged_head)
        if protected:
            return CleanupCandidate("remote_branch", "NOT_SAFE", "PROTECTED_BRANCH", repo, pr_number, branch, merged_head)

        if _active_branch_owner(repo=repo, branch=branch, active_workstreams=active_workstreams):
            return CleanupCandidate("remote_branch", "NOT_SAFE", "ACTIVE_WORKSTREAM_OWNS_BRANCH", repo, pr_number, branch, merged_head)

        current_sha = read_branch_sha(repo, branch)
        if current_sha is None:
            return CleanupCandidate("remote_branch", "ALREADY_ABSENT", "REMOTE_BRANCH_ABSENT", repo, pr_number, branch, merged_head)
        if not isinstance(current_sha, str) or not _SHA_RE.fullmatch(current_sha):
            return CleanupCandidate("remote_branch", "UNCERTAIN", "REMOTE_BRANCH_SHA_MALFORMED", repo, pr_number, branch, merged_head)
        if current_sha.lower() != merged_head:
            return CleanupCandidate("remote_branch", "NOT_SAFE", "REMOTE_BRANCH_DRIFTED", repo, pr_number, branch, merged_head)

        open_prs = list_open_prs(repo)
        if not isinstance(open_prs, Sequence) or isinstance(open_prs, (str, bytes)):
            return CleanupCandidate("remote_branch", "UNCERTAIN", "OPEN_PR_EVIDENCE_MALFORMED", repo, pr_number, branch, merged_head)
        for item in open_prs:
            if not isinstance(item, Mapping):
                return CleanupCandidate("remote_branch", "UNCERTAIN", "OPEN_PR_EVIDENCE_MALFORMED", repo, pr_number, branch, merged_head)
            open_branch, open_repo, open_error = _open_pr_head_identity(item)
            if open_error:
                return CleanupCandidate("remote_branch", "UNCERTAIN", open_error, repo, pr_number, branch, merged_head)
            if open_branch == branch and open_repo is not None and open_repo.casefold() == repo.casefold():
                return CleanupCandidate("remote_branch", "NOT_SAFE", "OPEN_PR_USES_BRANCH", repo, pr_number, branch, merged_head)

        return CleanupCandidate("remote_branch", "SAFE_TO_CONSIDER", "EXACT_MERGED_BRANCH_UNOWNED", repo, pr_number, branch, merged_head)
    except Exception:
        return CleanupCandidate("remote_branch", "UNCERTAIN", "EXTERNAL_READ_UNCERTAINTY", repo, pr_number)


def parse_local_closeout_evidence(
    *, output: str, returncode: int, expected_pr_head: str
) -> LocalCloseoutEvidence:
    """Parse only the explicit PASS contract emitted by verify_local_closeout.py."""
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        return LocalCloseoutEvidence(False, "LOCAL_CLOSEOUT_RETURN_CODE_INVALID")
    if returncode != 0:
        return LocalCloseoutEvidence(False, "LOCAL_CLOSEOUT_FAILED")
    if not isinstance(expected_pr_head, str) or not _SHA_RE.fullmatch(expected_pr_head):
        return LocalCloseoutEvidence(False, "EXPECTED_PR_HEAD_INVALID")
    if not isinstance(output, str):
        return LocalCloseoutEvidence(False, "LOCAL_CLOSEOUT_OUTPUT_MALFORMED")

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    required = {
        "LOCAL CLOSEOUT: PASS",
        "task_worktree_role=topic",
        "task_worktree=clean",
        "expected_pr_head=matched",
        "canonical_worktree=ready",
        "freshness=canonical-branch-fetch-completed",
        "next_task_checkout=canonical-worktree",
    }
    if not required.issubset(set(lines)):
        return LocalCloseoutEvidence(False, "LOCAL_CLOSEOUT_PASS_EVIDENCE_INCOMPLETE")

    task_heads = [line.split("=", 1)[1] for line in lines if line.startswith("task_head=")]
    if len(task_heads) != 1 or not _SHA_RE.fullmatch(task_heads[0]):
        return LocalCloseoutEvidence(False, "LOCAL_CLOSEOUT_TASK_HEAD_MALFORMED")
    task_head = task_heads[0].lower()
    if task_head != expected_pr_head.lower():
        return LocalCloseoutEvidence(False, "LOCAL_CLOSEOUT_HEAD_MISMATCH", task_head)
    return LocalCloseoutEvidence(True, "LOCAL_CLOSEOUT_VERIFIED", task_head)


def assess_local_worktree_cleanup_candidate(
    *,
    repo: str,
    pr_number: int,
    topic_branch: str,
    merged_pr_head: str,
    active_workstreams: Sequence[WorkstreamBinding],
    closeout_output: str,
    closeout_returncode: int,
) -> CleanupCandidate:
    """Surface advisory local-worktree cleanup evidence from explicit closeout PASS only."""
    active_error = _validate_active_set(active_workstreams)
    if active_error:
        return CleanupCandidate("local_worktree", "UNCERTAIN", active_error, repo, pr_number)
    if not isinstance(topic_branch, str) or not topic_branch.strip():
        return CleanupCandidate("local_worktree", "UNCERTAIN", "TOPIC_BRANCH_INVALID", repo, pr_number)
    branch = _normalize_branch(topic_branch.strip())
    if not isinstance(merged_pr_head, str) or not _SHA_RE.fullmatch(merged_pr_head):
        return CleanupCandidate("local_worktree", "UNCERTAIN", "MERGED_PR_HEAD_INVALID", repo, pr_number, branch)
    merged_head = merged_pr_head.lower()

    if _active_branch_owner(repo=repo, branch=branch, active_workstreams=active_workstreams):
        return CleanupCandidate("local_worktree", "NOT_SAFE", "ACTIVE_WORKSTREAM_OWNS_BRANCH", repo, pr_number, branch, merged_head)

    evidence = parse_local_closeout_evidence(
        output=closeout_output,
        returncode=closeout_returncode,
        expected_pr_head=merged_head,
    )
    if not evidence.valid:
        return CleanupCandidate("local_worktree", "NOT_SAFE", evidence.reason, repo, pr_number, branch, merged_head)
    return CleanupCandidate("local_worktree", "SAFE_TO_CONSIDER", "LOCAL_CLOSEOUT_VERIFIED", repo, pr_number, branch, merged_head)
