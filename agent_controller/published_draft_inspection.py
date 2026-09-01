from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping, Optional

from agent_controller.jules_draft_publication import DraftPublicationResult
from agent_controller.provider_contract import TaskBinding
from agent_controller.workstream import WorkstreamBinding, validate_branch_workstream, validate_task_workstream


@dataclass(frozen=True)
class PublishedDraftInspectionResult:
    status: str
    reason: Optional[str] = None
    pr_number: Optional[int] = None
    head_sha: Optional[str] = None
    classification: Optional[str] = None
    actions_ci_status: Optional[str] = None
    scope_status: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _base_branch(ref: str) -> str:
    if ref.startswith("refs/heads/"):
        branch = ref[len("refs/heads/") :]
    elif ref.startswith("heads/"):
        branch = ref[len("heads/") :]
    elif ref.startswith("refs/"):
        raise ValueError("EXPECTED_START_REF_NOT_BRANCH")
    else:
        branch = ref
    if not branch or branch.startswith("/") or branch.endswith("/") or branch in {"HEAD", "head", ".", ".."}:
        raise ValueError("EXPECTED_START_REF_INVALID")
    return branch


def _scope_policy(task: TaskBinding) -> dict[str, Any]:
    return {
        "allowed_paths": list(task.objective_scope.allowed_paths or ()),
        "denied_paths": list(task.objective_scope.denied_paths or ()),
    }


def _validate_pr_snapshot(
    *,
    snapshot: Mapping[str, Any],
    repo: str,
    pr_number: int,
    branch: str,
    head_sha: str,
    base_branch: str,
) -> Optional[str]:
    if not isinstance(snapshot, Mapping):
        return "PR_SNAPSHOT_MALFORMED"
    if snapshot.get("number") != pr_number:
        return "PR_NUMBER_MISMATCH"
    if snapshot.get("state") != "open" or snapshot.get("draft") is not True or snapshot.get("merged") is True:
        return "PR_STATE_MISMATCH"

    head = snapshot.get("head")
    base = snapshot.get("base")
    if not isinstance(head, Mapping) or not isinstance(base, Mapping):
        return "PR_IDENTITY_MALFORMED"
    if head.get("ref") != branch or head.get("sha") != head_sha:
        return "PR_HEAD_MISMATCH"
    head_repo = head.get("repo")
    if not isinstance(head_repo, Mapping) or not isinstance(head_repo.get("full_name"), str):
        return "PR_HEAD_REPO_UNCERTAIN"
    if head_repo.get("full_name").casefold() != repo.casefold():
        return "PR_HEAD_REPO_MISMATCH"
    if base.get("ref") != base_branch:
        return "PR_BASE_MISMATCH"
    return None


def inspect_published_draft_pr(
    *,
    publication: DraftPublicationResult,
    task: TaskBinding,
    workstream: WorkstreamBinding,
    read_pr: Callable[[str, int], Mapping[str, Any]],
    inspector: Callable[[str, str, int, Mapping[str, Any]], Mapping[str, Any]],
) -> PublishedDraftInspectionResult:
    """Inspect exactly one successfully published Controller-owned Draft PR.

    This is composition only. It reuses the existing inspector's scope, Actions,
    and review classification and exposes no Ready/merge mutation authority.
    """

    try:
        if not isinstance(publication, DraftPublicationResult):
            return PublishedDraftInspectionResult("BLOCKED", "PUBLICATION_RESULT_INVALID")
        if publication.status != "PASS":
            return PublishedDraftInspectionResult("BLOCKED", "PUBLICATION_NOT_PASS")
        if not isinstance(task, TaskBinding) or not isinstance(workstream, WorkstreamBinding):
            return PublishedDraftInspectionResult("BLOCKED", "BINDING_TYPE_INVALID")
        if not isinstance(task.repo, str) or task.repo.count("/") != 1:
            return PublishedDraftInspectionResult("BLOCKED", "TASK_REPO_INVALID")
        if not isinstance(task.expected_start_ref, str) or not task.expected_start_ref:
            return PublishedDraftInspectionResult("BLOCKED", "EXPECTED_START_REF_REQUIRED")

        pr_number = publication.pr_number
        branch = publication.branch
        head_sha = publication.commit_sha
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
            return PublishedDraftInspectionResult("BLOCKED", "PUBLICATION_PR_INVALID")
        if not isinstance(branch, str) or not branch or not branch.startswith("controller/"):
            return PublishedDraftInspectionResult("BLOCKED", "PUBLICATION_BRANCH_INVALID")
        if not isinstance(head_sha, str) or len(head_sha) != 40 or any(c not in "0123456789abcdefABCDEF" for c in head_sha):
            return PublishedDraftInspectionResult("BLOCKED", "PUBLICATION_HEAD_INVALID")

        for check in (
            validate_task_workstream(binding=workstream, task=task),
            validate_branch_workstream(binding=workstream, repo=task.repo, branch_ref=branch),
        ):
            if not check.valid:
                return PublishedDraftInspectionResult("BLOCKED", check.reason)

        base_branch = _base_branch(task.expected_start_ref)
        owner, repo_name = task.repo.split("/", 1)

        before = read_pr(task.repo, pr_number)
        reason = _validate_pr_snapshot(
            snapshot=before,
            repo=task.repo,
            pr_number=pr_number,
            branch=branch,
            head_sha=head_sha,
            base_branch=base_branch,
        )
        if reason is not None:
            return PublishedDraftInspectionResult("BLOCKED", reason, pr_number=pr_number, head_sha=head_sha)

        evidence = inspector(owner, repo_name, pr_number, _scope_policy(task))
        if not isinstance(evidence, Mapping):
            return PublishedDraftInspectionResult("UNCERTAIN", "INSPECTION_EVIDENCE_MALFORMED", pr_number=pr_number, head_sha=head_sha)
        if evidence.get("head_sha") != head_sha or evidence.get("base_branch") != base_branch:
            return PublishedDraftInspectionResult("UNCERTAIN", "INSPECTION_IDENTITY_MISMATCH", pr_number=pr_number, head_sha=head_sha)
        if evidence.get("state") != "open" or evidence.get("draft") is not True or evidence.get("merged") is True:
            return PublishedDraftInspectionResult("UNCERTAIN", "INSPECTION_STATE_MISMATCH", pr_number=pr_number, head_sha=head_sha)

        classification = evidence.get("classification")
        actions_ci_status = evidence.get("actions_ci_status")
        scope_status = evidence.get("scope_status")
        if not all(isinstance(value, str) and value for value in (classification, actions_ci_status, scope_status)):
            return PublishedDraftInspectionResult("UNCERTAIN", "INSPECTION_CLASSIFICATION_MALFORMED", pr_number=pr_number, head_sha=head_sha)

        after = read_pr(task.repo, pr_number)
        reason = _validate_pr_snapshot(
            snapshot=after,
            repo=task.repo,
            pr_number=pr_number,
            branch=branch,
            head_sha=head_sha,
            base_branch=base_branch,
        )
        if reason is not None:
            return PublishedDraftInspectionResult("UNCERTAIN", "PR_DRIFT_AFTER_INSPECTION", pr_number=pr_number, head_sha=head_sha)

        return PublishedDraftInspectionResult(
            "PASS",
            pr_number=pr_number,
            head_sha=head_sha,
            classification=classification,
            actions_ci_status=actions_ci_status,
            scope_status=scope_status,
        )
    except ValueError as exc:
        return PublishedDraftInspectionResult("BLOCKED", str(exc) or "INSPECTION_VALIDATION_FAILED")
    except Exception:
        return PublishedDraftInspectionResult("UNCERTAIN", "INSPECTION_EXTERNAL_UNCERTAINTY")


def inspect_published_draft_pr_live(
    *,
    publication: DraftPublicationResult,
    task: TaskBinding,
    workstream: WorkstreamBinding,
) -> PublishedDraftInspectionResult:
    """Read-only live composition using the existing GitHub inspector implementation."""

    from agent_controller import inspector as existing_inspector

    def read_pr(repo: str, pr_number: int) -> Mapping[str, Any]:
        owner, repo_name = repo.split("/", 1)
        return existing_inspector.get_pr_details(owner, repo_name, pr_number)

    def inspect_existing(
        owner: str,
        repo_name: str,
        pr_number: int,
        scope_policy: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return existing_inspector.inspect_pr(owner, repo_name, pr_number, dict(scope_policy))

    return inspect_published_draft_pr(
        publication=publication,
        task=task,
        workstream=workstream,
        read_pr=read_pr,
        inspector=inspect_existing,
    )
