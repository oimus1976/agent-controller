from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Sequence

from agent_controller.provider_contract import ProviderOperationRef, TaskBinding


@dataclass(frozen=True)
class WorkstreamValidation:
    valid: bool
    reason: str | None = None


@dataclass(frozen=True)
class WorkstreamBinding:
    """Minimal provider-neutral binding for one independent line of work.

    The binding records Controller-owned membership facts only. Repository
    proximity, recency, provider prose, and queue ordering never create
    membership implicitly.
    """

    workstream_id: str
    repo: str
    root_work_item_ref: str
    task_ids: Sequence[str] = ()
    github_issues: Sequence[int] = ()
    github_prs: Sequence[int] = ()
    branch_refs: Sequence[str] = ()
    depends_on_workstream_ids: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.workstream_id, str) or not self.workstream_id.strip():
            raise ValueError("workstream_id must be a nonempty string")
        if not isinstance(self.repo, str) or self.repo.count("/") != 1:
            raise ValueError("repo must be OWNER/REPO")
        owner, name = self.repo.split("/", 1)
        if not owner or not name:
            raise ValueError("repo must be OWNER/REPO")
        if not isinstance(self.root_work_item_ref, str) or not self.root_work_item_ref.strip():
            raise ValueError("root_work_item_ref must be a nonempty string")

        task_ids = tuple(self.task_ids)
        github_issues = tuple(self.github_issues)
        github_prs = tuple(self.github_prs)
        branch_refs = tuple(self.branch_refs)
        dependencies = tuple(self.depends_on_workstream_ids)

        if any(not isinstance(item, str) or not item.strip() for item in task_ids):
            raise ValueError("task_ids must contain nonempty strings")
        if len(set(task_ids)) != len(task_ids):
            raise ValueError("task_ids must not contain duplicates")

        if any(
            not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0
            for issue in github_issues
        ):
            raise ValueError("github_issues must contain positive integers")
        if len(set(github_issues)) != len(github_issues):
            raise ValueError("github_issues must not contain duplicates")

        if any(not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0 for pr in github_prs):
            raise ValueError("github_prs must contain positive integers")
        if len(set(github_prs)) != len(github_prs):
            raise ValueError("github_prs must not contain duplicates")

        if any(not isinstance(ref, str) or not ref.strip() for ref in branch_refs):
            raise ValueError("branch_refs must contain nonempty strings")
        if len(set(branch_refs)) != len(branch_refs):
            raise ValueError("branch_refs must not contain duplicates")

        if any(not isinstance(item, str) or not item.strip() for item in dependencies):
            raise ValueError("depends_on_workstream_ids must contain nonempty strings")
        if self.workstream_id in dependencies:
            raise ValueError("workstream cannot depend on itself")
        if len(set(dependencies)) != len(dependencies):
            raise ValueError("depends_on_workstream_ids must not contain duplicates")

        object.__setattr__(self, "task_ids", task_ids)
        object.__setattr__(self, "github_issues", github_issues)
        object.__setattr__(self, "github_prs", github_prs)
        object.__setattr__(self, "branch_refs", branch_refs)
        object.__setattr__(self, "depends_on_workstream_ids", dependencies)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["task_ids"] = list(self.task_ids)
        data["github_issues"] = list(self.github_issues)
        data["github_prs"] = list(self.github_prs)
        data["branch_refs"] = list(self.branch_refs)
        data["depends_on_workstream_ids"] = list(self.depends_on_workstream_ids)
        return data


def validate_workstream_set(bindings: Sequence[WorkstreamBinding]) -> WorkstreamValidation:
    """Fail closed if active workstreams claim overlapping Controller targets.

    No persistent registry is introduced in this MVP. Callers that assemble a
    concurrent active set can validate it deterministically before observation,
    selection, or mutation. One task/GitHub target may belong to only one active
    workstream in this slice.

    GitHub Issues and pull requests share the repository work-item number
    namespace. A cross-type claim such as Issue #119 in one lane and PR #119 in
    another is therefore treated as overlapping ownership.
    """

    if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
        return WorkstreamValidation(False, "WORKSTREAM_SET_MALFORMED")
    materialized = tuple(bindings)
    if any(not isinstance(binding, WorkstreamBinding) for binding in materialized):
        return WorkstreamValidation(False, "WORKSTREAM_SET_MALFORMED")

    seen_workstream_ids: set[str] = set()
    seen_tasks: set[str] = set()
    seen_issues: set[tuple[str, int]] = set()
    seen_prs: set[tuple[str, int]] = set()
    seen_work_items: dict[tuple[str, int], str] = {}
    seen_branches: set[tuple[str, str]] = set()

    for binding in materialized:
        if binding.workstream_id in seen_workstream_ids:
            return WorkstreamValidation(False, "DUPLICATE_WORKSTREAM_ID")
        seen_workstream_ids.add(binding.workstream_id)

        for task_id in binding.task_ids:
            if task_id in seen_tasks:
                return WorkstreamValidation(False, "TASK_BOUND_TO_MULTIPLE_WORKSTREAMS")
            seen_tasks.add(task_id)

        repo_key = binding.repo.casefold()
        for issue in binding.github_issues:
            target = (repo_key, issue)
            if target in seen_issues:
                return WorkstreamValidation(False, "ISSUE_BOUND_TO_MULTIPLE_WORKSTREAMS")
            existing_owner = seen_work_items.get(target)
            if existing_owner is not None and existing_owner != binding.workstream_id:
                return WorkstreamValidation(False, "GITHUB_WORK_ITEM_BOUND_TO_MULTIPLE_WORKSTREAMS")
            seen_issues.add(target)
            seen_work_items[target] = binding.workstream_id
        for pr in binding.github_prs:
            target = (repo_key, pr)
            if target in seen_prs:
                return WorkstreamValidation(False, "PR_BOUND_TO_MULTIPLE_WORKSTREAMS")
            existing_owner = seen_work_items.get(target)
            if existing_owner is not None and existing_owner != binding.workstream_id:
                return WorkstreamValidation(False, "GITHUB_WORK_ITEM_BOUND_TO_MULTIPLE_WORKSTREAMS")
            seen_prs.add(target)
            seen_work_items[target] = binding.workstream_id
        for branch_ref in binding.branch_refs:
            target = (repo_key, branch_ref)
            if target in seen_branches:
                return WorkstreamValidation(False, "BRANCH_BOUND_TO_MULTIPLE_WORKSTREAMS")
            seen_branches.add(target)

    for binding in materialized:
        for dependency in binding.depends_on_workstream_ids:
            if dependency not in seen_workstream_ids:
                return WorkstreamValidation(False, "UNKNOWN_WORKSTREAM_DEPENDENCY")

    return WorkstreamValidation(True)


def validate_task_workstream(
    *, binding: WorkstreamBinding, task: TaskBinding
) -> WorkstreamValidation:
    if task.controller_task_id not in binding.task_ids:
        return WorkstreamValidation(False, "TASK_NOT_IN_WORKSTREAM")
    if task.repo is not None and task.repo.casefold() != binding.repo.casefold():
        return WorkstreamValidation(False, "TASK_REPO_MISMATCH")
    return WorkstreamValidation(True)


def validate_operation_workstream(
    *, binding: WorkstreamBinding, operation: ProviderOperationRef
) -> WorkstreamValidation:
    if operation.controller_task_id not in binding.task_ids:
        return WorkstreamValidation(False, "OPERATION_TASK_NOT_IN_WORKSTREAM")
    return WorkstreamValidation(True)


def _validate_github_target_repo(binding: WorkstreamBinding, repo: str) -> WorkstreamValidation:
    if not isinstance(repo, str) or repo.casefold() != binding.repo.casefold():
        return WorkstreamValidation(False, "WORKSTREAM_REPO_MISMATCH")
    return WorkstreamValidation(True)


def validate_issue_workstream(
    *, binding: WorkstreamBinding, repo: str, issue: int
) -> WorkstreamValidation:
    repo_result = _validate_github_target_repo(binding, repo)
    if not repo_result.valid:
        return repo_result
    if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
        return WorkstreamValidation(False, "INVALID_ISSUE_TARGET")
    if issue not in binding.github_issues:
        return WorkstreamValidation(False, "ISSUE_NOT_IN_WORKSTREAM")
    return WorkstreamValidation(True)


def validate_pr_workstream(
    *, binding: WorkstreamBinding, repo: str, pr: int
) -> WorkstreamValidation:
    repo_result = _validate_github_target_repo(binding, repo)
    if not repo_result.valid:
        return repo_result
    if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
        return WorkstreamValidation(False, "INVALID_PR_TARGET")
    if pr not in binding.github_prs:
        return WorkstreamValidation(False, "PR_NOT_IN_WORKSTREAM")
    return WorkstreamValidation(True)


def validate_branch_workstream(
    *, binding: WorkstreamBinding, repo: str, branch_ref: str
) -> WorkstreamValidation:
    repo_result = _validate_github_target_repo(binding, repo)
    if not repo_result.valid:
        return repo_result
    if not isinstance(branch_ref, str) or not branch_ref:
        return WorkstreamValidation(False, "INVALID_BRANCH_TARGET")
    if branch_ref not in binding.branch_refs:
        return WorkstreamValidation(False, "BRANCH_NOT_IN_WORKSTREAM")
    return WorkstreamValidation(True)


def validate_dependency_reference(
    *, binding: WorkstreamBinding, related_workstream_id: str
) -> WorkstreamValidation:
    if not isinstance(related_workstream_id, str) or not related_workstream_id:
        return WorkstreamValidation(False, "INVALID_RELATED_WORKSTREAM")
    if related_workstream_id not in binding.depends_on_workstream_ids:
        return WorkstreamValidation(False, "WORKSTREAM_RELATIONSHIP_NOT_BOUND")
    return WorkstreamValidation(True)
