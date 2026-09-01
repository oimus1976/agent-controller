from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence

from agent_controller.binding_validator import validate_operation_binding
from agent_controller.jules_changesets import JulesChangeSetEvidence, JulesChangeSetReadClient
from agent_controller.jules_patch import ParsedTextPatch, changed_paths, parse_and_apply_text_patch
from agent_controller.provider_contract import AgentObservation, ProviderOperationRef, TaskBinding, TerminalClaim
from agent_controller.repository_write_guard import RepositoryWriteDecision, RepositoryWriteGuard, RepositoryWritePurpose, RepositoryWriteTarget
from agent_controller.workstream import WorkstreamBinding, validate_branch_workstream, validate_operation_workstream, validate_task_workstream

_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
_DRAFT_PR_EFFECT = "DRAFT_PR_CREATE"


@dataclass(frozen=True)
class DraftPublicationResult:
    status: str
    reason: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    pr_number: Optional[int] = None
    patch_sha256: Optional[str] = None
    activity_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GitHubDraftPublicationBackend(Protocol):
    def get_default_branch(self, repo: str) -> str: ...
    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]: ...
    def get_file_text(self, repo: str, commit_sha: str, path: str) -> Optional[str]: ...
    def create_commit_from_text_changes(self, *, repo: str, base_sha: str, changes: Sequence[ParsedTextPatch], message: str) -> str: ...
    def create_branch(self, repo: str, branch: str, sha: str) -> None: ...
    def list_open_prs_for_branch(self, repo: str, branch: str) -> Sequence[Mapping[str, Any]]: ...
    def create_draft_pr(self, *, repo: str, head: str, base: str, title: str, body: str) -> Mapping[str, Any]: ...
    def get_pr(self, repo: str, pr_number: int) -> Mapping[str, Any]: ...
    def compare_files(self, repo: str, base_sha: str, head_sha: str) -> Sequence[Mapping[str, Any]]: ...


def _base_branch(ref: str) -> str:
    if ref.startswith("refs/heads/"):
        value = ref[len("refs/heads/"):]
    elif ref.startswith("heads/"):
        value = ref[len("heads/"):]
    elif ref.startswith("refs/"):
        raise ValueError("EXPECTED_START_REF_NOT_BRANCH")
    else:
        value = ref
    if not value or value.startswith("/") or value.endswith("/") or value in {"HEAD", "head", ".", ".."}:
        raise ValueError("EXPECTED_START_REF_INVALID")
    return value


def _scope_allows(task: TaskBinding, paths: Sequence[str]) -> bool:
    allowed = tuple(task.objective_scope.allowed_paths or ())
    denied = tuple(task.objective_scope.denied_paths or ())
    if not allowed and not denied:
        return False
    if any(not isinstance(pattern, str) or not pattern for pattern in (*allowed, *denied)):
        return False
    for path in paths:
        if any(fnmatch.fnmatch(path, pattern) for pattern in denied):
            return False
        if allowed and not any(fnmatch.fnmatch(path, pattern) for pattern in allowed):
            return False
    return True


def _compare_paths(files: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    paths: list[str] = []
    for item in files:
        filename = item.get("filename")
        previous = item.get("previous_filename")
        if not isinstance(filename, str) or not filename:
            raise RuntimeError("COMPARE_FILE_IDENTITY_MALFORMED")
        for value in (filename, previous):
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise RuntimeError("COMPARE_FILE_IDENTITY_MALFORMED")
                if value not in paths:
                    paths.append(value)
    return tuple(paths)


def publish_jules_changeset_to_draft_pr(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    workstream: WorkstreamBinding,
    destination_branch: str,
    observe: Callable[[ProviderOperationRef], AgentObservation],
    change_reader: JulesChangeSetReadClient,
    github: GitHubDraftPublicationBackend,
    pr_title: str,
    pr_body: str,
) -> DraftPublicationResult:
    """Publish exactly one completed Jules ChangeSet to an exact guarded Draft PR."""
    try:
        if not isinstance(task, TaskBinding) or not isinstance(operation, ProviderOperationRef):
            return DraftPublicationResult("BLOCKED", "BINDING_TYPE_INVALID")
        if not isinstance(workstream, WorkstreamBinding):
            return DraftPublicationResult("BLOCKED", "WORKSTREAM_BINDING_REQUIRED")
        op_binding = validate_operation_binding(task=task, operation=operation)
        if not op_binding.valid:
            return DraftPublicationResult("BLOCKED", op_binding.reason or "OPERATION_BINDING_INVALID")
        for check in (
            validate_task_workstream(binding=workstream, task=task),
            validate_operation_workstream(binding=workstream, operation=operation),
            validate_branch_workstream(binding=workstream, repo=task.repo or "", branch_ref=destination_branch),
        ):
            if not check.valid:
                return DraftPublicationResult("BLOCKED", check.reason)
        if task.provider != "jules" or operation.provider != "jules":
            return DraftPublicationResult("BLOCKED", "JULES_PROVIDER_REQUIRED")
        if _DRAFT_PR_EFFECT not in task.allowed_effects or _DRAFT_PR_EFFECT in task.forbidden_effects:
            return DraftPublicationResult("BLOCKED", "DRAFT_PR_EFFECT_NOT_ALLOWED")
        if not isinstance(task.repo, str) or not task.repo:
            return DraftPublicationResult("BLOCKED", "TASK_REPO_REQUIRED")
        if not isinstance(task.expected_start_ref, str) or not task.expected_start_ref:
            return DraftPublicationResult("BLOCKED", "EXPECTED_START_REF_REQUIRED")
        if not isinstance(task.expected_start_sha, str) or not _SHA40.fullmatch(task.expected_start_sha):
            return DraftPublicationResult("BLOCKED", "EXPECTED_START_SHA_INVALID")
        if not all(isinstance(v, str) and bool(v.strip()) for v in (destination_branch, pr_title, pr_body)):
            return DraftPublicationResult("BLOCKED", "PUBLICATION_METADATA_INVALID")
        expected_base_branch = _base_branch(task.expected_start_ref)

        default_branch = github.get_default_branch(task.repo)
        guard = RepositoryWriteGuard(repo=task.repo, default_branch=default_branch)
        write = guard.validate(target=RepositoryWriteTarget(repo=task.repo, explicit_ref=destination_branch, purpose=RepositoryWritePurpose.IMPLEMENTATION_BRANCH))
        if write.decision is not RepositoryWriteDecision.PASS:
            return DraftPublicationResult("BLOCKED", write.reason)
        branch = write.normalized_ref
        assert branch is not None
        if not branch.startswith("controller/") or branch == "controller/":
            return DraftPublicationResult("BLOCKED", "CONTROLLER_BRANCH_NAMESPACE_REQUIRED")

        observation = observe(operation)
        if not isinstance(observation, AgentObservation):
            return DraftPublicationResult("UNCERTAIN", "OBSERVATION_MALFORMED")
        if observation.provider != operation.provider or observation.provider_operation_id != operation.provider_operation_id:
            return DraftPublicationResult("BLOCKED", "OBSERVATION_OPERATION_MISMATCH")
        if observation.terminal_claim is not TerminalClaim.SUCCESS:
            return DraftPublicationResult("BLOCKED", "JULES_SESSION_NOT_COMPLETED_SUCCESSFULLY")

        candidates = change_reader.list_change_sets(task=task, operation=operation)
        completed_candidates = tuple(
            candidate
            for candidate in candidates
            if isinstance(candidate, JulesChangeSetEvidence) and candidate.session_completed is True
        )
        if len(completed_candidates) != 1:
            return DraftPublicationResult("BLOCKED", "CHANGESET_FINALITY_AMBIGUOUS")
        candidate = completed_candidates[0]
        if not isinstance(candidate, JulesChangeSetEvidence):
            return DraftPublicationResult("BLOCKED", "CHANGESET_EVIDENCE_INVALID")
        if candidate.provider != "jules" or candidate.provider_operation_id != operation.provider_operation_id:
            return DraftPublicationResult("BLOCKED", "CHANGESET_OPERATION_MISMATCH")
        if not isinstance(candidate.activity_id, str) or not candidate.activity_id:
            return DraftPublicationResult("BLOCKED", "CHANGESET_ACTIVITY_INVALID")
        expected_activity_name = f"sessions/{operation.provider_operation_id}/activities/{candidate.activity_id}"
        if candidate.activity_name != expected_activity_name:
            return DraftPublicationResult("BLOCKED", "CHANGESET_ACTIVITY_MISMATCH")
        if candidate.session_completed is not True:
            return DraftPublicationResult("BLOCKED", "CHANGESET_NOT_COMPLETED")
        if not isinstance(candidate.source, str) or not candidate.source:
            return DraftPublicationResult("BLOCKED", "CHANGESET_SOURCE_INVALID")
        if candidate.suggested_commit_message is not None and (
            not isinstance(candidate.suggested_commit_message, str) or not candidate.suggested_commit_message.strip()
        ):
            return DraftPublicationResult("BLOCKED", "CHANGESET_COMMIT_MESSAGE_INVALID")
        if not isinstance(candidate.base_commit_id, str) or not _SHA40.fullmatch(candidate.base_commit_id):
            return DraftPublicationResult("BLOCKED", "CHANGESET_BASE_INVALID")
        if candidate.base_commit_id.casefold() != task.expected_start_sha.casefold():
            return DraftPublicationResult("BLOCKED", "CHANGESET_BASE_MISMATCH")
        if not isinstance(candidate.unidiff_patch, str) or not candidate.unidiff_patch:
            return DraftPublicationResult("BLOCKED", "CHANGESET_PATCH_INVALID")
        digest = hashlib.sha256(candidate.unidiff_patch.encode("utf-8")).hexdigest()
        if candidate.patch_sha256 != digest:
            return DraftPublicationResult("BLOCKED", "CHANGESET_DIGEST_MISMATCH")

        current_base = github.get_ref_sha(task.repo, task.expected_start_ref)
        if current_base is None or current_base.casefold() != task.expected_start_sha.casefold():
            return DraftPublicationResult("BLOCKED", "EXPECTED_BASE_DRIFT")
        if github.get_ref_sha(task.repo, branch) is not None or tuple(github.list_open_prs_for_branch(task.repo, branch)):
            return DraftPublicationResult("BLOCKED", "PUBLICATION_TARGET_ALREADY_EXISTS")

        changes = parse_and_apply_text_patch(candidate.unidiff_patch, lambda path: github.get_file_text(task.repo, task.expected_start_sha or "", path))
        paths = changed_paths(changes)
        if not paths or not _scope_allows(task, paths):
            return DraftPublicationResult("BLOCKED", "PATCH_SCOPE_VIOLATION")

        fresh_base = github.get_ref_sha(task.repo, task.expected_start_ref)
        if fresh_base is None or fresh_base.casefold() != task.expected_start_sha.casefold():
            return DraftPublicationResult("BLOCKED", "EXPECTED_BASE_DRIFT_BEFORE_WRITE")
        if github.get_ref_sha(task.repo, branch) is not None:
            return DraftPublicationResult("BLOCKED", "DESTINATION_BRANCH_COLLISION")

        commit_sha = github.create_commit_from_text_changes(repo=task.repo, base_sha=task.expected_start_sha, changes=changes, message=candidate.suggested_commit_message or f"Implement {task.controller_task_id}")
        if not isinstance(commit_sha, str) or not _SHA40.fullmatch(commit_sha):
            return DraftPublicationResult("UNCERTAIN", "CREATED_COMMIT_SHA_INVALID")
        github.create_branch(task.repo, branch, commit_sha)
        created = github.create_draft_pr(repo=task.repo, head=branch, base=expected_base_branch, title=pr_title, body=pr_body)
        pr_number = created.get("number") if isinstance(created, Mapping) else None
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
            return DraftPublicationResult("UNCERTAIN", "PR_IDENTITY_UNCERTAIN")

        branch_sha = github.get_ref_sha(task.repo, branch)
        if branch_sha is None or branch_sha.casefold() != commit_sha.casefold():
            return DraftPublicationResult("UNCERTAIN", "BRANCH_POSTCONDITION_FAILED")
        post_base = github.get_ref_sha(task.repo, task.expected_start_ref)
        if post_base is None or post_base.casefold() != task.expected_start_sha.casefold():
            return DraftPublicationResult("UNCERTAIN", "BASE_POSTCONDITION_DRIFT")
        files = github.compare_files(task.repo, task.expected_start_sha, branch_sha)
        compared = _compare_paths(files)
        if set(compared) != set(paths) or not _scope_allows(task, compared):
            return DraftPublicationResult("UNCERTAIN", "PUBLISHED_SCOPE_POSTCONDITION_FAILED")
        pr = github.get_pr(task.repo, pr_number)
        if pr.get("state") != "open" or pr.get("draft") is not True or pr.get("merged") is True:
            return DraftPublicationResult("UNCERTAIN", "PR_STATE_POSTCONDITION_FAILED")
        head = pr.get("head")
        base = pr.get("base")
        if not isinstance(head, Mapping) or not isinstance(base, Mapping):
            return DraftPublicationResult("UNCERTAIN", "PR_IDENTITY_POSTCONDITION_FAILED")
        if head.get("ref") != branch or not isinstance(head.get("sha"), str) or head.get("sha").casefold() != branch_sha.casefold():
            return DraftPublicationResult("UNCERTAIN", "PR_HEAD_POSTCONDITION_FAILED")
        if base.get("ref") != expected_base_branch:
            return DraftPublicationResult("UNCERTAIN", "PR_BASE_POSTCONDITION_FAILED")
        open_prs = tuple(github.list_open_prs_for_branch(task.repo, branch))
        if len(open_prs) != 1 or open_prs[0].get("number") != pr_number:
            return DraftPublicationResult("UNCERTAIN", "PR_UNIQUENESS_POSTCONDITION_FAILED")

        return DraftPublicationResult("PASS", branch=branch, commit_sha=branch_sha, pr_number=pr_number, patch_sha256=digest, activity_id=candidate.activity_id)
    except ValueError as exc:
        return DraftPublicationResult("BLOCKED", str(exc) or "PUBLICATION_VALIDATION_FAILED")
    except Exception:
        return DraftPublicationResult("UNCERTAIN", "PUBLICATION_EXTERNAL_UNCERTAINTY")
