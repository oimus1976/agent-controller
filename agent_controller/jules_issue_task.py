from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from agent_controller.github_draft_publication import GitHubRestDraftPublicationBackend
from agent_controller.jules_changesets import JulesChangeSetReadClient
from agent_controller.jules_live import JulesApiClient, JulesDispatchClient, JulesReadClient
from agent_controller.provider_adapters import JulesObservationAdapter
from agent_controller.provider_artifacts import JulesArtifactAdapter
from agent_controller.provider_contract import ObjectiveScope, ProviderOperationRef, TaskBinding
from agent_controller.provider_runtime import JulesAgentAdapter
from agent_controller.workstream import WorkstreamBinding


SUPPORTED_REPO = "oimus1976/agent-controller"
SUPPORTED_BASE_REF = "main"
ALLOWED_EFFECTS = ("SESSION_CREATE", "DRAFT_PR_CREATE")
FORBIDDEN_EFFECTS = ("AUTO_CREATE_PR", "PLAN_APPROVAL", "READY", "MERGE")
APPROVAL_POLICY_ID = "adr-90-human-final"
REQUESTED_CAPABILITY = "JULES_BOUNDED_ISSUE_IMPLEMENTATION"
_SPEC_FIELDS = frozenset(
    {
        "schema_version",
        "issue_number",
        "repo",
        "expected_start_ref",
        "expected_start_sha",
        "controller_task_id",
        "operation_id",
        "workstream_id",
        "destination_branch",
        "prompt",
        "allowed_paths",
        "denied_paths",
        "requested_capability",
        "allowed_effects",
        "forbidden_effects",
        "approval_policy_id",
    }
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")


def _observed_at_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{field} must be a list of strings")
    result = tuple(value)
    if not result or any(not isinstance(item, str) or not item for item in result):
        raise ValueError(f"{field} must be a non-empty list of non-empty strings")
    if len(set(result)) != len(result):
        raise ValueError(f"{field} must not contain duplicates")
    return result


def _validate_exact_allowed_path(path: str) -> None:
    if "*" in path or "?" in path or "[" in path:
        raise ValueError("allowed_paths must use exact paths during limited deployment")
    if "\\" in path or path.startswith("/"):
        raise ValueError("allowed path must be repository-relative POSIX path")
    parts = PurePosixPath(path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("allowed path contains unsafe traversal or empty segment")


@dataclass(frozen=True)
class JulesIssueTaskSpec:
    schema_version: int
    issue_number: int
    repo: str
    expected_start_ref: str
    expected_start_sha: str
    controller_task_id: str
    operation_id: str
    workstream_id: str
    destination_branch: str
    prompt: str
    allowed_paths: tuple[str, ...]
    denied_paths: tuple[str, ...]
    requested_capability: str
    allowed_effects: tuple[str, ...]
    forbidden_effects: tuple[str, ...]
    approval_policy_id: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "JulesIssueTaskSpec":
        if not isinstance(raw, Mapping):
            raise ValueError("task spec must be an object")
        unknown = set(raw) - _SPEC_FIELDS
        missing = _SPEC_FIELDS - set(raw)
        if unknown:
            raise ValueError(f"unknown task spec fields: {sorted(unknown)}")
        if missing:
            raise ValueError(f"missing task spec fields: {sorted(missing)}")

        issue_number = raw["issue_number"]
        if not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number < 1:
            raise ValueError("issue_number must be a positive integer")
        schema_version = raw["schema_version"]
        if schema_version != 1:
            raise ValueError("unsupported task spec schema_version")

        expected_start_sha = raw["expected_start_sha"]
        if not isinstance(expected_start_sha, str) or not _SHA_RE.fullmatch(expected_start_sha):
            raise ValueError("expected_start_sha must be lowercase 40-hex")
        suffix = expected_start_sha[:12]
        expected_task_id = f"task-jules-issue-{issue_number}-{suffix}"
        expected_operation_id = f"op-jules-issue-{issue_number}-{suffix}"
        expected_workstream_id = f"jules-issue-{issue_number}-{suffix}"
        expected_branch = f"controller/jules-issue-{issue_number}-{suffix}"

        exact_strings = {
            "repo": SUPPORTED_REPO,
            "expected_start_ref": SUPPORTED_BASE_REF,
            "controller_task_id": expected_task_id,
            "operation_id": expected_operation_id,
            "workstream_id": expected_workstream_id,
            "destination_branch": expected_branch,
            "requested_capability": REQUESTED_CAPABILITY,
            "approval_policy_id": APPROVAL_POLICY_ID,
        }
        for field, expected in exact_strings.items():
            if raw[field] != expected:
                raise ValueError(f"{field} must equal {expected!r}")
        for field in ("controller_task_id", "operation_id", "workstream_id"):
            if not _ID_RE.fullmatch(str(raw[field])):
                raise ValueError(f"{field} has invalid identity syntax")

        prompt = raw["prompt"]
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 12000:
            raise ValueError("prompt must be non-empty and at most 12000 characters")
        if f"#{issue_number}" not in prompt:
            raise ValueError("prompt must explicitly bind the GitHub issue number")

        allowed_paths = _string_tuple(raw["allowed_paths"], field="allowed_paths")
        denied_paths = _string_tuple(raw["denied_paths"], field="denied_paths")
        for path in allowed_paths:
            _validate_exact_allowed_path(path)
        if any(path in {"*", "**", "**/*"} for path in denied_paths):
            raise ValueError("denied_paths must not use an all-repository wildcard")

        allowed_effects = _string_tuple(raw["allowed_effects"], field="allowed_effects")
        forbidden_effects = _string_tuple(raw["forbidden_effects"], field="forbidden_effects")
        if allowed_effects != ALLOWED_EFFECTS:
            raise ValueError("allowed_effects cannot differ from bounded Jules policy")
        if forbidden_effects != FORBIDDEN_EFFECTS:
            raise ValueError("forbidden_effects cannot differ from bounded Jules policy")
        if set(allowed_effects) & set(forbidden_effects):
            raise ValueError("allowed and forbidden effects overlap")

        return cls(
            schema_version=schema_version,
            issue_number=issue_number,
            repo=SUPPORTED_REPO,
            expected_start_ref=SUPPORTED_BASE_REF,
            expected_start_sha=expected_start_sha,
            controller_task_id=expected_task_id,
            operation_id=expected_operation_id,
            workstream_id=expected_workstream_id,
            destination_branch=expected_branch,
            prompt=prompt,
            allowed_paths=allowed_paths,
            denied_paths=denied_paths,
            requested_capability=REQUESTED_CAPABILITY,
            allowed_effects=allowed_effects,
            forbidden_effects=forbidden_effects,
            approval_policy_id=APPROVAL_POLICY_ID,
        )

    @property
    def state_filename(self) -> str:
        return f".jules_issue_task_{self.issue_number}_{self.expected_start_sha[:12]}_state.json"

    def to_task_binding(self) -> TaskBinding:
        return TaskBinding(
            controller_task_id=self.controller_task_id,
            operation_id=self.operation_id,
            provider="jules",
            repo=self.repo,
            expected_start_ref=self.expected_start_ref,
            expected_start_sha=self.expected_start_sha,
            objective_scope=ObjectiveScope(
                allowed_paths=self.allowed_paths,
                denied_paths=self.denied_paths,
            ),
            requested_capability=self.requested_capability,
            allowed_effects=self.allowed_effects,
            forbidden_effects=self.forbidden_effects,
            approval_policy_id=self.approval_policy_id,
            created_at=_observed_at_now(),
        )

    def to_workstream_binding(self) -> WorkstreamBinding:
        return WorkstreamBinding(
            workstream_id=self.workstream_id,
            repo=self.repo,
            root_work_item_ref=f"github:issue:{self.issue_number}",
            task_ids=(self.controller_task_id,),
            github_issues=(self.issue_number,),
            branch_refs=(self.destination_branch,),
        )


class _UnusedArtifactReadClient:
    def list_artifacts_raw(self, operation: ProviderOperationRef):
        return ()


def build_issue_task(
    spec: JulesIssueTaskSpec,
    *,
    github: GitHubRestDraftPublicationBackend | None = None,
    api_client: JulesApiClient | None = None,
) -> tuple[
    TaskBinding,
    WorkstreamBinding,
    str,
    JulesAgentAdapter,
    JulesChangeSetReadClient,
    GitHubRestDraftPublicationBackend,
]:
    if not isinstance(spec, JulesIssueTaskSpec):
        raise TypeError("spec must be JulesIssueTaskSpec")
    github = github or GitHubRestDraftPublicationBackend()
    api_client = api_client or JulesApiClient()
    current_sha = github.get_ref_sha(spec.repo, spec.expected_start_ref)
    if current_sha != spec.expected_start_sha:
        raise RuntimeError("ISSUE_TASK_EXPECTED_BASE_DRIFT")

    task = spec.to_task_binding()
    workstream = spec.to_workstream_binding()
    observation = JulesObservationAdapter(
        client=JulesReadClient(api_client),
        observed_at=_observed_at_now,
    )
    adapter = JulesAgentAdapter(
        dispatch_client=JulesDispatchClient(api_client, default_prompt=spec.prompt),
        observation=observation,
        artifacts=JulesArtifactAdapter(
            client=_UnusedArtifactReadClient(),
            observed_at=_observed_at_now,
        ),
    )
    change_reader = JulesChangeSetReadClient(api_client, _observed_at_now)
    return task, workstream, spec.destination_branch, adapter, change_reader, github
