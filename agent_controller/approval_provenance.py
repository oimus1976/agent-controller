from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional, Protocol, runtime_checkable


class ProvenanceAssurance(str, Enum):
    VERIFIED_EVENT_PROVENANCE = "VERIFIED_EVENT_PROVENANCE"
    SOURCE_AUTHENTICATED_ONLY = "SOURCE_AUTHENTICATED_ONLY"
    PROVENANCE_UNAVAILABLE = "PROVENANCE_UNAVAILABLE"


@dataclass(frozen=True)
class ApprovalIngressProvenance:
    source_name: str
    source_event_id: str
    source_created_at: str
    actor: str
    actor_id: str
    event_name: str
    workflow_ref: str
    controller_task_id: str
    operation_id: str
    operation_version: str
    approval_id: str
    effect: str
    repo: str
    target_kind: str
    target_id: str
    expected_head_sha: str
    assurance: ProvenanceAssurance


@dataclass(frozen=True)
class ProvenanceValidation:
    valid: bool
    assurance: ProvenanceAssurance
    reason: Optional[str] = None
    provenance: Optional[ApprovalIngressProvenance] = None


@runtime_checkable
class GitHubWorkflowRunReader(Protocol):
    """Read authoritative bounded workflow-run metadata by GitHub run id."""

    def get_workflow_run(self, run_id: str) -> Mapping[str, object]:
        ...


@dataclass(frozen=True)
class TrustedGitHubWorkflowIngress:
    """Controller-owned trust configuration for one approval workflow."""

    source_name: str
    expected_workflow_ref: str
    reader: GitHubWorkflowRunReader


_REQUIRED_FIELDS = (
    "event_name",
    "actor",
    "actor_id",
    "run_id",
    "created_at",
    "workflow_ref",
    "controller_task_id",
    "operation_id",
    "operation_version",
    "approval_id",
    "effect",
    "repo",
    "target_kind",
    "target_id",
    "expected_head_sha",
)


def _validate_authoritative_workflow_record(
    *,
    record: Mapping[str, object],
    source_name: str,
    expected_workflow_ref: str,
    expected_run_id: str,
    expected_controller_task_id: str,
    expected_operation_id: str,
    expected_operation_version: str,
    expected_approval_id: str,
    expected_effect: str,
    expected_repo: str,
    expected_target_kind: str,
    expected_target_id: str,
    expected_head_sha: str,
) -> ProvenanceValidation:
    if not isinstance(record, Mapping):
        return ProvenanceValidation(False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, "RECORD_INVALID")

    values: dict[str, str] = {}
    for key in _REQUIRED_FIELDS:
        value = record.get(key)
        if not isinstance(value, str) or not value.strip():
            return ProvenanceValidation(
                False,
                ProvenanceAssurance.PROVENANCE_UNAVAILABLE,
                f"FIELD_MISSING_OR_INVALID:{key}",
            )
        values[key] = value.strip()

    if values["event_name"] != "workflow_dispatch":
        return ProvenanceValidation(False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, "EVENT_TYPE_MISMATCH")
    if values["run_id"] != expected_run_id:
        return ProvenanceValidation(False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, "RUN_ID_MISMATCH")
    if values["workflow_ref"] != expected_workflow_ref:
        return ProvenanceValidation(False, ProvenanceAssurance.SOURCE_AUTHENTICATED_ONLY, "WORKFLOW_REF_MISMATCH")

    expected = {
        "controller_task_id": expected_controller_task_id,
        "operation_id": expected_operation_id,
        "operation_version": expected_operation_version,
        "approval_id": expected_approval_id,
        "effect": expected_effect,
        "repo": expected_repo,
        "target_kind": expected_target_kind,
        "target_id": expected_target_id,
        "expected_head_sha": expected_head_sha,
    }
    for key, expected_value in expected.items():
        if values[key] != expected_value:
            return ProvenanceValidation(
                False,
                ProvenanceAssurance.SOURCE_AUTHENTICATED_ONLY,
                f"BINDING_MISMATCH:{key}",
            )

    provenance = ApprovalIngressProvenance(
        source_name=source_name,
        source_event_id=values["run_id"],
        source_created_at=values["created_at"],
        actor=values["actor"],
        actor_id=values["actor_id"],
        event_name=values["event_name"],
        workflow_ref=values["workflow_ref"],
        controller_task_id=values["controller_task_id"],
        operation_id=values["operation_id"],
        operation_version=values["operation_version"],
        approval_id=values["approval_id"],
        effect=values["effect"],
        repo=values["repo"],
        target_kind=values["target_kind"],
        target_id=values["target_id"],
        expected_head_sha=values["expected_head_sha"],
        assurance=ProvenanceAssurance.SOURCE_AUTHENTICATED_ONLY,
    )
    return ProvenanceValidation(True, provenance.assurance, provenance=provenance)


def read_and_validate_github_workflow_dispatch_candidate(
    *,
    ingress: TrustedGitHubWorkflowIngress,
    run_id: str,
    expected_controller_task_id: str,
    expected_operation_id: str,
    expected_operation_version: str,
    expected_approval_id: str,
    expected_effect: str,
    expected_repo: str,
    expected_target_kind: str,
    expected_target_id: str,
    expected_head_sha: str,
) -> ProvenanceValidation:
    """Read one GitHub run through configured ingress, then validate it.

    The supported API deliberately does not accept a caller-supplied Mapping.
    This PoC never emits VERIFIED_EVENT_PROVENANCE. Even an authoritative GitHub
    workflow run proves only source/account authentication until deployment
    configuration independently proves that Agent Controller credentials cannot
    dispatch the approval workflow.
    """

    if not isinstance(ingress, TrustedGitHubWorkflowIngress):
        return ProvenanceValidation(False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, "INGRESS_INVALID")
    if not run_id or not ingress.source_name or not ingress.expected_workflow_ref:
        return ProvenanceValidation(False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, "INGRESS_BINDING_MISSING")
    if not isinstance(ingress.reader, GitHubWorkflowRunReader):
        return ProvenanceValidation(False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, "READER_INVALID")

    try:
        record = ingress.reader.get_workflow_run(run_id)
    except Exception:
        return ProvenanceValidation(False, ProvenanceAssurance.PROVENANCE_UNAVAILABLE, "SOURCE_READ_UNCERTAIN")

    return _validate_authoritative_workflow_record(
        record=record,
        source_name=ingress.source_name,
        expected_workflow_ref=ingress.expected_workflow_ref,
        expected_run_id=run_id,
        expected_controller_task_id=expected_controller_task_id,
        expected_operation_id=expected_operation_id,
        expected_operation_version=expected_operation_version,
        expected_approval_id=expected_approval_id,
        expected_effect=expected_effect,
        expected_repo=expected_repo,
        expected_target_kind=expected_target_kind,
        expected_target_id=expected_target_id,
        expected_head_sha=expected_head_sha,
    )
