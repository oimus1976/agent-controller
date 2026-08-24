from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional


class ProvenanceAssurance(str, Enum):
    VERIFIED_EVENT_PROVENANCE = "VERIFIED_EVENT_PROVENANCE"
    SOURCE_AUTHENTICATED_ONLY = "SOURCE_AUTHENTICATED_ONLY"
    PROVENANCE_UNAVAILABLE = "PROVENANCE_UNAVAILABLE"


@dataclass(frozen=True)
class ApprovalIngressProvenance:
    source_name: str
    source_event_id: str
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


_REQUIRED_FIELDS = (
    "event_name",
    "actor",
    "actor_id",
    "run_id",
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


def validate_github_workflow_dispatch_candidate(
    *,
    record: Mapping[str, object],
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
    """Validate bounded GitHub workflow_dispatch metadata conservatively.

    This PoC never emits VERIFIED_EVENT_PROVENANCE. A workflow run authenticates
    a GitHub source/actor, but the application cannot prove that Agent Controller
    credentials were unable to dispatch the workflow. That privilege-separation
    fact must be established by deployment configuration outside this parser.
    """

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
        source_name="github-workflow-dispatch",
        source_event_id=values["run_id"],
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
