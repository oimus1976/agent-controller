from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath

from agent_controller.private_ci_pilot_identity import (
    PILOT_IDENTITY_FREEZE_SCHEMA,
    PRIVATE_CI_BROKER_IDENTITY,
    PRIVATE_CI_HOST,
    PRIVATE_CI_TARGET_IDENTITY,
    PrivateCiPilotIdentityFreeze,
    pilot_identity_freeze_reason_codes,
)


PHASE0_EVIDENCE_SCHEMA = "agent-controller.private-ci-phase0-evidence.v2"

# Historical values retained only for regression fixtures / archival inspection.
# They are not authority defaults for a future fresh pilot.
EXPECTED_CONTROLLER_MAIN = "0b0508d4f6ad2765e315e39450b71adfb371f8ca"
EXPECTED_CONTROLLER_TREE = r"C:\Users\c-admin\agent-controller-pilot-216"
EXPECTED_HOST = PRIVATE_CI_HOST
EXPECTED_BROKER_IDENTITY = PRIVATE_CI_BROKER_IDENTITY
EXPECTED_TARGET_IDENTITY = PRIVATE_CI_TARGET_IDENTITY


@dataclass(frozen=True, slots=True)
class Phase0Evidence:
    schema: str
    collected_at: str
    status: str
    controller_main_sha: str
    controller_tree: str
    controller_tree_head_sha: str
    controller_tree_clean: bool
    host: str
    broker_identity: str
    target_identity: str
    target_identity_enabled: bool
    target_identity_admin: bool
    repository: str
    repository_visibility: str
    default_branch: str
    pull_request_number: int
    pull_request_state: str
    pull_request_draft: bool
    pull_request_head_repository: str
    pull_request_head_sha: str
    pull_request_base: str
    workflow_sha: str
    workflow_path: str
    runner_name: str
    runner_label: str
    environment_generation: str
    runner_root: str
    work_folder: str
    runner_root_exists: bool
    matching_pilot_runner_count: int
    runner_process_count: int
    runner_service_count: int
    runner_task_count: int
    powershell_version: str
    python_version: str

    def to_dict(self) -> dict[str, object]:
        return {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
        }


def phase0_canonical_bytes(evidence: Phase0Evidence) -> bytes:
    return (
        json.dumps(
            evidence.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase0_evidence(raw: bytes) -> Phase0Evidence:
    if type(raw) is not bytes:
        raise ValueError("phase0 evidence must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("phase0 evidence JSON invalid") from error
    if type(payload) is not dict:
        raise ValueError("phase0 evidence must be object")
    expected_keys = set(Phase0Evidence.__dataclass_fields__)
    if set(payload) != expected_keys:
        raise ValueError("phase0 evidence fields invalid")
    try:
        evidence = Phase0Evidence(**payload)
    except TypeError as error:
        raise ValueError("phase0 evidence field types invalid") from error
    if raw != phase0_canonical_bytes(evidence):
        raise ValueError("phase0 evidence must be canonical JSON")
    return evidence


def phase0_pilot_identity_freeze(
    evidence: Phase0Evidence,
) -> PrivateCiPilotIdentityFreeze:
    if type(evidence) is not Phase0Evidence:
        raise ValueError("phase0 evidence type invalid")
    return PrivateCiPilotIdentityFreeze(
        schema=PILOT_IDENTITY_FREEZE_SCHEMA,
        repository=evidence.repository,
        pull_request_number=evidence.pull_request_number,
        target_sha=evidence.pull_request_head_sha,
        workflow_sha=evidence.workflow_sha,
        workflow_path=evidence.workflow_path,
        runner_name=evidence.runner_name,
        runner_label=evidence.runner_label,
        environment_generation=evidence.environment_generation,
        runner_root=evidence.runner_root,
        work_folder=evidence.work_folder,
        controller_main_sha=evidence.controller_main_sha,
        controller_tree=evidence.controller_tree,
        host=evidence.host,
        broker_identity=evidence.broker_identity,
        target_identity=evidence.target_identity,
    )


def phase0_freeze_mismatch_reason_codes(
    evidence: Phase0Evidence,
    freeze: PrivateCiPilotIdentityFreeze,
) -> tuple[str, ...]:
    if type(evidence) is not Phase0Evidence:
        return ("PHASE0_EVIDENCE_TYPE_INVALID",)
    freeze_reasons = pilot_identity_freeze_reason_codes(freeze)
    if freeze_reasons:
        return tuple(
            "PHASE0_FREEZE_" + reason
            for reason in freeze_reasons
        )
    observed = phase0_pilot_identity_freeze(evidence)
    if observed == freeze:
        return ()
    reasons: list[str] = []
    for field in PrivateCiPilotIdentityFreeze.__dataclass_fields__:
        if getattr(observed, field) != getattr(freeze, field):
            reasons.append(f"PHASE0_FREEZE_{field.upper()}_MISMATCH")
    return tuple(reasons)


def _lower_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _workflow_path_valid(value: object) -> bool:
    if type(value) is not str or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and len(path.parts) >= 3
        and path.parts[:2] == (".github", "workflows")
        and path.suffix in (".yml", ".yaml")
        and str(path) == value
    )


def phase0_reason_codes(evidence: object) -> tuple[str, ...]:
    if type(evidence) is not Phase0Evidence:
        return ("PHASE0_EVIDENCE_TYPE_INVALID",)

    reasons: list[str] = []
    if evidence.schema != PHASE0_EVIDENCE_SCHEMA:
        reasons.append("PHASE0_SCHEMA_MISMATCH")
    if evidence.status != "PHASE0_PASS":
        reasons.append("PHASE0_STATUS_MISMATCH")
    if not _lower_sha(evidence.controller_main_sha):
        reasons.append("PHASE0_CONTROLLER_MAIN_SHA_INVALID")
    if (
        type(evidence.controller_tree) is not str
        or not PureWindowsPath(evidence.controller_tree).is_absolute()
        or ".." in PureWindowsPath(evidence.controller_tree).parts
    ):
        reasons.append("PHASE0_CONTROLLER_TREE_INVALID")
    if evidence.controller_tree_head_sha != evidence.controller_main_sha:
        reasons.append("PHASE0_CONTROLLER_TREE_HEAD_SHA_MISMATCH")
    if evidence.controller_tree_clean is not True:
        reasons.append("PHASE0_CONTROLLER_TREE_CLEAN_MISMATCH")

    if evidence.host != PRIVATE_CI_HOST:
        reasons.append("PHASE0_HOST_MISMATCH")
    if evidence.broker_identity != PRIVATE_CI_BROKER_IDENTITY:
        reasons.append("PHASE0_BROKER_IDENTITY_MISMATCH")
    if evidence.target_identity != PRIVATE_CI_TARGET_IDENTITY:
        reasons.append("PHASE0_TARGET_IDENTITY_MISMATCH")
    if evidence.target_identity_enabled is not True:
        reasons.append("PHASE0_TARGET_IDENTITY_ENABLED_MISMATCH")
    if evidence.target_identity_admin is not False:
        reasons.append("PHASE0_TARGET_IDENTITY_ADMIN_MISMATCH")

    if (
        type(evidence.repository) is not str
        or evidence.repository.count("/") != 1
        or any(not part for part in evidence.repository.split("/"))
    ):
        reasons.append("PHASE0_REPOSITORY_INVALID")
    if evidence.repository_visibility != "private":
        reasons.append("PHASE0_REPOSITORY_VISIBILITY_MISMATCH")
    if evidence.default_branch != "main":
        reasons.append("PHASE0_DEFAULT_BRANCH_MISMATCH")
    if (
        type(evidence.pull_request_number) is not int
        or evidence.pull_request_number <= 0
    ):
        reasons.append("PHASE0_PULL_REQUEST_NUMBER_INVALID")
    if evidence.pull_request_state != "open":
        reasons.append("PHASE0_PULL_REQUEST_STATE_MISMATCH")
    if evidence.pull_request_draft is not True:
        reasons.append("PHASE0_PULL_REQUEST_DRAFT_MISMATCH")
    if evidence.pull_request_head_repository != evidence.repository:
        reasons.append("PHASE0_PULL_REQUEST_HEAD_REPOSITORY_MISMATCH")
    if not _lower_sha(evidence.pull_request_head_sha):
        reasons.append("PHASE0_PULL_REQUEST_HEAD_SHA_INVALID")
    if evidence.pull_request_base != "main":
        reasons.append("PHASE0_PULL_REQUEST_BASE_MISMATCH")
    if not _lower_sha(evidence.workflow_sha):
        reasons.append("PHASE0_WORKFLOW_SHA_INVALID")
    if not _workflow_path_valid(evidence.workflow_path):
        reasons.append("PHASE0_WORKFLOW_PATH_INVALID")

    try:
        identity_freeze = phase0_pilot_identity_freeze(evidence)
        identity_reasons = pilot_identity_freeze_reason_codes(identity_freeze)
    except ValueError:
        identity_reasons = ("PILOT_FREEZE_FROM_PHASE0_INVALID",)
    reasons.extend(
        f"PHASE0_{reason}"
        for reason in identity_reasons
    )

    if evidence.runner_root_exists is not False:
        reasons.append("PHASE0_RUNNER_ROOT_EXISTS_MISMATCH")
    if evidence.matching_pilot_runner_count != 0:
        reasons.append("PHASE0_MATCHING_PILOT_RUNNER_COUNT_MISMATCH")
    if evidence.runner_process_count != 0:
        reasons.append("PHASE0_RUNNER_PROCESS_COUNT_MISMATCH")
    if evidence.runner_service_count != 0:
        reasons.append("PHASE0_RUNNER_SERVICE_COUNT_MISMATCH")
    if evidence.runner_task_count != 0:
        reasons.append("PHASE0_RUNNER_TASK_COUNT_MISMATCH")

    if type(evidence.collected_at) is not str or not evidence.collected_at.strip():
        reasons.append("PHASE0_COLLECTED_AT_INVALID")
    if not (
        type(evidence.powershell_version) is str
        and evidence.powershell_version.startswith("5.1.")
    ):
        reasons.append("PHASE0_POWERSHELL_VERSION_INVALID")
    if not (
        type(evidence.python_version) is str
        and evidence.python_version.startswith("3.12.")
    ):
        reasons.append("PHASE0_PYTHON_VERSION_INVALID")
    return tuple(reasons)


def validate_phase0_evidence_bytes(raw: bytes) -> Phase0Evidence:
    evidence = parse_phase0_evidence(raw)
    reasons = phase0_reason_codes(evidence)
    if reasons:
        raise ValueError("phase0 evidence blocked: " + ",".join(reasons))
    return evidence
