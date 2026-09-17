from __future__ import annotations

import json
from dataclasses import dataclass

from agent_controller.owner_machine_jit_bridge import TRUSTED_BROKER_IDENTITY
from agent_controller.private_ci_live_registration import (
    FROZEN_ENVIRONMENT_GENERATION,
    FROZEN_PR_NUMBER,
    FROZEN_REPOSITORY,
    FROZEN_RUNNER_LABEL,
    FROZEN_RUNNER_NAME,
    FROZEN_RUNNER_ROOT,
    FROZEN_TARGET_SHA,
    FROZEN_WORKFLOW_SHA,
)

PHASE0_EVIDENCE_SCHEMA = "agent-controller.private-ci-phase0-evidence.v1"
EXPECTED_CONTROLLER_MAIN = "0b0508d4f6ad2765e315e39450b71adfb371f8ca"
EXPECTED_CONTROLLER_TREE = r"C:\Users\c-admin\agent-controller-pilot-216"
EXPECTED_HOST = "WOBBUFFET"
EXPECTED_BROKER_IDENTITY = rf"{EXPECTED_HOST}\{TRUSTED_BROKER_IDENTITY}"
EXPECTED_TARGET_IDENTITY = "ac-runner"


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
    runner_name: str
    runner_label: str
    environment_generation: str
    runner_root: str
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
    payload = json.loads(raw.decode("utf-8"))
    if type(payload) is not dict:
        raise ValueError("phase0 evidence must be object")
    expected_keys = set(Phase0Evidence.__dataclass_fields__)
    if set(payload) != expected_keys:
        raise ValueError("phase0 evidence fields invalid")
    evidence = Phase0Evidence(**payload)
    if raw != phase0_canonical_bytes(evidence):
        raise ValueError("phase0 evidence must be canonical JSON")
    return evidence


def phase0_reason_codes(evidence: object) -> tuple[str, ...]:
    if type(evidence) is not Phase0Evidence:
        return ("PHASE0_EVIDENCE_TYPE_INVALID",)
    expected = {
        "schema": PHASE0_EVIDENCE_SCHEMA,
        "status": "PHASE0_PASS",
        "controller_main_sha": EXPECTED_CONTROLLER_MAIN,
        "controller_tree": EXPECTED_CONTROLLER_TREE,
        "controller_tree_head_sha": EXPECTED_CONTROLLER_MAIN,
        "controller_tree_clean": True,
        "host": EXPECTED_HOST,
        "broker_identity": EXPECTED_BROKER_IDENTITY,
        "target_identity": EXPECTED_TARGET_IDENTITY,
        "target_identity_enabled": True,
        "target_identity_admin": False,
        "repository": FROZEN_REPOSITORY,
        "repository_visibility": "private",
        "default_branch": "main",
        "pull_request_number": FROZEN_PR_NUMBER,
        "pull_request_state": "open",
        "pull_request_draft": True,
        "pull_request_head_repository": FROZEN_REPOSITORY,
        "pull_request_head_sha": FROZEN_TARGET_SHA,
        "pull_request_base": "main",
        "workflow_sha": FROZEN_WORKFLOW_SHA,
        "runner_name": FROZEN_RUNNER_NAME,
        "runner_label": FROZEN_RUNNER_LABEL,
        "environment_generation": FROZEN_ENVIRONMENT_GENERATION,
        "runner_root": FROZEN_RUNNER_ROOT,
        "runner_root_exists": False,
        "matching_pilot_runner_count": 0,
        "runner_process_count": 0,
        "runner_service_count": 0,
        "runner_task_count": 0,
    }
    reasons: list[str] = []
    for field, required in expected.items():
        if getattr(evidence, field) != required:
            reasons.append(f"PHASE0_{field.upper()}_MISMATCH")
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
