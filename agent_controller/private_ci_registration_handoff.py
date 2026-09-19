from __future__ import annotations

import hashlib
import json
from datetime import datetime

from agent_controller.private_ci_consumption_marker import (
    parse_consumption_marker_bytes,
)
from agent_controller.private_ci_human_approval import (
    approval_sha256,
    parse_approval_bytes,
)
from agent_controller.private_ci_live_registration import (
    live_registration_binding_from_phase0_evidence_bytes,
)
from agent_controller.private_ci_live_registration_runtime import (
    RESULT_SCHEMA,
    canonical_json_bytes,
    parse_plan_bytes,
    validate_frozen_plan,
)
from agent_controller.private_ci_phase0_evidence import (
    validate_phase0_evidence_bytes,
)
from agent_controller.private_ci_phase4_contract import (
    REGISTRATION_HANDOFF_SCHEMA,
    PrivateCiPilotBinding,
    RegistrationHandoffEvidence,
    registration_handoff_bytes,
)
from agent_controller.private_ci_runner_tree_snapshot import (
    parse_runner_generation_snapshot_bytes,
)


HUMAN_AUTHORIZATION_METHOD = "uac-elevated-acl-protected-approval-v1"
def _sha256(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise ValueError("artifact must be exact bytes")
    return hashlib.sha256(raw).hexdigest()


def _parse_registration_result(
    raw: bytes,
    *,
    expected_plan_sha256: str,
    expected_human_approval_sha256: str,
) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("registration result must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("registration result JSON invalid") from error
    expected = {
        "schema",
        "plan_sha256",
        "repository",
        "pull_request_number",
        "target_sha",
        "workflow_sha",
        "workflow_path",
        "runner_name",
        "runner_label",
        "environment_generation",
        "candidate_sha256",
        "status",
        "reason_codes",
        "child_exit_code",
        "runner_id",
        "runner_readback_attempts",
        "stdout",
        "stderr",
        "started_at",
        "ended_at",
        "human_authorization",
        "human_approval_sha256",
        "registration_token_recorded",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("registration result shape invalid")
    if raw != canonical_json_bytes(payload):
        raise ValueError("registration result is not canonical")
    if payload["schema"] != RESULT_SCHEMA:
        raise ValueError("registration result schema invalid")
    if payload["plan_sha256"] != expected_plan_sha256:
        raise ValueError("registration result plan SHA-256 mismatch")
    if payload["human_approval_sha256"] != expected_human_approval_sha256:
        raise ValueError("registration result approval SHA-256 mismatch")
    if payload["human_authorization"] != HUMAN_AUTHORIZATION_METHOD:
        raise ValueError("registration result human authorization mismatch")
    if payload["registration_token_recorded"] is not False:
        raise ValueError("registration result recorded token state unsafe")
    if payload["status"] != "REGISTERED":
        raise ValueError("registration result status is not REGISTERED")
    if payload["reason_codes"] != []:
        raise ValueError("registration result reason codes not empty")
    if payload["child_exit_code"] != 0:
        raise ValueError("registration result child exit is not zero")
    if type(payload["runner_id"]) is not int or payload["runner_id"] <= 0:
        raise ValueError("registration result runner id invalid")
    if (
        type(payload["runner_readback_attempts"]) is not int
        or payload["runner_readback_attempts"] <= 0
    ):
        raise ValueError("registration result readback attempts invalid")
    for field in ("started_at", "ended_at"):
        value = payload[field]
        if type(value) is not str or not value:
            raise ValueError(f"registration result {field} invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"registration result {field} invalid") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(
                f"registration result {field} must be timezone-aware"
            )
    return payload


def _parse_local_runner_settings(
    raw: bytes,
    *,
    expected_runner_id: int,
    expected_runner_name: str,
    expected_work_folder: str,
) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("local runner settings must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("local runner settings JSON invalid") from error
    if type(payload) is not dict:
        raise ValueError("local runner settings shape invalid")
    if payload.get("agentId") != expected_runner_id:
        raise ValueError("local runner settings agent id mismatch")
    if payload.get("agentName") != expected_runner_name:
        raise ValueError("local runner settings name mismatch")
    if payload.get("workFolder") != expected_work_folder:
        raise ValueError("local runner settings work folder mismatch")
    if payload.get("ephemeral") is not True:
        raise ValueError("local runner settings not ephemeral")
    if payload.get("disableUpdate") is not True:
        raise ValueError("local runner settings update disablement missing")
    return payload


def build_registration_handoff_evidence(
    *,
    phase0_evidence_bytes: bytes,
    registration_plan_bytes: bytes,
    human_approval_bytes: bytes,
    registration_consumption_bytes: bytes,
    registration_result_bytes: bytes,
    local_runner_settings_bytes: bytes,
    runner_generation_snapshot_bytes: bytes,
) -> RegistrationHandoffEvidence:
    phase0 = validate_phase0_evidence_bytes(phase0_evidence_bytes)
    phase0_sha = _sha256(phase0_evidence_bytes)
    expected_binding = live_registration_binding_from_phase0_evidence_bytes(
        phase0_evidence_bytes
    )

    plan = parse_plan_bytes(registration_plan_bytes)
    plan_sha = _sha256(registration_plan_bytes)
    if validate_frozen_plan(
        plan,
        phase0_evidence_bytes=phase0_evidence_bytes,
    ):
        raise ValueError("registration plan does not match Phase 0 evidence")
    if plan.binding != expected_binding:
        raise ValueError("registration plan binding mismatch")

    approval_sha = approval_sha256(human_approval_bytes)
    consumption = parse_consumption_marker_bytes(
        registration_consumption_bytes,
        expected_plan_sha256=plan_sha,
        expected_phase0_evidence_sha256=phase0_sha,
        expected_human_approval_sha256=approval_sha,
    )
    try:
        consumed_at = datetime.fromisoformat(
            consumption.consumed_at.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("registration consumption timestamp invalid") from error
    approval = parse_approval_bytes(
        human_approval_bytes,
        expected_plan_sha256=plan_sha,
        now=lambda: consumed_at,
    )
    if approval.host != phase0.host:
        raise ValueError("registration approval host mismatch")
    if approval.approver_identity != phase0.broker_identity:
        raise ValueError("registration approval identity mismatch")
    consumption_sha = _sha256(registration_consumption_bytes)

    result = _parse_registration_result(
        registration_result_bytes,
        expected_plan_sha256=plan_sha,
        expected_human_approval_sha256=approval_sha,
    )
    result_binding = (
        result["repository"],
        result["pull_request_number"],
        result["target_sha"],
        result["workflow_sha"],
        result["workflow_path"],
        result["runner_name"],
        result["runner_label"],
        result["environment_generation"],
    )
    expected_result_binding = (
        expected_binding.repository,
        expected_binding.pull_request_number,
        expected_binding.target_sha,
        expected_binding.workflow_sha,
        expected_binding.workflow_path,
        expected_binding.runner_name,
        expected_binding.runner_label,
        expected_binding.environment_generation,
    )
    if result_binding != expected_result_binding:
        raise ValueError("registration result binding mismatch")
    if result["candidate_sha256"] != plan.candidate_sha256:
        raise ValueError("registration result candidate SHA-256 mismatch")

    runner_id = result["runner_id"]
    assert type(runner_id) is int
    _parse_local_runner_settings(
        local_runner_settings_bytes,
        expected_runner_id=runner_id,
        expected_runner_name=expected_binding.runner_name,
        expected_work_folder=expected_binding.work_folder,
    )
    snapshot = parse_runner_generation_snapshot_bytes(
        runner_generation_snapshot_bytes
    )
    if snapshot["work_folder"] != expected_binding.work_folder:
        raise ValueError("runner generation snapshot work folder mismatch")

    cross_phase_binding = PrivateCiPilotBinding(
        repository=expected_binding.repository,
        pull_request_number=expected_binding.pull_request_number,
        target_sha=expected_binding.target_sha,
        controller_main_sha=phase0.controller_main_sha,
        controller_tree=phase0.controller_tree,
        workflow_sha=expected_binding.workflow_sha,
        workflow_path=expected_binding.workflow_path,
        runner_id=runner_id,
        runner_name=expected_binding.runner_name,
        runner_label=expected_binding.runner_label,
        environment_generation=expected_binding.environment_generation,
        runner_root=expected_binding.runner_root,
        work_folder=expected_binding.work_folder,
        host=phase0.host,
        broker_identity=phase0.broker_identity,
        target_identity=phase0.target_identity,
    )
    evidence = RegistrationHandoffEvidence(
        schema=REGISTRATION_HANDOFF_SCHEMA,
        binding=cross_phase_binding,
        phase0_evidence_sha256=phase0_sha,
        registration_plan_sha256=plan_sha,
        human_approval_sha256=approval_sha,
        registration_consumption_sha256=consumption_sha,
        registration_result_sha256=_sha256(registration_result_bytes),
        local_runner_settings_sha256=_sha256(local_runner_settings_bytes),
        runner_generation_snapshot_sha256=_sha256(
            runner_generation_snapshot_bytes
        ),
        registration_status="REGISTERED",
    )
    registration_handoff_bytes(evidence)
    return evidence
