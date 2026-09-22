from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    OperatorEffectClass,
    OperatorStepSpec,
    PriorEvidenceRequirement,
)
from agent_controller.private_ci_phase4_contract import (
    PrivateCiPilotBinding,
    pilot_binding_reason_codes,
)
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_STATUS,
    parse_phase5_result_bytes,
)


PHASE6_CLEANUP_PLAN_SCHEMA = "agent-controller.private-ci-phase6-cleanup-plan.v1"
PHASE6_OPERATION_ID = "issue230-phase6-cleanup"
PHASE6_STEP_ID = "cleanup-fresh-pilot"
PHASE6_HOST_ROLE = "private-ci-owner-machine"
PHASE6_BROKER_IDENTITY = "c-admin"
PHASE6_TRANSCRIPT_FILENAME = "issue230-phase6-cleanup.log"
PHASE6_SUCCESS_MARKER = "PHASE6_CLEANUP_PASS"
PHASE6_EFFECTS = (
    "HTTP_API_ACCESS",
    "PROCESS_CONTROL",
    "SERVICE_CONTROL",
    "TASK_CONTROL",
    "FILE_SYSTEM_MUTATION",
)
PHASE5_RESULT_PRODUCER_OPERATION_ID = "issue225-phase5-exactly-one-job"
PHASE5_RESULT_PRODUCER_STEP_ID = "run-exactly-one-job"


@dataclass(frozen=True, slots=True)
class Phase6CleanupPlan:
    schema: str
    phase5_result_sha256: str
    binding: PrivateCiPilotBinding
    runner_id: int
    runner_name: str
    runner_label: str
    environment_generation: str
    runner_root: str
    work_folder: str


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _reason_codes(plan: object) -> tuple[str, ...]:
    if type(plan) is not Phase6CleanupPlan:
        return ("PHASE6_PLAN_TYPE_INVALID",)
    reasons: list[str] = []
    if plan.schema != PHASE6_CLEANUP_PLAN_SCHEMA:
        reasons.append("PHASE6_PLAN_SCHEMA_INVALID")
    for reason in pilot_binding_reason_codes(plan.binding):
        reasons.append("PHASE6_PLAN_" + reason)
    if not _digest(plan.phase5_result_sha256):
        reasons.append("PHASE6_PLAN_PHASE5_SHA_INVALID")
    exact = (
        ("RUNNER_ID", plan.runner_id, plan.binding.runner_id),
        ("RUNNER_NAME", plan.runner_name, plan.binding.runner_name),
        ("RUNNER_LABEL", plan.runner_label, plan.binding.runner_label),
        (
            "ENVIRONMENT_GENERATION",
            plan.environment_generation,
            plan.binding.environment_generation,
        ),
        ("RUNNER_ROOT", plan.runner_root, plan.binding.runner_root),
        ("WORK_FOLDER", plan.work_folder, plan.binding.work_folder),
    )
    for label, observed, expected in exact:
        if observed != expected:
            reasons.append("PHASE6_PLAN_" + label + "_MISMATCH")
    return tuple(reasons)


def build_phase6_cleanup_plan(phase5_result_bytes: bytes) -> Phase6CleanupPlan:
    evidence = parse_phase5_result_bytes(phase5_result_bytes)
    if evidence.status != PHASE5_RESULT_STATUS:
        raise ValueError("Phase 5 result status invalid for cleanup plan")
    binding = evidence.binding
    return Phase6CleanupPlan(
        schema=PHASE6_CLEANUP_PLAN_SCHEMA,
        phase5_result_sha256=hashlib.sha256(phase5_result_bytes).hexdigest(),
        binding=binding,
        runner_id=binding.runner_id,
        runner_name=binding.runner_name,
        runner_label=binding.runner_label,
        environment_generation=binding.environment_generation,
        runner_root=binding.runner_root,
        work_folder=binding.work_folder,
    )


def phase6_cleanup_plan_bytes(plan: Phase6CleanupPlan) -> bytes:
    reasons = _reason_codes(plan)
    if reasons:
        raise ValueError("Phase 6 cleanup plan invalid: " + ",".join(reasons))
    return (
        json.dumps(
            asdict(plan),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase6_cleanup_plan_bytes(raw: bytes) -> Phase6CleanupPlan:
    if type(raw) is not bytes:
        raise ValueError("Phase 6 cleanup plan must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 6 cleanup plan JSON invalid") from error
    expected = set(Phase6CleanupPlan.__dataclass_fields__)
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 6 cleanup plan shape invalid")
    binding_payload = payload.get("binding")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 6 cleanup plan binding shape invalid")
    try:
        plan = Phase6CleanupPlan(
            schema=payload["schema"],
            phase5_result_sha256=payload["phase5_result_sha256"],
            binding=PrivateCiPilotBinding(**binding_payload),
            runner_id=payload["runner_id"],
            runner_name=payload["runner_name"],
            runner_label=payload["runner_label"],
            environment_generation=payload["environment_generation"],
            runner_root=payload["runner_root"],
            work_folder=payload["work_folder"],
        )
    except TypeError as error:
        raise ValueError("Phase 6 cleanup plan fields invalid") from error
    if raw != phase6_cleanup_plan_bytes(plan):
        raise ValueError("Phase 6 cleanup plan is not canonical")
    return plan


def build_phase6_cleanup_operator_spec(
    plan: Phase6CleanupPlan,
    *,
    phase6_plan_sha256: str,
) -> OperatorStepSpec:
    reasons = _reason_codes(plan)
    if reasons:
        raise ValueError("Phase 6 cleanup plan invalid: " + ",".join(reasons))
    if not _digest(phase6_plan_sha256):
        raise ValueError("Phase 6 plan SHA-256 invalid")
    return OperatorStepSpec(
        operation_id=PHASE6_OPERATION_ID,
        step_id=PHASE6_STEP_ID,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=plan.binding.repository,
        pull_request_number=plan.binding.pull_request_number,
        target_sha=plan.binding.target_sha,
        target_host_role=PHASE6_HOST_ROLE,
        required_identity=PHASE6_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=PHASE6_TRANSCRIPT_FILENAME,
        expected_success_marker=PHASE6_SUCCESS_MARKER,
        allowed_effect_families=PHASE6_EFFECTS,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id=PHASE5_RESULT_PRODUCER_OPERATION_ID,
            producer_step_id=PHASE5_RESULT_PRODUCER_STEP_ID,
            evidence_sha256=plan.phase5_result_sha256,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=True,
        require_child_exit_code=True,
        require_fail_fast=True,
    )
