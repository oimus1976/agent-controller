from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from agent_controller.operator_step_gate import (
    AuthenticatedAstAttestation,
    OperatorGateStatus,
    _attestation_reason_codes,
    _candidate_sha256,
    _spec_reason_codes,
    operator_step_spec_sha256,
)
from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase4_result import (
    parse_phase4_result_bytes,
)
from agent_controller.private_ci_phase5_contract import (
    build_phase5_exactly_one_job_spec,
    render_phase5_exactly_one_job_candidate,
)


PHASE5_PLAN_SCHEMA = "agent-controller.private-ci-phase5-plan.v1"


@dataclass(frozen=True, slots=True)
class Phase5Plan:
    schema: str
    binding: PrivateCiPilotBinding
    phase4_result_sha256: str
    candidate: str
    candidate_sha256: str
    spec_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "binding": asdict(self.binding),
            "phase4_result_sha256": self.phase4_result_sha256,
            "candidate": self.candidate,
            "candidate_sha256": self.candidate_sha256,
            "spec_sha256": self.spec_sha256,
        }


def _valid_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def phase5_plan_bytes(plan: Phase5Plan) -> bytes:
    if type(plan) is not Phase5Plan:
        raise ValueError("Phase 5 plan type invalid")
    return (
        json.dumps(
            plan.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def phase5_plan_sha256(plan: Phase5Plan) -> str:
    return hashlib.sha256(phase5_plan_bytes(plan)).hexdigest()


def parse_phase5_plan_bytes(raw: bytes) -> Phase5Plan:
    if type(raw) is not bytes:
        raise ValueError("Phase 5 plan must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 5 plan JSON invalid") from error
    expected = {
        "schema",
        "binding",
        "phase4_result_sha256",
        "candidate",
        "candidate_sha256",
        "spec_sha256",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 5 plan shape invalid")
    binding_payload = payload.get("binding")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 5 plan binding shape invalid")
    try:
        plan = Phase5Plan(
            schema=payload["schema"],
            binding=PrivateCiPilotBinding(**binding_payload),
            phase4_result_sha256=payload["phase4_result_sha256"],
            candidate=payload["candidate"],
            candidate_sha256=payload["candidate_sha256"],
            spec_sha256=payload["spec_sha256"],
        )
    except TypeError as error:
        raise ValueError("Phase 5 plan fields invalid") from error
    if plan.schema != PHASE5_PLAN_SCHEMA:
        raise ValueError("Phase 5 plan schema invalid")
    if not _valid_digest(plan.phase4_result_sha256):
        raise ValueError("Phase 5 plan Phase 4 result SHA invalid")
    if not _valid_digest(plan.candidate_sha256):
        raise ValueError("Phase 5 plan candidate SHA invalid")
    if not _valid_digest(plan.spec_sha256):
        raise ValueError("Phase 5 plan spec SHA invalid")
    if type(plan.candidate) is not str or not plan.candidate:
        raise ValueError("Phase 5 plan candidate invalid")
    if raw != phase5_plan_bytes(plan):
        raise ValueError("Phase 5 plan is not canonical")
    return plan


def validate_frozen_phase5_plan(
    plan: Phase5Plan,
    *,
    phase4_result_bytes: bytes,
) -> tuple[str, ...]:
    reasons: list[str] = []
    try:
        phase4 = parse_phase4_result_bytes(phase4_result_bytes)
    except (TypeError, ValueError):
        return ("PHASE5_PLAN_PHASE4_RESULT_INVALID",)

    phase4_sha = hashlib.sha256(phase4_result_bytes).hexdigest()
    if plan.phase4_result_sha256 != phase4_sha:
        reasons.append("PHASE5_PLAN_PHASE4_RESULT_SHA_MISMATCH")
    if plan.binding != phase4.binding:
        reasons.append("PHASE5_PLAN_BINDING_MISMATCH")

    expected_candidate = render_phase5_exactly_one_job_candidate(
        phase4.binding,
        phase4_result_sha256=phase4_sha,
    )
    if plan.candidate != expected_candidate:
        reasons.append("PHASE5_PLAN_CANDIDATE_MISMATCH")
    expected_candidate_sha = hashlib.sha256(
        expected_candidate.encode("utf-8")
    ).hexdigest()
    if plan.candidate_sha256 != expected_candidate_sha:
        reasons.append("PHASE5_PLAN_CANDIDATE_SHA_MISMATCH")

    spec = build_phase5_exactly_one_job_spec(
        phase4.binding,
        phase4_result_sha256=phase4_sha,
    )
    if plan.spec_sha256 != operator_step_spec_sha256(spec):
        reasons.append("PHASE5_PLAN_SPEC_SHA_MISMATCH")
    return tuple(reasons)


def build_reviewed_phase5_plan(
    *,
    phase4_result_bytes: bytes,
    ast_attestation: AuthenticatedAstAttestation,
) -> Phase5Plan:
    phase4 = parse_phase4_result_bytes(phase4_result_bytes)
    phase4_sha = hashlib.sha256(phase4_result_bytes).hexdigest()
    candidate = render_phase5_exactly_one_job_candidate(
        phase4.binding,
        phase4_result_sha256=phase4_sha,
    )
    candidate_sha = _candidate_sha256(candidate)
    spec = build_phase5_exactly_one_job_spec(
        phase4.binding,
        phase4_result_sha256=phase4_sha,
    )

    spec_reasons = _spec_reason_codes(spec)
    if spec_reasons:
        raise ValueError(
            "Phase 5 plan blocked: " + ",".join(spec_reasons)
        )
    status, reasons = _attestation_reason_codes(
        spec,
        candidate_sha,
        ast_attestation,
    )
    if status is not OperatorGateStatus.PASS_TO_OPERATOR:
        reasons_text = ",".join(reasons) or status.value
        raise ValueError("Phase 5 plan blocked: " + reasons_text)

    return Phase5Plan(
        schema=PHASE5_PLAN_SCHEMA,
        binding=phase4.binding,
        phase4_result_sha256=phase4_sha,
        candidate=candidate,
        candidate_sha256=candidate_sha,
        spec_sha256=operator_step_spec_sha256(spec),
    )
