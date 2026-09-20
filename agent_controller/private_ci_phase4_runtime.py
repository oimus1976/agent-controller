from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from agent_controller.operator_step_gate import (
    AuthenticatedAstAttestation,
    OperatorGateStatus,
    operator_step_spec_sha256,
)
from agent_controller.private_ci_phase4_contract import (
    PrivateCiPilotBinding,
    build_phase4_target_environment_spec,
    parse_registration_handoff_bytes,
    phase4_target_probe_sha256,
    plan_phase4_target_environment,
    render_phase4_target_environment_candidate,
)


PHASE4_PLAN_SCHEMA = "agent-controller.private-ci-phase4-plan.v1"


@dataclass(frozen=True, slots=True)
class Phase4Plan:
    schema: str
    binding: PrivateCiPilotBinding
    registration_handoff_sha256: str
    candidate: str
    candidate_sha256: str
    spec_sha256: str
    target_probe_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "binding": asdict(self.binding),
            "registration_handoff_sha256": self.registration_handoff_sha256,
            "candidate": self.candidate,
            "candidate_sha256": self.candidate_sha256,
            "spec_sha256": self.spec_sha256,
            "target_probe_sha256": self.target_probe_sha256,
        }


def _canonical_json_bytes(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _valid_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def phase4_plan_bytes(plan: Phase4Plan) -> bytes:
    if type(plan) is not Phase4Plan:
        raise ValueError("Phase 4 plan type invalid")
    return _canonical_json_bytes(plan.to_dict())


def phase4_plan_sha256(plan: Phase4Plan) -> str:
    return hashlib.sha256(phase4_plan_bytes(plan)).hexdigest()


def parse_phase4_plan_bytes(raw: bytes) -> Phase4Plan:
    if type(raw) is not bytes:
        raise ValueError("Phase 4 plan must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 4 plan JSON invalid") from error
    expected = {
        "schema",
        "binding",
        "registration_handoff_sha256",
        "candidate",
        "candidate_sha256",
        "spec_sha256",
        "target_probe_sha256",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 4 plan shape invalid")
    binding_payload = payload.get("binding")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 4 plan binding shape invalid")
    try:
        plan = Phase4Plan(
            schema=payload["schema"],
            binding=PrivateCiPilotBinding(**binding_payload),
            registration_handoff_sha256=payload[
                "registration_handoff_sha256"
            ],
            candidate=payload["candidate"],
            candidate_sha256=payload["candidate_sha256"],
            spec_sha256=payload["spec_sha256"],
            target_probe_sha256=payload["target_probe_sha256"],
        )
    except TypeError as error:
        raise ValueError("Phase 4 plan fields invalid") from error
    if plan.schema != PHASE4_PLAN_SCHEMA:
        raise ValueError("Phase 4 plan schema invalid")
    if not all(
        _valid_digest(value)
        for value in (
            plan.registration_handoff_sha256,
            plan.candidate_sha256,
            plan.spec_sha256,
            plan.target_probe_sha256,
        )
    ):
        raise ValueError("Phase 4 plan digest invalid")
    if type(plan.candidate) is not str or not plan.candidate:
        raise ValueError("Phase 4 plan candidate invalid")
    if raw != phase4_plan_bytes(plan):
        raise ValueError("Phase 4 plan is not canonical")
    return plan


def validate_frozen_phase4_plan(
    plan: Phase4Plan,
    *,
    registration_handoff_bytes: bytes,
    target_probe_bytes: bytes,
) -> tuple[str, ...]:
    reasons: list[str] = []
    try:
        handoff = parse_registration_handoff_bytes(
            registration_handoff_bytes
        )
    except (TypeError, ValueError):
        return ("PHASE4_PLAN_HANDOFF_INVALID",)
    if handoff.binding != plan.binding:
        reasons.append("PHASE4_PLAN_BINDING_MISMATCH")

    handoff_sha = hashlib.sha256(registration_handoff_bytes).hexdigest()
    if plan.registration_handoff_sha256 != handoff_sha:
        reasons.append("PHASE4_PLAN_HANDOFF_SHA_MISMATCH")

    try:
        probe_sha = phase4_target_probe_sha256(target_probe_bytes)
    except ValueError:
        return tuple(reasons + ["PHASE4_PLAN_TARGET_PROBE_BYTES_INVALID"])
    if plan.target_probe_sha256 != probe_sha:
        reasons.append("PHASE4_PLAN_TARGET_PROBE_SHA_MISMATCH")

    expected_candidate = render_phase4_target_environment_candidate(
        handoff.binding,
        handoff,
        target_probe_sha256=probe_sha,
    )
    if plan.candidate != expected_candidate:
        reasons.append("PHASE4_PLAN_CANDIDATE_MISMATCH")
    expected_candidate_sha = hashlib.sha256(
        expected_candidate.encode("utf-8")
    ).hexdigest()
    if plan.candidate_sha256 != expected_candidate_sha:
        reasons.append("PHASE4_PLAN_CANDIDATE_SHA_MISMATCH")

    spec = build_phase4_target_environment_spec(
        handoff.binding,
        registration_handoff_sha256=handoff_sha,
    )
    if plan.spec_sha256 != operator_step_spec_sha256(spec):
        reasons.append("PHASE4_PLAN_SPEC_SHA_MISMATCH")
    return tuple(reasons)


def build_reviewed_phase4_plan(
    *,
    registration_handoff_bytes: bytes,
    target_probe_bytes: bytes,
    ast_attestation: AuthenticatedAstAttestation,
) -> Phase4Plan:
    handoff = parse_registration_handoff_bytes(
        registration_handoff_bytes
    )
    probe_sha = phase4_target_probe_sha256(target_probe_bytes)
    candidate = render_phase4_target_environment_candidate(
        handoff.binding,
        handoff,
        target_probe_sha256=probe_sha,
    )
    planned = plan_phase4_target_environment(
        registration_handoff_bytes=registration_handoff_bytes,
        target_probe_bytes=target_probe_bytes,
        candidate=candidate,
        ast_attestation=ast_attestation,
    )
    if planned.status is not OperatorGateStatus.PASS_TO_OPERATOR:
        reasons = ",".join(planned.reason_codes) or "PLAN_NOT_PASS"
        raise ValueError(f"Phase 4 plan blocked: {reasons}")
    handoff_sha = hashlib.sha256(registration_handoff_bytes).hexdigest()
    spec = build_phase4_target_environment_spec(
        handoff.binding,
        registration_handoff_sha256=handoff_sha,
    )
    return Phase4Plan(
        schema=PHASE4_PLAN_SCHEMA,
        binding=handoff.binding,
        registration_handoff_sha256=handoff_sha,
        candidate=candidate,
        candidate_sha256=planned.candidate_sha256,
        spec_sha256=operator_step_spec_sha256(spec),
        target_probe_sha256=probe_sha,
    )
