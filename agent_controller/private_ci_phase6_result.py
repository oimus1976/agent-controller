from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime

from agent_controller.private_ci_phase4_contract import (
    PrivateCiPilotBinding,
    pilot_binding_reason_codes,
)


PHASE6_RESULT_SCHEMA = "agent-controller.private-ci-phase6-result.v1"
PHASE6_RESULT_STATUS = "PHASE6_CLEANUP_PASS"


@dataclass(frozen=True, slots=True)
class Phase6CleanupResultEvidence:
    schema: str
    binding: PrivateCiPilotBinding
    phase6_plan_sha256: str
    phase5_result_sha256: str
    human_approval_sha256: str
    phase6_consumption_sha256: str
    runner_deregistered: bool
    generation_removed: bool
    status: str
    completed_at: str


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def phase6_result_reason_codes(
    evidence: object,
) -> tuple[str, ...]:
    if type(evidence) is not Phase6CleanupResultEvidence:
        return ("PHASE6_RESULT_TYPE_INVALID",)

    reasons: list[str] = []
    if evidence.schema != PHASE6_RESULT_SCHEMA:
        reasons.append("PHASE6_RESULT_SCHEMA_INVALID")
    for reason in pilot_binding_reason_codes(evidence.binding):
        reasons.append("PHASE6_RESULT_" + reason)

    digest_fields = (
        ("PHASE6_RESULT_PLAN_SHA_INVALID", evidence.phase6_plan_sha256),
        ("PHASE6_RESULT_PHASE5_SHA_INVALID", evidence.phase5_result_sha256),
        (
            "PHASE6_RESULT_APPROVAL_SHA_INVALID",
            evidence.human_approval_sha256,
        ),
        (
            "PHASE6_RESULT_CONSUMPTION_SHA_INVALID",
            evidence.phase6_consumption_sha256,
        ),
    )
    for reason, value in digest_fields:
        if not _digest(value):
            reasons.append(reason)

    if evidence.runner_deregistered is not True:
        reasons.append("PHASE6_RESULT_RUNNER_DEREGISTRATION_FAILED")
    if evidence.generation_removed is not True:
        reasons.append("PHASE6_RESULT_GENERATION_REMOVAL_FAILED")
    if evidence.status != PHASE6_RESULT_STATUS:
        reasons.append("PHASE6_RESULT_STATUS_INVALID")

    if type(evidence.completed_at) is not str or not evidence.completed_at:
        reasons.append("PHASE6_RESULT_COMPLETED_AT_INVALID")
    else:
        try:
            parsed = datetime.fromisoformat(
                evidence.completed_at.replace("Z", "+00:00")
            )
        except ValueError:
            reasons.append("PHASE6_RESULT_COMPLETED_AT_INVALID")
        else:
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                reasons.append("PHASE6_RESULT_COMPLETED_AT_INVALID")

    return tuple(reasons)


def phase6_result_bytes(evidence: Phase6CleanupResultEvidence) -> bytes:
    reasons = phase6_result_reason_codes(evidence)
    if reasons:
        raise ValueError("Phase 6 result invalid: " + ",".join(reasons))
    return (
        json.dumps(
            asdict(evidence),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase6_result_bytes(raw: bytes) -> Phase6CleanupResultEvidence:
    if type(raw) is not bytes:
        raise ValueError("Phase 6 result must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 6 result JSON invalid") from error
    expected = set(Phase6CleanupResultEvidence.__dataclass_fields__)
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 6 result shape invalid")

    binding_payload = payload.get("binding")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 6 result binding shape invalid")

    try:
        evidence = Phase6CleanupResultEvidence(
            schema=payload["schema"],
            binding=PrivateCiPilotBinding(**binding_payload),
            phase6_plan_sha256=payload["phase6_plan_sha256"],
            phase5_result_sha256=payload["phase5_result_sha256"],
            human_approval_sha256=payload["human_approval_sha256"],
            phase6_consumption_sha256=payload["phase6_consumption_sha256"],
            runner_deregistered=payload["runner_deregistered"],
            generation_removed=payload["generation_removed"],
            status=payload["status"],
            completed_at=payload["completed_at"],
        )
    except TypeError as error:
        raise ValueError("Phase 6 result fields invalid") from error

    if raw != phase6_result_bytes(evidence):
        raise ValueError("Phase 6 result is not canonical")
    return evidence
