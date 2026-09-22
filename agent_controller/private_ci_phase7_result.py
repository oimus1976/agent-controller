from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from agent_controller.private_ci_phase4_contract import (
    PrivateCiPilotBinding,
    pilot_binding_reason_codes,
)


PHASE7_RESULT_SCHEMA = "agent-controller.private-ci-phase7-result.v1"
PHASE7_ZERO_RESIDUAL_STATUS = "PHASE7_ZERO_RESIDUAL_PASS"


@dataclass(frozen=True, slots=True)
class ZeroResidualObservation:
    runner_match_count: int
    active_targetable_run_count: int
    generation_exists: bool
    workspace_exists: bool
    process_count: int
    service_count: int
    task_count: int
    credential_lifecycle_proven: bool
    target_binding_exact: bool
    github_readback_complete: bool
    local_readback_complete: bool


@dataclass(frozen=True, slots=True)
class Phase7ZeroResidualEvidence:
    schema: str
    binding: PrivateCiPilotBinding
    phase6_result_sha256: str
    observation: ZeroResidualObservation
    status: str


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonnegative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _observation_reason_codes(
    observation: object,
) -> tuple[str, ...]:
    if type(observation) is not ZeroResidualObservation:
        return ("PHASE7_OBSERVATION_TYPE_INVALID",)

    reasons: list[str] = []
    count_fields = (
        ("RUNNER_RESIDUAL", observation.runner_match_count),
        ("ACTIVE_JOB_RESIDUAL", observation.active_targetable_run_count),
        ("PROCESS_RESIDUAL", observation.process_count),
        ("SERVICE_RESIDUAL", observation.service_count),
        ("TASK_RESIDUAL", observation.task_count),
    )
    for reason, value in count_fields:
        if not _nonnegative_int(value) or value != 0:
            reasons.append(reason)

    bool_fields = (
        ("GENERATION_RESIDUAL", observation.generation_exists, False),
        ("WORKSPACE_RESIDUAL", observation.workspace_exists, False),
        (
            "CREDENTIAL_LIFECYCLE_UNPROVEN",
            observation.credential_lifecycle_proven,
            True,
        ),
        ("TARGET_BINDING_DRIFT", observation.target_binding_exact, True),
        (
            "GITHUB_READBACK_INCOMPLETE",
            observation.github_readback_complete,
            True,
        ),
        (
            "LOCAL_READBACK_INCOMPLETE",
            observation.local_readback_complete,
            True,
        ),
    )
    for reason, value, expected in bool_fields:
        if type(value) is not bool or value is not expected:
            reasons.append(reason)

    return tuple(reasons)


def build_phase7_zero_residual_result(
    *,
    binding: PrivateCiPilotBinding,
    phase6_result_sha256: str,
    observation: ZeroResidualObservation,
) -> Phase7ZeroResidualEvidence:
    binding_reasons = pilot_binding_reason_codes(binding)
    if binding_reasons:
        raise ValueError(
            "Phase 7 pilot binding invalid: " + ",".join(binding_reasons)
        )
    if not _digest(phase6_result_sha256):
        raise ValueError("Phase 7 Phase 6 result SHA-256 invalid")

    reasons = _observation_reason_codes(observation)
    if reasons:
        raise ValueError(
            "Phase 7 zero-residual observation invalid: "
            + ",".join(reasons)
        )

    return Phase7ZeroResidualEvidence(
        schema=PHASE7_RESULT_SCHEMA,
        binding=binding,
        phase6_result_sha256=phase6_result_sha256,
        observation=observation,
        status=PHASE7_ZERO_RESIDUAL_STATUS,
    )


def phase7_result_reason_codes(
    evidence: object,
) -> tuple[str, ...]:
    if type(evidence) is not Phase7ZeroResidualEvidence:
        return ("PHASE7_RESULT_TYPE_INVALID",)

    reasons: list[str] = []
    if evidence.schema != PHASE7_RESULT_SCHEMA:
        reasons.append("PHASE7_RESULT_SCHEMA_INVALID")
    for reason in pilot_binding_reason_codes(evidence.binding):
        reasons.append("PHASE7_RESULT_" + reason)
    if not _digest(evidence.phase6_result_sha256):
        reasons.append("PHASE7_RESULT_PHASE6_SHA_INVALID")
    reasons.extend(_observation_reason_codes(evidence.observation))
    if evidence.status != PHASE7_ZERO_RESIDUAL_STATUS:
        reasons.append("PHASE7_RESULT_STATUS_INVALID")
    return tuple(reasons)


def phase7_result_bytes(evidence: Phase7ZeroResidualEvidence) -> bytes:
    reasons = phase7_result_reason_codes(evidence)
    if reasons:
        raise ValueError("Phase 7 result invalid: " + ",".join(reasons))
    return (
        json.dumps(
            asdict(evidence),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase7_result_bytes(raw: bytes) -> Phase7ZeroResidualEvidence:
    if type(raw) is not bytes:
        raise ValueError("Phase 7 result must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 7 result JSON invalid") from error

    expected = set(Phase7ZeroResidualEvidence.__dataclass_fields__)
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 7 result shape invalid")

    binding_payload = payload.get("binding")
    observation_payload = payload.get("observation")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 7 result binding shape invalid")
    if (
        type(observation_payload) is not dict
        or set(observation_payload)
        != set(ZeroResidualObservation.__dataclass_fields__)
    ):
        raise ValueError("Phase 7 observation shape invalid")

    try:
        evidence = Phase7ZeroResidualEvidence(
            schema=payload["schema"],
            binding=PrivateCiPilotBinding(**binding_payload),
            phase6_result_sha256=payload["phase6_result_sha256"],
            observation=ZeroResidualObservation(**observation_payload),
            status=payload["status"],
        )
    except TypeError as error:
        raise ValueError("Phase 7 result fields invalid") from error

    if raw != phase7_result_bytes(evidence):
        raise ValueError("Phase 7 result is not canonical")
    return evidence
