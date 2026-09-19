from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime

from agent_controller.private_ci_phase4_contract import (
    PrivateCiPilotBinding,
    pilot_binding_reason_codes,
)


PHASE4_RESULT_SCHEMA = "agent-controller.private-ci-phase4-result.v1"
PHASE4_RESULT_STATUS = "PHASE4_TARGET_ENVIRONMENT_PASS"
PHASE4_TARGET_PROBE_SCHEMA = "agent-controller.private-ci-phase4-target-probe.v1"


@dataclass(frozen=True, slots=True)
class Phase4ResultEvidence:
    schema: str
    binding: PrivateCiPilotBinding
    phase4_plan_sha256: str
    registration_handoff_sha256: str
    human_approval_sha256: str
    phase4_consumption_sha256: str
    candidate_sha256: str
    target_probe_sha256: str
    target_probe_result_sha256: str
    target_probe_stdout_sha256: str
    target_probe_stderr_sha256: str
    runner_generation_snapshot_sha256: str
    status: str
    completed_at: str


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def parse_target_probe_result_bytes(
    raw: bytes,
    *,
    binding: PrivateCiPilotBinding,
) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("Phase 4 target probe result must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 4 target probe result JSON invalid") from error
    expected = {
        "schema",
        "status",
        "host",
        "identity",
        "admin_sid_present",
        "high_integrity_present",
        "forbidden_environment_count",
        "broker_credential_roots_readable",
        "gh_authenticated",
        "authority_marker_write_denied",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 4 target probe result shape invalid")
    if payload["schema"] != PHASE4_TARGET_PROBE_SCHEMA:
        raise ValueError("Phase 4 target probe result schema invalid")
    if payload["status"] != "TARGET_PROBE_PASS":
        raise ValueError("Phase 4 target probe did not pass")
    expected_identity = f"{binding.host}\\{binding.target_identity}"
    if payload["host"] != binding.host:
        raise ValueError("Phase 4 target probe host mismatch")
    if str(payload["identity"]).casefold() != expected_identity.casefold():
        raise ValueError("Phase 4 target probe identity mismatch")
    safe_expectations = {
        "admin_sid_present": False,
        "high_integrity_present": False,
        "forbidden_environment_count": 0,
        "broker_credential_roots_readable": 0,
        "gh_authenticated": False,
        "authority_marker_write_denied": True,
    }
    for field, expected_value in safe_expectations.items():
        if payload[field] != expected_value:
            raise ValueError(f"Phase 4 target probe unsafe field: {field}")
    return payload


def phase4_result_reason_codes(
    evidence: object,
) -> tuple[str, ...]:
    if type(evidence) is not Phase4ResultEvidence:
        return ("PHASE4_RESULT_TYPE_INVALID",)
    reasons: list[str] = []
    if evidence.schema != PHASE4_RESULT_SCHEMA:
        reasons.append("PHASE4_RESULT_SCHEMA_INVALID")
    for reason in pilot_binding_reason_codes(evidence.binding):
        reasons.append("PHASE4_RESULT_" + reason)
    digest_fields = (
        ("PHASE4_RESULT_PLAN_SHA_INVALID", evidence.phase4_plan_sha256),
        (
            "PHASE4_RESULT_HANDOFF_SHA_INVALID",
            evidence.registration_handoff_sha256,
        ),
        (
            "PHASE4_RESULT_APPROVAL_SHA_INVALID",
            evidence.human_approval_sha256,
        ),
        (
            "PHASE4_RESULT_CONSUMPTION_SHA_INVALID",
            evidence.phase4_consumption_sha256,
        ),
        ("PHASE4_RESULT_CANDIDATE_SHA_INVALID", evidence.candidate_sha256),
        ("PHASE4_RESULT_PROBE_SHA_INVALID", evidence.target_probe_sha256),
        (
            "PHASE4_RESULT_PROBE_RESULT_SHA_INVALID",
            evidence.target_probe_result_sha256,
        ),
        (
            "PHASE4_RESULT_PROBE_STDOUT_SHA_INVALID",
            evidence.target_probe_stdout_sha256,
        ),
        (
            "PHASE4_RESULT_PROBE_STDERR_SHA_INVALID",
            evidence.target_probe_stderr_sha256,
        ),
        (
            "PHASE4_RESULT_RUNNER_SNAPSHOT_SHA_INVALID",
            evidence.runner_generation_snapshot_sha256,
        ),
    )
    for reason, value in digest_fields:
        if not _digest(value):
            reasons.append(reason)
    if evidence.status != PHASE4_RESULT_STATUS:
        reasons.append("PHASE4_RESULT_STATUS_INVALID")
    if type(evidence.completed_at) is not str or not evidence.completed_at:
        reasons.append("PHASE4_RESULT_COMPLETED_AT_INVALID")
    else:
        try:
            parsed = datetime.fromisoformat(
                evidence.completed_at.replace("Z", "+00:00")
            )
        except ValueError:
            reasons.append("PHASE4_RESULT_COMPLETED_AT_INVALID")
        else:
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                reasons.append("PHASE4_RESULT_COMPLETED_AT_INVALID")
    return tuple(reasons)


def phase4_result_bytes(evidence: Phase4ResultEvidence) -> bytes:
    reasons = phase4_result_reason_codes(evidence)
    if reasons:
        raise ValueError("Phase 4 result invalid: " + ",".join(reasons))
    return (
        json.dumps(
            asdict(evidence),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase4_result_bytes(raw: bytes) -> Phase4ResultEvidence:
    if type(raw) is not bytes:
        raise ValueError("Phase 4 result must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 4 result JSON invalid") from error
    expected = set(Phase4ResultEvidence.__dataclass_fields__)
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 4 result shape invalid")
    binding_payload = payload.get("binding")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 4 result binding shape invalid")
    try:
        evidence = Phase4ResultEvidence(
            schema=payload["schema"],
            binding=PrivateCiPilotBinding(**binding_payload),
            phase4_plan_sha256=payload["phase4_plan_sha256"],
            registration_handoff_sha256=payload[
                "registration_handoff_sha256"
            ],
            human_approval_sha256=payload["human_approval_sha256"],
            phase4_consumption_sha256=payload[
                "phase4_consumption_sha256"
            ],
            candidate_sha256=payload["candidate_sha256"],
            target_probe_sha256=payload["target_probe_sha256"],
            target_probe_result_sha256=payload[
                "target_probe_result_sha256"
            ],
            target_probe_stdout_sha256=payload[
                "target_probe_stdout_sha256"
            ],
            target_probe_stderr_sha256=payload[
                "target_probe_stderr_sha256"
            ],
            runner_generation_snapshot_sha256=payload[
                "runner_generation_snapshot_sha256"
            ],
            status=payload["status"],
            completed_at=payload["completed_at"],
        )
    except TypeError as error:
        raise ValueError("Phase 4 result fields invalid") from error
    if raw != phase4_result_bytes(evidence):
        raise ValueError("Phase 4 result is not canonical")
    return evidence


def sha256_bytes(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise ValueError("artifact must be exact bytes")
    return hashlib.sha256(raw).hexdigest()
