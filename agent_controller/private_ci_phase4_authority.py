from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from agent_controller.private_ci_consumption_marker import CONSUMPTION_ROOT


PHASE4_CONSUMPTION_SCHEMA = "agent-controller.private-ci-phase4-consumed.v1"
PHASE4_APPROVAL_FILENAME_PREFIX = "issue225-phase4-approval-"
PHASE4_CONSUMPTION_FILENAME_PREFIX = "issue225-phase4-handoff-"


@dataclass(frozen=True, slots=True)
class Phase4ConsumptionMarker:
    schema: str
    phase4_plan_sha256: str
    registration_handoff_sha256: str
    human_approval_sha256: str
    consumed_at: str


def _digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"Phase 4 {field} invalid")
    return value


def phase4_approval_filename(plan_sha256: str) -> str:
    digest = _digest(plan_sha256, "plan SHA-256")
    return f"{PHASE4_APPROVAL_FILENAME_PREFIX}{digest}.json"


def phase4_consumption_marker_path(
    registration_handoff_sha256: str,
) -> Path:
    digest = _digest(
        registration_handoff_sha256,
        "handoff SHA-256",
    )
    return (
        CONSUMPTION_ROOT
        / f"{PHASE4_CONSUMPTION_FILENAME_PREFIX}{digest}.consumed.json"
    )


def canonical_phase4_consumption_bytes(
    payload: dict[str, object],
) -> bytes:
    ordered = {
        "schema": payload["schema"],
        "phase4_plan_sha256": payload["phase4_plan_sha256"],
        "registration_handoff_sha256": payload[
            "registration_handoff_sha256"
        ],
        "human_approval_sha256": payload["human_approval_sha256"],
        "consumed_at": payload["consumed_at"],
    }
    return (
        json.dumps(
            ordered,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase4_consumption_marker_bytes(
    raw: bytes,
    *,
    expected_plan_sha256: str,
    expected_registration_handoff_sha256: str,
    expected_human_approval_sha256: str,
) -> Phase4ConsumptionMarker:
    if type(raw) is not bytes:
        raise ValueError("Phase 4 consumption marker must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 4 consumption marker JSON invalid") from error
    expected = {
        "schema",
        "phase4_plan_sha256",
        "registration_handoff_sha256",
        "human_approval_sha256",
        "consumed_at",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 4 consumption marker shape invalid")
    if raw != canonical_phase4_consumption_bytes(payload):
        raise ValueError("Phase 4 consumption marker is not canonical")
    if payload["schema"] != PHASE4_CONSUMPTION_SCHEMA:
        raise ValueError("Phase 4 consumption marker schema invalid")

    plan_sha = _digest(
        payload["phase4_plan_sha256"],
        "plan SHA-256",
    )
    handoff_sha = _digest(
        payload["registration_handoff_sha256"],
        "handoff SHA-256",
    )
    approval_sha = _digest(
        payload["human_approval_sha256"],
        "human approval SHA-256",
    )
    if plan_sha != _digest(
        expected_plan_sha256,
        "expected plan SHA-256",
    ):
        raise ValueError("Phase 4 consumption marker plan SHA-256 mismatch")
    if handoff_sha != _digest(
        expected_registration_handoff_sha256,
        "expected handoff SHA-256",
    ):
        raise ValueError(
            "Phase 4 consumption marker handoff SHA-256 mismatch"
        )
    if approval_sha != _digest(
        expected_human_approval_sha256,
        "expected human approval SHA-256",
    ):
        raise ValueError(
            "Phase 4 consumption marker human approval SHA-256 mismatch"
        )

    consumed_at = payload["consumed_at"]
    if type(consumed_at) is not str or not consumed_at:
        raise ValueError("Phase 4 consumption marker consumed_at invalid")
    try:
        parsed = datetime.fromisoformat(
            consumed_at.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "Phase 4 consumption marker consumed_at invalid"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "Phase 4 consumption marker consumed_at must be timezone-aware"
        )

    return Phase4ConsumptionMarker(
        schema=payload["schema"],
        phase4_plan_sha256=plan_sha,
        registration_handoff_sha256=handoff_sha,
        human_approval_sha256=approval_sha,
        consumed_at=consumed_at,
    )
