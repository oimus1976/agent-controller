from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from agent_controller.private_ci_consumption_marker import CONSUMPTION_ROOT


PHASE5_CONSUMPTION_SCHEMA = "agent-controller.private-ci-phase5-consumed.v1"
PHASE5_APPROVAL_FILENAME_PREFIX = "issue225-phase5-approval-"
PHASE5_CONSUMPTION_FILENAME_PREFIX = "issue225-phase5-result-"


@dataclass(frozen=True, slots=True)
class Phase5ConsumptionMarker:
    schema: str
    phase5_plan_sha256: str
    phase4_result_sha256: str
    human_approval_sha256: str
    consumed_at: str


def _digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"Phase 5 {field} invalid")
    return value


def phase5_approval_filename(plan_sha256: str) -> str:
    digest = _digest(plan_sha256, "plan SHA-256")
    return f"{PHASE5_APPROVAL_FILENAME_PREFIX}{digest}.json"


def phase5_consumption_marker_path(phase4_result_sha256: str) -> Path:
    digest = _digest(
        phase4_result_sha256,
        "Phase 4 result SHA-256",
    )
    return (
        CONSUMPTION_ROOT
        / f"{PHASE5_CONSUMPTION_FILENAME_PREFIX}{digest}.consumed.json"
    )


def canonical_phase5_consumption_bytes(
    payload: dict[str, object],
) -> bytes:
    ordered = {
        "schema": payload["schema"],
        "phase5_plan_sha256": payload["phase5_plan_sha256"],
        "phase4_result_sha256": payload["phase4_result_sha256"],
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


def parse_phase5_consumption_marker_bytes(
    raw: bytes,
    *,
    expected_plan_sha256: str,
    expected_phase4_result_sha256: str,
    expected_human_approval_sha256: str,
) -> Phase5ConsumptionMarker:
    if type(raw) is not bytes:
        raise ValueError("Phase 5 consumption marker must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 5 consumption marker JSON invalid") from error

    expected = {
        "schema",
        "phase5_plan_sha256",
        "phase4_result_sha256",
        "human_approval_sha256",
        "consumed_at",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 5 consumption marker shape invalid")
    if raw != canonical_phase5_consumption_bytes(payload):
        raise ValueError("Phase 5 consumption marker is not canonical")
    if payload["schema"] != PHASE5_CONSUMPTION_SCHEMA:
        raise ValueError("Phase 5 consumption marker schema invalid")

    plan_sha = _digest(payload["phase5_plan_sha256"], "plan SHA-256")
    phase4_sha = _digest(
        payload["phase4_result_sha256"],
        "Phase 4 result SHA-256",
    )
    approval_sha = _digest(
        payload["human_approval_sha256"],
        "human approval SHA-256",
    )
    if plan_sha != _digest(
        expected_plan_sha256,
        "expected plan SHA-256",
    ):
        raise ValueError("Phase 5 consumption marker plan SHA-256 mismatch")
    if phase4_sha != _digest(
        expected_phase4_result_sha256,
        "expected Phase 4 result SHA-256",
    ):
        raise ValueError(
            "Phase 5 consumption marker Phase 4 result SHA-256 mismatch"
        )
    if approval_sha != _digest(
        expected_human_approval_sha256,
        "expected human approval SHA-256",
    ):
        raise ValueError(
            "Phase 5 consumption marker human approval SHA-256 mismatch"
        )

    consumed_at = payload["consumed_at"]
    if type(consumed_at) is not str or not consumed_at:
        raise ValueError("Phase 5 consumption marker consumed_at invalid")
    try:
        parsed = datetime.fromisoformat(consumed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "Phase 5 consumption marker consumed_at invalid"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "Phase 5 consumption marker consumed_at must be timezone-aware"
        )

    return Phase5ConsumptionMarker(
        schema=payload["schema"],
        phase5_plan_sha256=plan_sha,
        phase4_result_sha256=phase4_sha,
        human_approval_sha256=approval_sha,
        consumed_at=consumed_at,
    )
