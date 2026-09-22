from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from agent_controller.private_ci_consumption_marker import CONSUMPTION_ROOT


PHASE6_CONSUMPTION_SCHEMA = "agent-controller.private-ci-phase6-consumed.v1"
PHASE6_CONSUMPTION_FILENAME_PREFIX = "issue230-phase6-cleanup-"


@dataclass(frozen=True, slots=True)
class Phase6ConsumptionMarker:
    schema: str
    phase6_plan_sha256: str
    phase5_result_sha256: str
    human_approval_sha256: str
    consumed_at: str


def _digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"Phase 6 {field} invalid")
    return value


def phase6_consumption_marker_path(phase6_plan_sha256: str) -> Path:
    digest = _digest(phase6_plan_sha256, "plan SHA-256")
    return CONSUMPTION_ROOT / (
        f"{PHASE6_CONSUMPTION_FILENAME_PREFIX}{digest}.consumed.json"
    )


def canonical_phase6_consumption_bytes(payload: dict[str, object]) -> bytes:
    ordered = {
        "schema": payload["schema"],
        "phase6_plan_sha256": payload["phase6_plan_sha256"],
        "phase5_result_sha256": payload["phase5_result_sha256"],
        "human_approval_sha256": payload["human_approval_sha256"],
        "consumed_at": payload["consumed_at"],
    }
    return (
        json.dumps(ordered, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def parse_phase6_consumption_marker_bytes(
    raw: bytes,
    *,
    expected_plan_sha256: str,
    expected_phase5_result_sha256: str,
    expected_human_approval_sha256: str,
) -> Phase6ConsumptionMarker:
    if type(raw) is not bytes:
        raise ValueError("Phase 6 consumption marker must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 6 consumption marker JSON invalid") from error

    expected = {
        "schema",
        "phase6_plan_sha256",
        "phase5_result_sha256",
        "human_approval_sha256",
        "consumed_at",
    }
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 6 consumption marker shape invalid")
    if raw != canonical_phase6_consumption_bytes(payload):
        raise ValueError("Phase 6 consumption marker is not canonical")
    if payload["schema"] != PHASE6_CONSUMPTION_SCHEMA:
        raise ValueError("Phase 6 consumption marker schema invalid")

    plan_sha = _digest(payload["phase6_plan_sha256"], "plan SHA-256")
    phase5_sha = _digest(
        payload["phase5_result_sha256"],
        "Phase 5 result SHA-256",
    )
    approval_sha = _digest(
        payload["human_approval_sha256"],
        "human approval SHA-256",
    )
    if plan_sha != _digest(expected_plan_sha256, "expected plan SHA-256"):
        raise ValueError("Phase 6 consumption marker plan SHA-256 mismatch")
    if phase5_sha != _digest(
        expected_phase5_result_sha256,
        "expected Phase 5 result SHA-256",
    ):
        raise ValueError(
            "Phase 6 consumption marker Phase 5 result SHA-256 mismatch"
        )
    if approval_sha != _digest(
        expected_human_approval_sha256,
        "expected human approval SHA-256",
    ):
        raise ValueError(
            "Phase 6 consumption marker human approval SHA-256 mismatch"
        )

    consumed_at = payload["consumed_at"]
    if type(consumed_at) is not str or not consumed_at:
        raise ValueError("Phase 6 consumption marker consumed_at invalid")
    try:
        parsed = datetime.fromisoformat(consumed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            "Phase 6 consumption marker consumed_at invalid"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "Phase 6 consumption marker consumed_at must be timezone-aware"
        )

    return Phase6ConsumptionMarker(
        schema=payload["schema"],
        phase6_plan_sha256=plan_sha,
        phase5_result_sha256=phase5_sha,
        human_approval_sha256=approval_sha,
        consumed_at=consumed_at,
    )


@dataclass(frozen=True, slots=True)
class _CleanupAuthorityBinding:
    phase6_plan_sha256: str
    phase5_result_sha256: str
    human_approval_sha256: str


class InMemoryPhase6CleanupAuthority:
    """Test seam for single-use cleanup authority semantics.

    Durable production consumption remains represented by the canonical
    consumption marker. This in-memory seam proves replay rejection without
    granting mutation authority by itself.
    """

    def __init__(self) -> None:
        self._issued: dict[str, _CleanupAuthorityBinding] = {}
        self._consumed: set[str] = set()

    def issue_for_test(
        self,
        *,
        phase6_plan_sha256: str,
        phase5_result_sha256: str,
        human_approval_sha256: str,
    ) -> str:
        binding = _CleanupAuthorityBinding(
            phase6_plan_sha256=_digest(
                phase6_plan_sha256, "plan SHA-256"
            ),
            phase5_result_sha256=_digest(
                phase5_result_sha256, "Phase 5 result SHA-256"
            ),
            human_approval_sha256=_digest(
                human_approval_sha256, "human approval SHA-256"
            ),
        )
        token = secrets.token_hex(32)
        self._issued[token] = binding
        return token

    def consume(
        self,
        token: str,
        *,
        phase6_plan_sha256: str,
        phase5_result_sha256: str,
        human_approval_sha256: str,
    ) -> None:
        if type(token) is not str or token in self._consumed:
            raise ValueError("Phase 6 cleanup authority already consumed")
        expected = _CleanupAuthorityBinding(
            phase6_plan_sha256=_digest(
                phase6_plan_sha256, "plan SHA-256"
            ),
            phase5_result_sha256=_digest(
                phase5_result_sha256, "Phase 5 result SHA-256"
            ),
            human_approval_sha256=_digest(
                human_approval_sha256, "human approval SHA-256"
            ),
        )
        actual = self._issued.get(token)
        if actual is None:
            raise ValueError("Phase 6 cleanup authority unknown")
        if actual != expected:
            raise ValueError("Phase 6 cleanup authority binding mismatch")
        self._consumed.add(token)
