from __future__ import annotations

import re
from typing import Any, Mapping, Optional, Sequence

from agent_controller.provider_contract import (
    AgentObservation,
    AwaitingInput,
    ControllerState,
    TerminalClaim,
)


_SAFE_NATIVE_VALUES = frozenset(
    {
        "STATE_UNSPECIFIED",
        "QUEUED",
        "PLANNING",
        "AWAITING_PLAN_APPROVAL",
        "AWAITING_USER_FEEDBACK",
        "IN_PROGRESS",
        "PAUSED",
        "FAILED",
        "COMPLETED",
        "planning",
        "thinking",
        "waiting_for_user",
        "running",
        "working",
        "executing",
        "done",
        "completed",
        "failed",
        "error",
        "plan_review",
        "success",
        "succeeded",
        "failure",
    }
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
_SAFE_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def _string(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _safe_id(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _SAFE_ID.fullmatch(value) else None


def _safe_timestamp(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _SAFE_TIMESTAMP.fullmatch(value) else None


def _evidence_projection(raw_state: Any) -> Any:
    """Retain only bounded structural evidence, never arbitrary provider text."""

    if not isinstance(raw_state, Mapping):
        return {"raw_type": type(raw_state).__name__}

    projection = {}
    for key in ("status", "state", "reason", "result"):
        value = raw_state.get(key)
        if isinstance(value, str) and value in _SAFE_NATIVE_VALUES:
            projection[key] = value

    updated_at = _safe_timestamp(raw_state.get("updated_at")) or _safe_timestamp(raw_state.get("updateTime"))
    if updated_at is not None:
        projection["updated_at"] = updated_at

    for key in ("plan_id", "artifact_id", "result_id", "task_id", "id", "name"):
        value = _safe_id(raw_state.get(key))
        if value is not None:
            projection[key] = value

    return projection


def _refs(raw_state: Mapping[str, Any], keys: Sequence[str]) -> tuple[str, ...]:
    refs = []
    for key in keys:
        value = _safe_id(raw_state.get(key))
        if value is not None:
            refs.append(value)
    return tuple(refs)


def _uncertain(
    *,
    provider: str,
    provider_operation_id: str,
    raw_state: Any,
    observed_at: str,
    provider_updated_at: Optional[str],
    reason: str,
) -> AgentObservation:
    return AgentObservation(
        provider=provider,
        provider_operation_id=provider_operation_id,
        observed_at=observed_at,
        provider_updated_at=provider_updated_at,
        provider_raw_state=_evidence_projection(raw_state),
        mapped_state=ControllerState.UNCERTAIN,
        uncertainty_reason=reason,
    )


def map_jules_observation(
    *,
    provider_operation_id: str,
    raw_state: Any,
    observed_at: str,
) -> AgentObservation:
    """Map an official Jules v1alpha session payload into the provider-neutral observation model."""

    if not isinstance(raw_state, Mapping):
        return _uncertain(
            provider="jules",
            provider_operation_id=provider_operation_id,
            raw_state=raw_state,
            observed_at=observed_at,
            provider_updated_at=None,
            reason="JULES_RAW_STATE_NOT_MAPPING",
        )

    provider_updated_at = _safe_timestamp(raw_state.get("updateTime")) or _safe_timestamp(
        raw_state.get("updated_at")
    )
    state = _string(raw_state.get("state")) or _string(raw_state.get("status"))
    if state is None:
        return _uncertain(
            provider="jules",
            provider_operation_id=provider_operation_id,
            raw_state=raw_state,
            observed_at=observed_at,
            provider_updated_at=provider_updated_at,
            reason="JULES_STATUS_MISSING",
        )

    normalized = state.upper()
    common = dict(
        provider="jules",
        provider_operation_id=provider_operation_id,
        observed_at=observed_at,
        provider_updated_at=provider_updated_at,
        provider_raw_state=_evidence_projection(raw_state),
        provider_refs=_refs(raw_state, ("plan_id", "artifact_id", "result_id", "id", "name")),
    )

    if normalized in {"QUEUED", "PLANNING"}:
        return AgentObservation(mapped_state=ControllerState.PLANNING, **common)
    if normalized == "AWAITING_PLAN_APPROVAL":
        return AgentObservation(
            mapped_state=ControllerState.PLAN_REVIEW_REQUIRED,
            awaiting_input=AwaitingInput.PLAN_APPROVAL,
            **common,
        )
    if normalized == "IN_PROGRESS":
        return AgentObservation(mapped_state=ControllerState.EXECUTING, **common)
    if normalized == "AWAITING_USER_FEEDBACK":
        return AgentObservation(
            mapped_state=ControllerState.REVIEW_REQUIRED,
            awaiting_input=AwaitingInput.USER_FEEDBACK,
            **common,
        )
    if normalized == "PAUSED":
        return AgentObservation(
            mapped_state=ControllerState.BLOCKED,
            **common,
        )
    if normalized == "COMPLETED":
        return AgentObservation(
            mapped_state=ControllerState.ARTIFACT_READY,
            terminal_claim=TerminalClaim.SUCCESS,
            **common,
        )
    if normalized == "FAILED":
        return AgentObservation(
            mapped_state=ControllerState.BLOCKED,
            terminal_claim=TerminalClaim.FAILURE,
            **common,
        )

    return _uncertain(
        provider="jules",
        provider_operation_id=provider_operation_id,
        raw_state=raw_state,
        observed_at=observed_at,
        provider_updated_at=provider_updated_at,
        reason="JULES_STATUS_UNKNOWN",
    )


def map_codex_observation(
    *,
    provider_operation_id: str,
    raw_state: Any,
    observed_at: str,
) -> AgentObservation:
    """Map a Codex fixture payload into the provider-neutral observation model.

    This is fixture vocabulary, not a claim about a stable external Codex API.
    Ambiguous completion without an explicit success result fails closed.
    """

    if not isinstance(raw_state, Mapping):
        return _uncertain(
            provider="codex",
            provider_operation_id=provider_operation_id,
            raw_state=raw_state,
            observed_at=observed_at,
            provider_updated_at=None,
            reason="CODEX_RAW_STATE_NOT_MAPPING",
        )

    provider_updated_at = _safe_timestamp(raw_state.get("updated_at"))
    status = _string(raw_state.get("status"))
    reason = _string(raw_state.get("reason"))
    result = _string(raw_state.get("result"))

    if status is None:
        return _uncertain(
            provider="codex",
            provider_operation_id=provider_operation_id,
            raw_state=raw_state,
            observed_at=observed_at,
            provider_updated_at=provider_updated_at,
            reason="CODEX_STATUS_MISSING",
        )

    normalized = status.lower()
    reason_normalized = reason.lower() if reason else None
    result_normalized = result.lower() if result else None
    common = dict(
        provider="codex",
        provider_operation_id=provider_operation_id,
        observed_at=observed_at,
        provider_updated_at=provider_updated_at,
        provider_raw_state=_evidence_projection(raw_state),
        provider_refs=_refs(raw_state, ("task_id", "artifact_id", "result_id")),
    )

    if normalized in {"planning", "thinking"}:
        return AgentObservation(mapped_state=ControllerState.PLANNING, **common)
    if normalized == "waiting_for_user" and reason_normalized == "plan_review":
        return AgentObservation(
            mapped_state=ControllerState.PLAN_REVIEW_REQUIRED,
            awaiting_input=AwaitingInput.PLAN_APPROVAL,
            **common,
        )
    if normalized in {"running", "working", "executing"}:
        return AgentObservation(mapped_state=ControllerState.EXECUTING, **common)
    if normalized == "waiting_for_user":
        return AgentObservation(
            mapped_state=ControllerState.REVIEW_REQUIRED,
            awaiting_input=AwaitingInput.USER_FEEDBACK,
            **common,
        )
    if normalized in {"done", "completed"} and result_normalized in {"success", "succeeded"}:
        return AgentObservation(
            mapped_state=ControllerState.ARTIFACT_READY,
            terminal_claim=TerminalClaim.SUCCESS,
            **common,
        )
    if normalized in {"failed", "error"} or (
        normalized in {"done", "completed"}
        and result_normalized in {"failure", "failed", "error"}
    ):
        return AgentObservation(
            mapped_state=ControllerState.BLOCKED,
            terminal_claim=TerminalClaim.FAILURE,
            **common,
        )

    return _uncertain(
        provider="codex",
        provider_operation_id=provider_operation_id,
        raw_state=raw_state,
        observed_at=observed_at,
        provider_updated_at=provider_updated_at,
        reason="CODEX_STATE_UNKNOWN",
    )
