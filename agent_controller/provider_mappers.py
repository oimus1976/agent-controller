from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from agent_controller.provider_contract import (
    AgentObservation,
    AwaitingInput,
    ControllerState,
    TerminalClaim,
)


_EVIDENCE_KEYS = frozenset(
    {
        "status",
        "reason",
        "result",
        "updated_at",
        "plan_id",
        "artifact_id",
        "result_id",
        "task_id",
    }
)


def _string(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _evidence_projection(raw_state: Any) -> Any:
    """Retain only provider fields explicitly approved for normalized evidence.

    Arbitrary provider payload is intentionally not copied into normalized/audit
    evidence because credentials may appear under innocuous keys or inside URLs,
    headers, and free-form strings.
    """

    if not isinstance(raw_state, Mapping):
        return {"raw_type": type(raw_state).__name__}
    return {
        key: value
        for key, value in raw_state.items()
        if key in _EVIDENCE_KEYS and isinstance(value, (str, int, float, bool, type(None)))
    }


def _refs(raw_state: Mapping[str, Any], keys: Sequence[str]) -> tuple[str, ...]:
    refs = []
    for key in keys:
        value = _string(raw_state.get(key))
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
    """Map a Jules fixture payload into the provider-neutral observation model."""

    if not isinstance(raw_state, Mapping):
        return _uncertain(
            provider="jules",
            provider_operation_id=provider_operation_id,
            raw_state=raw_state,
            observed_at=observed_at,
            provider_updated_at=None,
            reason="JULES_RAW_STATE_NOT_MAPPING",
        )

    provider_updated_at = _string(raw_state.get("updated_at"))
    status = _string(raw_state.get("status"))
    if status is None:
        return _uncertain(
            provider="jules",
            provider_operation_id=provider_operation_id,
            raw_state=raw_state,
            observed_at=observed_at,
            provider_updated_at=provider_updated_at,
            reason="JULES_STATUS_MISSING",
        )

    normalized = status.upper()
    common = dict(
        provider="jules",
        provider_operation_id=provider_operation_id,
        observed_at=observed_at,
        provider_updated_at=provider_updated_at,
        provider_raw_state=_evidence_projection(raw_state),
        provider_refs=_refs(raw_state, ("plan_id", "artifact_id", "result_id")),
    )

    if normalized in {"PLANNING", "PLAN_GENERATING"}:
        return AgentObservation(mapped_state=ControllerState.PLANNING, **common)
    if normalized in {"AWAITING_PLAN_APPROVAL", "PLAN_REVIEW_REQUIRED"}:
        return AgentObservation(
            mapped_state=ControllerState.PLAN_REVIEW_REQUIRED,
            awaiting_input=AwaitingInput.PLAN_APPROVAL,
            **common,
        )
    if normalized in {"RUNNING", "EXECUTING", "WORKING"}:
        return AgentObservation(mapped_state=ControllerState.EXECUTING, **common)
    if normalized in {"AWAITING_USER", "NEEDS_USER_INPUT"}:
        return AgentObservation(
            mapped_state=ControllerState.REVIEW_REQUIRED,
            awaiting_input=AwaitingInput.USER_FEEDBACK,
            **common,
        )
    if normalized in {"COMPLETED", "SUCCEEDED"}:
        return AgentObservation(
            mapped_state=ControllerState.ARTIFACT_READY,
            terminal_claim=TerminalClaim.SUCCESS,
            **common,
        )
    if normalized in {"FAILED", "ERROR"}:
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
        reason=f"JULES_STATUS_UNKNOWN:{status}",
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

    provider_updated_at = _string(raw_state.get("updated_at"))
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
        reason=f"CODEX_STATE_UNKNOWN:{status}:{reason or ''}:{result or ''}",
    )
