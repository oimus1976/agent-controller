from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from math import isfinite
from time import monotonic, sleep
from typing import Callable

from agent_controller.binding_validator import (
    validate_observation_binding,
    validate_operation_binding,
)
from agent_controller.provider_contract import (
    AgentAdapter,
    AgentObservation,
    AwaitingInput,
    ControllerState,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)
from agent_controller.workstream import (
    WorkstreamBinding,
    validate_operation_workstream,
    validate_task_workstream,
)


class FollowStopReason(str, Enum):
    ATTENTION_REQUIRED = "ATTENTION_REQUIRED"
    HANDOFF_READY = "HANDOFF_READY"
    TERMINAL_CLAIM = "TERMINAL_CLAIM"
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"
    MAX_ELAPSED = "MAX_ELAPSED"
    MAX_OBSERVATIONS = "MAX_OBSERVATIONS"
    PROVIDER_READ_ERROR = "PROVIDER_READ_ERROR"
    BINDING_INVALID = "BINDING_INVALID"
    OBSERVATION_INVALID = "OBSERVATION_INVALID"


@dataclass(frozen=True)
class FollowTransition:
    observation_number: int
    mapped_state: ControllerState
    awaiting_input: AwaitingInput
    terminal_claim: TerminalClaim

    def to_dict(self) -> dict[str, object]:
        return {
            "observation_number": self.observation_number,
            "mapped_state": self.mapped_state.value,
            "awaiting_input": self.awaiting_input.value,
            "terminal_claim": self.terminal_claim.value,
        }


@dataclass(frozen=True)
class FollowResult:
    controller_task_id: str | None
    operation_id: str | None
    provider: str | None
    provider_operation_id: str | None
    workstream_id: str | None
    stop_reason: FollowStopReason
    outcome_state: ControllerState
    observation_count: int
    elapsed_seconds: float
    first_observation: AgentObservation | None
    final_observation: AgentObservation | None
    transitions: tuple[FollowTransition, ...] = ()
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "controller_task_id": self.controller_task_id,
            "operation_id": self.operation_id,
            "provider": self.provider,
            "provider_operation_id": self.provider_operation_id,
            "workstream_id": self.workstream_id,
            "stop_reason": self.stop_reason.value,
            "outcome_state": self.outcome_state.value,
            "observation_count": self.observation_count,
            "elapsed_seconds": self.elapsed_seconds,
            "first_observation": (
                self.first_observation.to_dict() if self.first_observation is not None else None
            ),
            "final_observation": (
                self.final_observation.to_dict() if self.final_observation is not None else None
            ),
            "transitions": [transition.to_dict() for transition in self.transitions],
            "failure_reason": self.failure_reason,
        }


def _validate_bounds(
    *, max_elapsed_seconds: float, max_observations: int, poll_interval_seconds: float
) -> None:
    if isinstance(max_elapsed_seconds, bool) or not isinstance(max_elapsed_seconds, (int, float)):
        raise TypeError("max_elapsed_seconds must be numeric")
    if not isfinite(float(max_elapsed_seconds)) or max_elapsed_seconds <= 0:
        raise ValueError("max_elapsed_seconds must be positive and finite")
    if isinstance(max_observations, bool) or not isinstance(max_observations, int):
        raise TypeError("max_observations must be an integer")
    if max_observations <= 0:
        raise ValueError("max_observations must be positive")
    if isinstance(poll_interval_seconds, bool) or not isinstance(
        poll_interval_seconds, (int, float)
    ):
        raise TypeError("poll_interval_seconds must be numeric")
    if not isfinite(float(poll_interval_seconds)) or poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be positive and finite")


def _clock_value(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("CLOCK_MALFORMED")
    value = float(value)
    if not isfinite(value):
        raise ValueError("CLOCK_MALFORMED")
    return value


def _observation_shape_valid(observation: object) -> bool:
    return (
        isinstance(observation, AgentObservation)
        and isinstance(observation.mapped_state, ControllerState)
        and isinstance(observation.awaiting_input, AwaitingInput)
        and isinstance(observation.terminal_claim, TerminalClaim)
    )


def _transition_signature(
    observation: AgentObservation,
) -> tuple[ControllerState, AwaitingInput, TerminalClaim]:
    return (
        observation.mapped_state,
        observation.awaiting_input,
        observation.terminal_claim,
    )


def _stop_for_observation(
    observation: AgentObservation,
) -> tuple[FollowStopReason, ControllerState] | None:
    if observation.awaiting_input is not AwaitingInput.NONE:
        return FollowStopReason.ATTENTION_REQUIRED, observation.mapped_state
    if observation.terminal_claim is not TerminalClaim.NONE:
        return FollowStopReason.TERMINAL_CLAIM, observation.mapped_state
    if observation.mapped_state is ControllerState.BLOCKED:
        return FollowStopReason.BLOCKED, ControllerState.BLOCKED
    if observation.mapped_state is ControllerState.UNCERTAIN:
        return FollowStopReason.UNCERTAIN, ControllerState.UNCERTAIN
    if observation.mapped_state is ControllerState.PLAN_REVIEW_REQUIRED:
        return FollowStopReason.ATTENTION_REQUIRED, observation.mapped_state
    if observation.mapped_state in {
        ControllerState.ARTIFACT_READY,
        ControllerState.REVIEW_REQUIRED,
        ControllerState.REVIEW_READY,
    }:
        return FollowStopReason.HANDOFF_READY, observation.mapped_state
    return None


def _result(
    *,
    task: object,
    operation: object,
    workstream_binding: object,
    stop_reason: FollowStopReason,
    outcome_state: ControllerState,
    observation_count: int = 0,
    elapsed_seconds: float = 0.0,
    first_observation: AgentObservation | None = None,
    final_observation: AgentObservation | None = None,
    transitions: tuple[FollowTransition, ...] = (),
    failure_reason: str | None = None,
) -> FollowResult:
    return FollowResult(
        controller_task_id=(
            task.controller_task_id if isinstance(task, TaskBinding) else None
        ),
        operation_id=(task.operation_id if isinstance(task, TaskBinding) else None),
        provider=(operation.provider if isinstance(operation, ProviderOperationRef) else None),
        provider_operation_id=(
            operation.provider_operation_id
            if isinstance(operation, ProviderOperationRef)
            else None
        ),
        workstream_id=(
            workstream_binding.workstream_id
            if isinstance(workstream_binding, WorkstreamBinding)
            else None
        ),
        stop_reason=stop_reason,
        outcome_state=outcome_state,
        observation_count=observation_count,
        elapsed_seconds=max(0.0, float(elapsed_seconds)),
        first_observation=first_observation,
        final_observation=final_observation,
        transitions=transitions,
        failure_reason=failure_reason,
    )


def follow_bound_operation(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    adapter: AgentAdapter,
    max_elapsed_seconds: float,
    max_observations: int,
    poll_interval_seconds: float,
    workstream_binding: WorkstreamBinding | None = None,
    clock: Callable[[], float] = monotonic,
    sleeper: Callable[[float], None] = sleep,
) -> FollowResult:
    """Follow one exact provider operation until a provider-neutral stop boundary.

    This function is read-only. It never approves plans, sends provider messages,
    retries/cancels provider work, mutates GitHub, or changes human-final gates.
    """

    _validate_bounds(
        max_elapsed_seconds=max_elapsed_seconds,
        max_observations=max_observations,
        poll_interval_seconds=poll_interval_seconds,
    )

    if not isinstance(task, TaskBinding):
        return _result(
            task=task,
            operation=operation,
            workstream_binding=workstream_binding,
            stop_reason=FollowStopReason.BINDING_INVALID,
            outcome_state=ControllerState.BLOCKED,
            failure_reason="TASK_BINDING_MALFORMED",
        )
    if not isinstance(operation, ProviderOperationRef):
        return _result(
            task=task,
            operation=operation,
            workstream_binding=workstream_binding,
            stop_reason=FollowStopReason.BINDING_INVALID,
            outcome_state=ControllerState.BLOCKED,
            failure_reason="OPERATION_BINDING_MALFORMED",
        )
    if workstream_binding is not None and not isinstance(
        workstream_binding, WorkstreamBinding
    ):
        return _result(
            task=task,
            operation=operation,
            workstream_binding=workstream_binding,
            stop_reason=FollowStopReason.BINDING_INVALID,
            outcome_state=ControllerState.BLOCKED,
            failure_reason="WORKSTREAM_BINDING_MALFORMED",
        )

    operation_binding = validate_operation_binding(task=task, operation=operation)
    if not operation_binding.valid:
        return _result(
            task=task,
            operation=operation,
            workstream_binding=workstream_binding,
            stop_reason=FollowStopReason.BINDING_INVALID,
            outcome_state=ControllerState.BLOCKED,
            failure_reason=operation_binding.reason,
        )

    if workstream_binding is not None:
        task_lane = validate_task_workstream(binding=workstream_binding, task=task)
        if not task_lane.valid:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.BINDING_INVALID,
                outcome_state=ControllerState.BLOCKED,
                failure_reason=task_lane.reason,
            )
        operation_lane = validate_operation_workstream(
            binding=workstream_binding, operation=operation
        )
        if not operation_lane.valid:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.BINDING_INVALID,
                outcome_state=ControllerState.BLOCKED,
                failure_reason=operation_lane.reason,
            )

    try:
        started_at = _clock_value(clock)
    except Exception as exc:
        return _result(
            task=task,
            operation=operation,
            workstream_binding=workstream_binding,
            stop_reason=FollowStopReason.UNCERTAIN,
            outcome_state=ControllerState.UNCERTAIN,
            failure_reason=(
                str(exc) if str(exc) == "CLOCK_MALFORMED" else "CLOCK_READ_FAILED"
            ),
        )

    first: AgentObservation | None = None
    final: AgentObservation | None = None
    transitions: list[FollowTransition] = []
    previous_signature: tuple[ControllerState, AwaitingInput, TerminalClaim] | None = None
    count = 0
    elapsed = 0.0

    while True:
        if count > 0:
            try:
                now = _clock_value(clock)
            except Exception as exc:
                return _result(
                    task=task,
                    operation=operation,
                    workstream_binding=workstream_binding,
                    stop_reason=FollowStopReason.UNCERTAIN,
                    outcome_state=ControllerState.UNCERTAIN,
                    observation_count=count,
                    elapsed_seconds=elapsed,
                    first_observation=first,
                    final_observation=final,
                    transitions=tuple(transitions),
                    failure_reason=(
                        str(exc)
                        if str(exc) == "CLOCK_MALFORMED"
                        else "CLOCK_READ_FAILED"
                    ),
                )
            elapsed = now - started_at
            if elapsed < 0:
                return _result(
                    task=task,
                    operation=operation,
                    workstream_binding=workstream_binding,
                    stop_reason=FollowStopReason.UNCERTAIN,
                    outcome_state=ControllerState.UNCERTAIN,
                    observation_count=count,
                    first_observation=first,
                    final_observation=final,
                    transitions=tuple(transitions),
                    failure_reason="MONOTONIC_CLOCK_REVERSED",
                )
            if elapsed >= max_elapsed_seconds:
                return _result(
                    task=task,
                    operation=operation,
                    workstream_binding=workstream_binding,
                    stop_reason=FollowStopReason.MAX_ELAPSED,
                    outcome_state=(
                        final.mapped_state if final is not None else ControllerState.UNCERTAIN
                    ),
                    observation_count=count,
                    elapsed_seconds=elapsed,
                    first_observation=first,
                    final_observation=final,
                    transitions=tuple(transitions),
                )

        try:
            observation = adapter.observe(operation)
        except Exception:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.PROVIDER_READ_ERROR,
                outcome_state=ControllerState.UNCERTAIN,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
                failure_reason="PROVIDER_OBSERVE_FAILED",
            )

        if not _observation_shape_valid(observation):
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.OBSERVATION_INVALID,
                outcome_state=ControllerState.UNCERTAIN,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
                failure_reason="OBSERVATION_MALFORMED",
            )

        evidence_binding = validate_observation_binding(
            operation=operation, observation=observation
        )
        if not evidence_binding.valid:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.OBSERVATION_INVALID,
                outcome_state=ControllerState.BLOCKED,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
                failure_reason=evidence_binding.reason,
            )

        count += 1
        if first is None:
            first = observation
        final = observation

        signature = _transition_signature(observation)
        if previous_signature is None:
            previous_signature = signature
        elif signature != previous_signature:
            transitions.append(
                FollowTransition(
                    observation_number=count,
                    mapped_state=observation.mapped_state,
                    awaiting_input=observation.awaiting_input,
                    terminal_claim=observation.terminal_claim,
                )
            )
            previous_signature = signature

        stop = _stop_for_observation(observation)
        if stop is not None:
            stop_reason, outcome_state = stop
            try:
                elapsed_after_read = _clock_value(clock) - started_at
                if elapsed_after_read >= 0:
                    elapsed = elapsed_after_read
            except Exception:
                pass
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=stop_reason,
                outcome_state=outcome_state,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
            )

        try:
            elapsed_after_read = _clock_value(clock) - started_at
        except Exception as exc:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.UNCERTAIN,
                outcome_state=ControllerState.UNCERTAIN,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
                failure_reason=(
                    str(exc) if str(exc) == "CLOCK_MALFORMED" else "CLOCK_READ_FAILED"
                ),
            )
        if elapsed_after_read < 0:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.UNCERTAIN,
                outcome_state=ControllerState.UNCERTAIN,
                observation_count=count,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
                failure_reason="MONOTONIC_CLOCK_REVERSED",
            )
        elapsed = elapsed_after_read

        if elapsed >= max_elapsed_seconds:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.MAX_ELAPSED,
                outcome_state=observation.mapped_state,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
            )

        if count >= max_observations:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.MAX_OBSERVATIONS,
                outcome_state=observation.mapped_state,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
            )

        sleep_for = min(float(poll_interval_seconds), max_elapsed_seconds - elapsed)
        try:
            sleeper(sleep_for)
        except Exception:
            return _result(
                task=task,
                operation=operation,
                workstream_binding=workstream_binding,
                stop_reason=FollowStopReason.UNCERTAIN,
                outcome_state=ControllerState.UNCERTAIN,
                observation_count=count,
                elapsed_seconds=elapsed,
                first_observation=first,
                final_observation=final,
                transitions=tuple(transitions),
                failure_reason="SLEEP_FAILED",
            )
