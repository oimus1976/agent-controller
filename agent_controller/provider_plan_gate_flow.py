from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from time import monotonic, sleep
from typing import Callable

from agent_controller.binding_validator import validate_operation_binding
from agent_controller.operation_follow import (
    FollowResult,
    FollowStopReason,
    follow_bound_operation,
)
from agent_controller.provider_contract import (
    AgentAdapter,
    AwaitingInput,
    ControllerState,
    ProviderOperationRef,
    TaskBinding,
)
from agent_controller.workstream import (
    WorkstreamBinding,
    validate_operation_workstream,
    validate_task_workstream,
)


class PlanGateFlowStatus(str, Enum):
    HUMAN_PLAN_ACTION_REQUIRED = "HUMAN_PLAN_ACTION_REQUIRED"
    FOLLOW_STOPPED = "FOLLOW_STOPPED"
    DISPATCH_FAILED = "DISPATCH_FAILED"
    BINDING_INVALID = "BINDING_INVALID"


@dataclass(frozen=True)
class PlanGateCheckpoint:
    """Controller-owned exact identity that may be resumed after a human plan action."""

    task: TaskBinding
    operation: ProviderOperationRef
    workstream_binding: WorkstreamBinding | None
    expected_provider: str
    expected_provider_operation_id: str
    expected_workstream_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "task": self.task.to_dict(),
            "operation": self.operation.to_dict(),
            "workstream_binding": (
                self.workstream_binding.to_dict()
                if self.workstream_binding is not None
                else None
            ),
            "expected_provider": self.expected_provider,
            "expected_provider_operation_id": self.expected_provider_operation_id,
            "expected_workstream_id": self.expected_workstream_id,
        }


@dataclass(frozen=True)
class HumanPlanAction:
    workstream_id: str | None
    controller_task_id: str
    operation_id: str
    provider: str
    provider_operation_id: str
    provider_url: str | None
    mapped_state: ControllerState
    awaiting_input: AwaitingInput
    controller_approved_plan: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "workstream_id": self.workstream_id,
            "controller_task_id": self.controller_task_id,
            "operation_id": self.operation_id,
            "provider": self.provider,
            "provider_operation_id": self.provider_operation_id,
            "provider_url": self.provider_url,
            "mapped_state": self.mapped_state.value,
            "awaiting_input": self.awaiting_input.value,
            "controller_approved_plan": self.controller_approved_plan,
            "operator_action": "Inspect and approve or reject the plan in the provider UI for this exact bound operation.",
        }


@dataclass(frozen=True)
class PlanGateFlowResult:
    status: PlanGateFlowStatus
    operation: ProviderOperationRef | None
    follow_result: FollowResult | None
    checkpoint: PlanGateCheckpoint | None = None
    human_action: HumanPlanAction | None = None
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "operation": self.operation.to_dict() if self.operation is not None else None,
            "follow_result": (
                self.follow_result.to_dict() if self.follow_result is not None else None
            ),
            "checkpoint": self.checkpoint.to_dict() if self.checkpoint is not None else None,
            "human_action": (
                self.human_action.to_dict() if self.human_action is not None else None
            ),
            "failure_reason": self.failure_reason,
        }


def _validate_pre_dispatch(
    *, task: object, workstream_binding: object
) -> str | None:
    if not isinstance(task, TaskBinding):
        return "TASK_BINDING_MALFORMED"
    if workstream_binding is not None and not isinstance(
        workstream_binding, WorkstreamBinding
    ):
        return "WORKSTREAM_BINDING_MALFORMED"
    if workstream_binding is not None:
        task_lane = validate_task_workstream(binding=workstream_binding, task=task)
        if not task_lane.valid:
            return task_lane.reason or "TASK_WORKSTREAM_INVALID"
    return None


def _validate_operation(
    *,
    task: TaskBinding,
    operation: object,
    workstream_binding: WorkstreamBinding | None,
) -> str | None:
    if not isinstance(operation, ProviderOperationRef):
        return "OPERATION_BINDING_MALFORMED"
    binding = validate_operation_binding(task=task, operation=operation)
    if not binding.valid:
        return binding.reason or "OPERATION_BINDING_INVALID"
    if workstream_binding is not None:
        operation_lane = validate_operation_workstream(
            binding=workstream_binding, operation=operation
        )
        if not operation_lane.valid:
            return operation_lane.reason or "OPERATION_WORKSTREAM_INVALID"
    return None


def _checkpoint(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    workstream_binding: WorkstreamBinding | None,
) -> PlanGateCheckpoint:
    return PlanGateCheckpoint(
        task=task,
        operation=operation,
        workstream_binding=workstream_binding,
        expected_provider=operation.provider,
        expected_provider_operation_id=operation.provider_operation_id,
        expected_workstream_id=(
            workstream_binding.workstream_id if workstream_binding is not None else None
        ),
    )


def _validate_checkpoint(checkpoint: object) -> str | None:
    if not isinstance(checkpoint, PlanGateCheckpoint):
        return "PLAN_GATE_CHECKPOINT_MALFORMED"
    if not isinstance(checkpoint.task, TaskBinding):
        return "CHECKPOINT_TASK_MALFORMED"
    if not isinstance(checkpoint.operation, ProviderOperationRef):
        return "CHECKPOINT_OPERATION_MALFORMED"
    if checkpoint.workstream_binding is not None and not isinstance(
        checkpoint.workstream_binding, WorkstreamBinding
    ):
        return "CHECKPOINT_WORKSTREAM_MALFORMED"

    operation = checkpoint.operation
    if operation.provider != checkpoint.expected_provider:
        return "CHECKPOINT_PROVIDER_CHANGED"
    if operation.provider_operation_id != checkpoint.expected_provider_operation_id:
        return "CHECKPOINT_PROVIDER_OPERATION_CHANGED"

    actual_workstream_id = (
        checkpoint.workstream_binding.workstream_id
        if checkpoint.workstream_binding is not None
        else None
    )
    if actual_workstream_id != checkpoint.expected_workstream_id:
        return "CHECKPOINT_WORKSTREAM_CHANGED"

    pre = _validate_pre_dispatch(
        task=checkpoint.task,
        workstream_binding=checkpoint.workstream_binding,
    )
    if pre is not None:
        return pre
    return _validate_operation(
        task=checkpoint.task,
        operation=operation,
        workstream_binding=checkpoint.workstream_binding,
    )


def _is_plan_gate(follow_result: FollowResult) -> bool:
    final = follow_result.final_observation
    if final is None:
        return False
    if follow_result.stop_reason is not FollowStopReason.ATTENTION_REQUIRED:
        return False
    return (
        final.awaiting_input is AwaitingInput.PLAN_APPROVAL
        or final.mapped_state is ControllerState.PLAN_REVIEW_REQUIRED
    )


def _from_follow(
    *,
    checkpoint: PlanGateCheckpoint,
    follow_result: FollowResult,
) -> PlanGateFlowResult:
    operation = checkpoint.operation
    if not _is_plan_gate(follow_result):
        return PlanGateFlowResult(
            status=PlanGateFlowStatus.FOLLOW_STOPPED,
            operation=operation,
            follow_result=follow_result,
            checkpoint=checkpoint,
        )

    final = follow_result.final_observation
    assert final is not None
    action = HumanPlanAction(
        workstream_id=checkpoint.expected_workstream_id,
        controller_task_id=checkpoint.task.controller_task_id,
        operation_id=checkpoint.task.operation_id,
        provider=operation.provider,
        provider_operation_id=operation.provider_operation_id,
        provider_url=operation.provider_url,
        mapped_state=final.mapped_state,
        awaiting_input=final.awaiting_input,
    )
    return PlanGateFlowResult(
        status=PlanGateFlowStatus.HUMAN_PLAN_ACTION_REQUIRED,
        operation=operation,
        follow_result=follow_result,
        checkpoint=checkpoint,
        human_action=action,
    )


def start_plan_gate_flow(
    *,
    task: TaskBinding,
    adapter: AgentAdapter,
    max_elapsed_seconds: float,
    max_observations: int,
    poll_interval_seconds: float,
    workstream_binding: WorkstreamBinding | None = None,
    clock: Callable[[], float] = monotonic,
    sleeper: Callable[[float], None] = sleep,
) -> PlanGateFlowResult:
    """Dispatch once, freeze that exact operation, then follow to the next stop."""

    failure = _validate_pre_dispatch(
        task=task, workstream_binding=workstream_binding
    )
    if failure is not None:
        return PlanGateFlowResult(
            status=PlanGateFlowStatus.BINDING_INVALID,
            operation=None,
            follow_result=None,
            failure_reason=failure,
        )

    try:
        operation = adapter.dispatch(task)
    except Exception:
        return PlanGateFlowResult(
            status=PlanGateFlowStatus.DISPATCH_FAILED,
            operation=None,
            follow_result=None,
            failure_reason="PROVIDER_DISPATCH_FAILED",
        )

    operation_failure = _validate_operation(
        task=task,
        operation=operation,
        workstream_binding=workstream_binding,
    )
    if operation_failure is not None:
        return PlanGateFlowResult(
            status=PlanGateFlowStatus.BINDING_INVALID,
            operation=(operation if isinstance(operation, ProviderOperationRef) else None),
            follow_result=None,
            failure_reason=operation_failure,
        )

    assert isinstance(operation, ProviderOperationRef)
    checkpoint = _checkpoint(
        task=task,
        operation=operation,
        workstream_binding=workstream_binding,
    )
    follow_result = follow_bound_operation(
        task=task,
        operation=operation,
        adapter=adapter,
        max_elapsed_seconds=max_elapsed_seconds,
        max_observations=max_observations,
        poll_interval_seconds=poll_interval_seconds,
        workstream_binding=workstream_binding,
        clock=clock,
        sleeper=sleeper,
    )
    return _from_follow(checkpoint=checkpoint, follow_result=follow_result)


def resume_plan_gate_flow(
    *,
    checkpoint: PlanGateCheckpoint,
    adapter: AgentAdapter,
    max_elapsed_seconds: float,
    max_observations: int,
    poll_interval_seconds: float,
    clock: Callable[[], float] = monotonic,
    sleeper: Callable[[float], None] = sleep,
) -> PlanGateFlowResult:
    """Re-read and follow the exact operation frozen before the human gate.

    No caller-supplied "approved" flag or replacement operation exists. Provider
    state is re-read through the existing adapter, and resume never dispatches.
    """

    failure = _validate_checkpoint(checkpoint)
    if failure is not None:
        return PlanGateFlowResult(
            status=PlanGateFlowStatus.BINDING_INVALID,
            operation=(
                checkpoint.operation
                if isinstance(checkpoint, PlanGateCheckpoint)
                and isinstance(checkpoint.operation, ProviderOperationRef)
                else None
            ),
            follow_result=None,
            checkpoint=(checkpoint if isinstance(checkpoint, PlanGateCheckpoint) else None),
            failure_reason=failure,
        )

    assert isinstance(checkpoint, PlanGateCheckpoint)
    follow_result = follow_bound_operation(
        task=checkpoint.task,
        operation=checkpoint.operation,
        adapter=adapter,
        max_elapsed_seconds=max_elapsed_seconds,
        max_observations=max_observations,
        poll_interval_seconds=poll_interval_seconds,
        workstream_binding=checkpoint.workstream_binding,
        clock=clock,
        sleeper=sleeper,
    )
    return _from_follow(checkpoint=checkpoint, follow_result=follow_result)
