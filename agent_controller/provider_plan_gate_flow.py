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
    human_action: HumanPlanAction | None = None
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "operation": self.operation.to_dict() if self.operation is not None else None,
            "follow_result": (
                self.follow_result.to_dict() if self.follow_result is not None else None
            ),
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
    task: TaskBinding,
    operation: ProviderOperationRef,
    workstream_binding: WorkstreamBinding | None,
    follow_result: FollowResult,
) -> PlanGateFlowResult:
    if not _is_plan_gate(follow_result):
        return PlanGateFlowResult(
            status=PlanGateFlowStatus.FOLLOW_STOPPED,
            operation=operation,
            follow_result=follow_result,
        )

    final = follow_result.final_observation
    assert final is not None
    action = HumanPlanAction(
        workstream_id=(
            workstream_binding.workstream_id if workstream_binding is not None else None
        ),
        controller_task_id=task.controller_task_id,
        operation_id=task.operation_id,
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
    """Dispatch once, then follow the returned exact operation to the next stop.

    This composition never approves a provider plan. If plan review is required,
    it emits a bound human action and stops.
    """

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
    return _from_follow(
        task=task,
        operation=operation,
        workstream_binding=workstream_binding,
        follow_result=follow_result,
    )


def resume_plan_gate_flow(
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
) -> PlanGateFlowResult:
    """Re-read and follow the original operation after a human provider action.

    No caller-supplied "approved" flag exists. Provider state is re-read through
    the existing adapter, and this function never redispatches a replacement.
    """

    failure = _validate_pre_dispatch(
        task=task, workstream_binding=workstream_binding
    )
    if failure is not None:
        return PlanGateFlowResult(
            status=PlanGateFlowStatus.BINDING_INVALID,
            operation=(operation if isinstance(operation, ProviderOperationRef) else None),
            follow_result=None,
            failure_reason=failure,
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
    return _from_follow(
        task=task,
        operation=operation,
        workstream_binding=workstream_binding,
        follow_result=follow_result,
    )
