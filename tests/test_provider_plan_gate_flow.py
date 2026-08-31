import inspect
import unittest

from agent_controller.provider_contract import (
    AgentObservation,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)
from agent_controller.provider_plan_gate_flow import (
    PlanGateCheckpoint,
    PlanGateFlowStatus,
    resume_plan_gate_flow,
    start_plan_gate_flow,
)
from agent_controller.workstream import WorkstreamBinding


def make_task(task_id="task-a", operation_id="op-a"):
    return TaskBinding(
        controller_task_id=task_id,
        operation_id=operation_id,
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="1" * 40,
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="IMPLEMENT",
        allowed_effects=("SESSION_CREATE",),
        forbidden_effects=("AUTO_CREATE_PR",),
        approval_policy_id="policy-1",
        created_at="2026-08-31T00:00:00Z",
    )


def make_operation(task, provider_operation_id="session-a"):
    return ProviderOperationRef(
        provider=task.provider,
        provider_operation_id=provider_operation_id,
        provider_url=f"https://jules.google.com/session/{provider_operation_id}",
        controller_task_id=task.controller_task_id,
        operation_id=task.operation_id,
    )


def make_workstream(task, workstream_id="lane-a"):
    return WorkstreamBinding(
        workstream_id=workstream_id,
        repo="oimus1976/agent-controller",
        root_work_item_ref="issue:127",
        task_ids=(task.controller_task_id,),
    )


def make_checkpoint(task=None, operation=None, lane=None):
    task = task or make_task()
    operation = operation or make_operation(task)
    lane = lane or make_workstream(task)
    return PlanGateCheckpoint(
        task=task,
        operation=operation,
        workstream_binding=lane,
        expected_provider=operation.provider,
        expected_provider_operation_id=operation.provider_operation_id,
        expected_workstream_id=lane.workstream_id,
    )


def obs(operation, state, awaiting=AwaitingInput.NONE, terminal=TerminalClaim.NONE):
    return AgentObservation(
        provider=operation.provider,
        provider_operation_id=operation.provider_operation_id,
        observed_at="2026-08-31T00:00:00Z",
        provider_updated_at=None,
        provider_raw_state={"state": state.value},
        mapped_state=state,
        awaiting_input=awaiting,
        terminal_claim=terminal,
    )


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class FakeAdapter:
    def __init__(self, operation, observations=None, observe_error=False):
        self.operation = operation
        self.observations = list(observations or [])
        self.last_observation = self.observations[-1] if self.observations else None
        self.observe_error = observe_error
        self.dispatch_calls = 0
        self.observe_calls = []

    def dispatch(self, task):
        self.dispatch_calls += 1
        return self.operation

    def observe(self, operation):
        self.observe_calls.append(operation.provider_operation_id)
        if self.observe_error:
            raise TimeoutError("provider read timed out")
        if self.observations:
            self.last_observation = self.observations.pop(0)
        if self.last_observation is None:
            raise RuntimeError("no observation")
        return self.last_observation

    def collect_artifacts(self, operation):
        return []


class ProviderPlanGateFlowTests(unittest.TestCase):
    def follow_kwargs(self, clock):
        return dict(
            max_elapsed_seconds=30.0,
            max_observations=5,
            poll_interval_seconds=1.0,
            clock=clock,
            sleeper=clock.sleep,
        )

    def test_dispatch_then_plan_gate_returns_exact_checkpoint_and_human_action_once(self):
        task = make_task()
        operation = make_operation(task)
        lane = make_workstream(task)
        adapter = FakeAdapter(
            operation,
            [
                obs(operation, ControllerState.PLANNING),
                obs(
                    operation,
                    ControllerState.PLAN_REVIEW_REQUIRED,
                    AwaitingInput.PLAN_APPROVAL,
                ),
            ],
        )
        clock = FakeClock()

        result = start_plan_gate_flow(
            task=task,
            adapter=adapter,
            workstream_binding=lane,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.HUMAN_PLAN_ACTION_REQUIRED)
        self.assertEqual(adapter.dispatch_calls, 1)
        self.assertEqual(adapter.observe_calls, ["session-a", "session-a"])
        self.assertIsNotNone(result.checkpoint)
        self.assertEqual(result.checkpoint.expected_provider_operation_id, "session-a")
        self.assertEqual(result.checkpoint.expected_workstream_id, "lane-a")
        self.assertEqual(result.checkpoint.operation, operation)
        self.assertIsNotNone(result.human_action)
        action = result.human_action
        self.assertEqual(action.workstream_id, "lane-a")
        self.assertEqual(action.controller_task_id, "task-a")
        self.assertEqual(action.operation_id, "op-a")
        self.assertEqual(action.provider_operation_id, "session-a")
        self.assertFalse(action.controller_approved_plan)
        self.assertIn("exact bound operation", action.to_dict()["operator_action"])

    def test_resume_same_checkpoint_after_provider_advances_reaches_handoff_without_dispatch(self):
        checkpoint = make_checkpoint()
        operation = checkpoint.operation
        adapter = FakeAdapter(
            operation,
            [
                obs(operation, ControllerState.EXECUTING),
                obs(operation, ControllerState.ARTIFACT_READY),
            ],
        )
        clock = FakeClock()

        result = resume_plan_gate_flow(
            checkpoint=checkpoint,
            adapter=adapter,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.FOLLOW_STOPPED)
        self.assertEqual(result.follow_result.outcome_state, ControllerState.ARTIFACT_READY)
        self.assertEqual(adapter.dispatch_calls, 0)
        self.assertEqual(adapter.observe_calls, ["session-a", "session-a"])
        self.assertEqual(result.checkpoint, checkpoint)

    def test_resume_while_still_waiting_returns_same_human_gate(self):
        checkpoint = make_checkpoint()
        operation = checkpoint.operation
        adapter = FakeAdapter(
            operation,
            [
                obs(
                    operation,
                    ControllerState.PLAN_REVIEW_REQUIRED,
                    AwaitingInput.PLAN_APPROVAL,
                )
            ],
        )
        clock = FakeClock()

        result = resume_plan_gate_flow(
            checkpoint=checkpoint,
            adapter=adapter,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.HUMAN_PLAN_ACTION_REQUIRED)
        self.assertEqual(result.human_action.provider_operation_id, "session-a")
        self.assertEqual(adapter.dispatch_calls, 0)
        self.assertEqual(adapter.observe_calls, ["session-a"])

    def test_changed_provider_operation_id_in_checkpoint_blocks_before_resumed_read(self):
        task = make_task()
        original = make_operation(task, "session-a")
        changed = make_operation(task, "session-b")
        lane = make_workstream(task)
        tampered = PlanGateCheckpoint(
            task=task,
            operation=changed,
            workstream_binding=lane,
            expected_provider="jules",
            expected_provider_operation_id=original.provider_operation_id,
            expected_workstream_id="lane-a",
        )
        adapter = FakeAdapter(original, [obs(original, ControllerState.EXECUTING)])
        clock = FakeClock()

        result = resume_plan_gate_flow(
            checkpoint=tampered,
            adapter=adapter,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.BINDING_INVALID)
        self.assertEqual(result.failure_reason, "CHECKPOINT_PROVIDER_OPERATION_CHANGED")
        self.assertEqual(adapter.dispatch_calls, 0)
        self.assertEqual(adapter.observe_calls, [])

    def test_changed_workstream_in_checkpoint_blocks_before_resumed_read(self):
        task = make_task()
        operation = make_operation(task)
        lane_b = WorkstreamBinding(
            workstream_id="lane-b",
            repo="oimus1976/agent-controller",
            root_work_item_ref="issue:999",
            task_ids=(task.controller_task_id,),
        )
        tampered = PlanGateCheckpoint(
            task=task,
            operation=operation,
            workstream_binding=lane_b,
            expected_provider="jules",
            expected_provider_operation_id="session-a",
            expected_workstream_id="lane-a",
        )
        adapter = FakeAdapter(operation, [obs(operation, ControllerState.EXECUTING)])
        clock = FakeClock()

        result = resume_plan_gate_flow(
            checkpoint=tampered,
            adapter=adapter,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.BINDING_INVALID)
        self.assertEqual(result.failure_reason, "CHECKPOINT_WORKSTREAM_CHANGED")
        self.assertEqual(adapter.observe_calls, [])
        self.assertEqual(adapter.dispatch_calls, 0)

    def test_no_human_approved_or_replacement_operation_parameter_can_promote_resume(self):
        params = inspect.signature(resume_plan_gate_flow).parameters
        self.assertNotIn("approved", params)
        self.assertNotIn("human_approved", params)
        self.assertNotIn("approval", params)
        self.assertNotIn("operation", params)
        self.assertNotIn("task", params)
        self.assertNotIn("workstream_binding", params)
        self.assertIn("checkpoint", params)

    def test_same_repo_concurrent_lanes_do_not_cross_resume(self):
        task_a = make_task("task-a", "op-a")
        task_b = make_task("task-b", "op-b")
        operation_a = make_operation(task_a, "session-a")
        operation_b = make_operation(task_b, "session-b")
        lane_a = make_workstream(task_a, "lane-a")
        lane_b = make_workstream(task_b, "lane-b")
        checkpoint_a = make_checkpoint(task_a, operation_a, lane_a)
        checkpoint_b = make_checkpoint(task_b, operation_b, lane_b)
        adapter_a = FakeAdapter(operation_a, [obs(operation_a, ControllerState.ARTIFACT_READY)])
        clock = FakeClock()

        result = resume_plan_gate_flow(
            checkpoint=checkpoint_a,
            adapter=adapter_a,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.FOLLOW_STOPPED)
        self.assertEqual(adapter_a.observe_calls, ["session-a"])
        self.assertEqual(result.checkpoint.expected_provider_operation_id, "session-a")
        self.assertEqual(checkpoint_b.expected_provider_operation_id, "session-b")
        self.assertNotEqual(result.checkpoint.expected_workstream_id, checkpoint_b.expected_workstream_id)

    def test_provider_read_error_after_human_action_is_uncertain_without_redispatch(self):
        checkpoint = make_checkpoint()
        adapter = FakeAdapter(checkpoint.operation, observe_error=True)
        clock = FakeClock()

        result = resume_plan_gate_flow(
            checkpoint=checkpoint,
            adapter=adapter,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.FOLLOW_STOPPED)
        self.assertEqual(result.follow_result.outcome_state, ControllerState.UNCERTAIN)
        self.assertEqual(adapter.dispatch_calls, 0)
        self.assertEqual(adapter.observe_calls, ["session-a"])

    def test_non_plan_stop_never_fabricates_plan_gate(self):
        task = make_task()
        operation = make_operation(task)
        lane = make_workstream(task)
        adapter = FakeAdapter(
            operation,
            [obs(operation, ControllerState.BLOCKED, terminal=TerminalClaim.FAILURE)],
        )
        clock = FakeClock()

        result = start_plan_gate_flow(
            task=task,
            adapter=adapter,
            workstream_binding=lane,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.FOLLOW_STOPPED)
        self.assertIsNone(result.human_action)
        self.assertEqual(adapter.dispatch_calls, 1)
        self.assertEqual(result.checkpoint.expected_provider_operation_id, "session-a")

    def test_wrong_lane_blocks_before_initial_dispatch(self):
        task = make_task()
        operation = make_operation(task)
        wrong_lane = WorkstreamBinding(
            workstream_id="lane-b",
            repo="oimus1976/agent-controller",
            root_work_item_ref="issue:999",
            task_ids=("task-b",),
        )
        adapter = FakeAdapter(operation, [obs(operation, ControllerState.PLANNING)])
        clock = FakeClock()

        result = start_plan_gate_flow(
            task=task,
            adapter=adapter,
            workstream_binding=wrong_lane,
            **self.follow_kwargs(clock),
        )

        self.assertEqual(result.status, PlanGateFlowStatus.BINDING_INVALID)
        self.assertEqual(adapter.dispatch_calls, 0)
        self.assertEqual(adapter.observe_calls, [])


if __name__ == "__main__":
    unittest.main()
