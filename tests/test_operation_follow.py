from __future__ import annotations

import unittest

from agent_controller.operation_follow import FollowStopReason, follow_bound_operation
from agent_controller.provider_contract import (
    AgentObservation,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)
from agent_controller.workstream import WorkstreamBinding


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class FakeAdapter:
    def __init__(self, observations, *, error_at=None):
        self.observations = list(observations)
        self.error_at = error_at
        self.observe_calls = 0

    def dispatch(self, task):
        raise AssertionError("dispatch must not be called by follow")

    def collect_artifacts(self, operation):
        raise AssertionError("collect_artifacts must not be called by follow")

    def observe(self, operation):
        self.observe_calls += 1
        if self.error_at == self.observe_calls:
            raise RuntimeError("provider unavailable")
        if not self.observations:
            raise AssertionError("unexpected extra observe call")
        return self.observations.pop(0)


def make_task(*, provider="jules", task_id="task-1", operation_id="op-1"):
    return TaskBinding(
        controller_task_id=task_id,
        operation_id=operation_id,
        provider=provider,
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/feature",
        expected_start_sha="a" * 40,
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="IMPLEMENT",
        allowed_effects=(),
        forbidden_effects=("MERGE", "READY"),
        approval_policy_id="policy-1",
        created_at="2026-08-31T00:00:00Z",
    )


def make_operation(*, provider="jules", task_id="task-1", operation_id="op-1"):
    return ProviderOperationRef(
        provider=provider,
        provider_operation_id="provider-op-1",
        provider_url=None,
        controller_task_id=task_id,
        operation_id=operation_id,
    )


def observation(
    state,
    *,
    provider="jules",
    provider_operation_id="provider-op-1",
    awaiting=AwaitingInput.NONE,
    terminal=TerminalClaim.NONE,
):
    return AgentObservation(
        provider=provider,
        provider_operation_id=provider_operation_id,
        observed_at="2026-08-31T00:00:00Z",
        provider_updated_at=None,
        provider_raw_state={"opaque": True},
        mapped_state=state,
        awaiting_input=awaiting,
        terminal_claim=terminal,
    )


class OperationFollowTests(unittest.TestCase):
    def run_follow(self, observations, **kwargs):
        task = kwargs.pop("task", make_task())
        operation = kwargs.pop("operation", make_operation())
        adapter = kwargs.pop("adapter", FakeAdapter(observations))
        clock = kwargs.pop("clock", FakeClock())
        result = follow_bound_operation(
            task=task,
            operation=operation,
            adapter=adapter,
            max_elapsed_seconds=kwargs.pop("max_elapsed_seconds", 30),
            max_observations=kwargs.pop("max_observations", 10),
            poll_interval_seconds=kwargs.pop("poll_interval_seconds", 1),
            workstream_binding=kwargs.pop("workstream_binding", None),
            clock=clock.now,
            sleeper=clock.sleep,
            **kwargs,
        )
        return result, adapter, clock

    def test_planning_to_executing_to_artifact_ready_stops_at_handoff(self):
        result, adapter, clock = self.run_follow(
            [
                observation(ControllerState.PLANNING),
                observation(ControllerState.EXECUTING),
                observation(ControllerState.ARTIFACT_READY),
            ]
        )
        self.assertEqual(FollowStopReason.HANDOFF_READY, result.stop_reason)
        self.assertEqual(ControllerState.ARTIFACT_READY, result.outcome_state)
        self.assertEqual(3, result.observation_count)
        self.assertEqual(3, adapter.observe_calls)
        self.assertEqual([1, 1], clock.sleeps)
        self.assertEqual(2, len(result.transitions))
        self.assertEqual(ControllerState.EXECUTING, result.transitions[0].mapped_state)
        self.assertEqual(ControllerState.ARTIFACT_READY, result.transitions[1].mapped_state)

    def test_plan_review_required_stops_for_human_without_effect(self):
        result, adapter, _ = self.run_follow(
            [
                observation(ControllerState.PLANNING),
                observation(
                    ControllerState.PLAN_REVIEW_REQUIRED,
                    awaiting=AwaitingInput.PLAN_APPROVAL,
                ),
            ]
        )
        self.assertEqual(FollowStopReason.ATTENTION_REQUIRED, result.stop_reason)
        self.assertEqual(AwaitingInput.PLAN_APPROVAL, result.final_observation.awaiting_input)
        self.assertEqual(2, adapter.observe_calls)

    def test_plan_review_state_alone_is_also_attention_stop(self):
        result, _, _ = self.run_follow(
            [observation(ControllerState.PLAN_REVIEW_REQUIRED)]
        )
        self.assertEqual(FollowStopReason.ATTENTION_REQUIRED, result.stop_reason)

    def test_unchanged_running_observations_stop_at_max_observations_compactly(self):
        result, adapter, _ = self.run_follow(
            [observation(ControllerState.EXECUTING) for _ in range(4)],
            max_observations=4,
        )
        self.assertEqual(FollowStopReason.MAX_OBSERVATIONS, result.stop_reason)
        self.assertEqual(4, adapter.observe_calls)
        self.assertEqual(0, len(result.transitions))
        self.assertIsNotNone(result.first_observation)
        self.assertIsNotNone(result.final_observation)

    def test_elapsed_bound_stops_without_extra_provider_read(self):
        result, adapter, clock = self.run_follow(
            [observation(ControllerState.EXECUTING) for _ in range(5)],
            max_elapsed_seconds=2,
            max_observations=10,
            poll_interval_seconds=1,
        )
        self.assertEqual(FollowStopReason.MAX_ELAPSED, result.stop_reason)
        self.assertEqual(2, adapter.observe_calls)
        self.assertEqual(2.0, result.elapsed_seconds)
        self.assertEqual([1, 1], clock.sleeps)

    def test_terminal_failure_claim_stops_explicitly(self):
        result, _, _ = self.run_follow(
            [
                observation(
                    ControllerState.BLOCKED,
                    terminal=TerminalClaim.FAILURE,
                )
            ]
        )
        self.assertEqual(FollowStopReason.TERMINAL_CLAIM, result.stop_reason)
        self.assertEqual(TerminalClaim.FAILURE, result.final_observation.terminal_claim)

    def test_blocked_and_uncertain_stop_immediately(self):
        for state, reason in (
            (ControllerState.BLOCKED, FollowStopReason.BLOCKED),
            (ControllerState.UNCERTAIN, FollowStopReason.UNCERTAIN),
        ):
            with self.subTest(state=state):
                result, adapter, _ = self.run_follow([observation(state)])
                self.assertEqual(reason, result.stop_reason)
                self.assertEqual(1, adapter.observe_calls)

    def test_wrong_task_operation_binding_stops_before_provider_read(self):
        adapter = FakeAdapter([observation(ControllerState.EXECUTING)])
        result, _, _ = self.run_follow(
            [],
            task=make_task(task_id="task-a"),
            operation=make_operation(task_id="task-b"),
            adapter=adapter,
        )
        self.assertEqual(FollowStopReason.BINDING_INVALID, result.stop_reason)
        self.assertEqual(ControllerState.BLOCKED, result.outcome_state)
        self.assertEqual(0, adapter.observe_calls)

    def test_wrong_workstream_binding_stops_before_provider_read(self):
        binding = WorkstreamBinding(
            workstream_id="lane-a",
            repo="oimus1976/agent-controller",
            root_work_item_ref="#122",
            task_ids=("other-task",),
        )
        adapter = FakeAdapter([observation(ControllerState.EXECUTING)])
        result, _, _ = self.run_follow(
            [], adapter=adapter, workstream_binding=binding
        )
        self.assertEqual(FollowStopReason.BINDING_INVALID, result.stop_reason)
        self.assertEqual("TASK_NOT_IN_WORKSTREAM", result.failure_reason)
        self.assertEqual(0, adapter.observe_calls)

    def test_correct_workstream_binding_is_preserved(self):
        binding = WorkstreamBinding(
            workstream_id="lane-122",
            repo="oimus1976/agent-controller",
            root_work_item_ref="#122",
            task_ids=("task-1",),
        )
        result, _, _ = self.run_follow(
            [observation(ControllerState.ARTIFACT_READY)],
            workstream_binding=binding,
        )
        self.assertEqual("lane-122", result.workstream_id)

    def test_provider_observation_binding_mismatch_fails_closed(self):
        result, adapter, _ = self.run_follow(
            [observation(ControllerState.EXECUTING, provider_operation_id="wrong")]
        )
        self.assertEqual(FollowStopReason.OBSERVATION_INVALID, result.stop_reason)
        self.assertEqual(ControllerState.BLOCKED, result.outcome_state)
        self.assertEqual(0, result.observation_count)
        self.assertEqual(1, adapter.observe_calls)

    def test_provider_read_exception_stops_uncertain_without_retry(self):
        adapter = FakeAdapter(
            [observation(ControllerState.EXECUTING)],
            error_at=1,
        )
        result, _, _ = self.run_follow([], adapter=adapter)
        self.assertEqual(FollowStopReason.PROVIDER_READ_ERROR, result.stop_reason)
        self.assertEqual(ControllerState.UNCERTAIN, result.outcome_state)
        self.assertEqual(1, adapter.observe_calls)

    def test_jules_and_codex_use_same_core_policy(self):
        for provider in ("jules", "codex"):
            with self.subTest(provider=provider):
                result, adapter, _ = self.run_follow(
                    [
                        observation(ControllerState.PLANNING, provider=provider),
                        observation(ControllerState.ARTIFACT_READY, provider=provider),
                    ],
                    task=make_task(provider=provider),
                    operation=make_operation(provider=provider),
                )
                self.assertEqual(FollowStopReason.HANDOFF_READY, result.stop_reason)
                self.assertEqual(2, adapter.observe_calls)

    def test_bounds_reject_boolean_zero_and_negative_values(self):
        adapter = FakeAdapter([])
        base = dict(
            task=make_task(),
            operation=make_operation(),
            adapter=adapter,
            clock=FakeClock().now,
            sleeper=lambda _: None,
        )
        for key, value in (
            ("max_elapsed_seconds", 0),
            ("max_elapsed_seconds", True),
            ("max_observations", 0),
            ("max_observations", True),
            ("poll_interval_seconds", 0),
            ("poll_interval_seconds", True),
        ):
            with self.subTest(key=key, value=value):
                kwargs = dict(
                    max_elapsed_seconds=10,
                    max_observations=3,
                    poll_interval_seconds=1,
                )
                kwargs[key] = value
                with self.assertRaises((TypeError, ValueError)):
                    follow_bound_operation(**base, **kwargs)
        self.assertEqual(0, adapter.observe_calls)

    def test_result_serialization_keeps_compact_transition_history(self):
        result, _, _ = self.run_follow(
            [
                observation(ControllerState.PLANNING),
                observation(ControllerState.PLANNING),
                observation(ControllerState.EXECUTING),
                observation(ControllerState.EXECUTING),
                observation(ControllerState.ARTIFACT_READY),
            ]
        )
        payload = result.to_dict()
        self.assertEqual(5, payload["observation_count"])
        self.assertEqual(2, len(payload["transitions"]))
        self.assertEqual("PLANNING", payload["first_observation"]["mapped_state"])
        self.assertEqual("ARTIFACT_READY", payload["final_observation"]["mapped_state"])


if __name__ == "__main__":
    unittest.main()
