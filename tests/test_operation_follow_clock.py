from __future__ import annotations

import unittest

from agent_controller.operation_follow import FollowStopReason, follow_bound_operation
from agent_controller.provider_contract import (
    AgentObservation,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
)


class SequenceClock:
    def __init__(self, values):
        self.values = iter(values)

    def __call__(self):
        return next(self.values)


class OneObservationAdapter:
    def __init__(self, value):
        self.value = value
        self.calls = 0

    def observe(self, operation):
        self.calls += 1
        return self.value

    def dispatch(self, task):
        raise AssertionError("follow must not dispatch")

    def collect_artifacts(self, operation):
        raise AssertionError("follow must not collect artifacts")


def task():
    return TaskBinding(
        controller_task_id="task-clock",
        operation_id="op-clock",
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/feature",
        expected_start_sha="a" * 40,
        objective_scope=ObjectiveScope(),
        requested_capability="IMPLEMENT",
        allowed_effects=(),
        forbidden_effects=(),
        approval_policy_id="policy",
        created_at="2026-08-31T00:00:00Z",
    )


def operation():
    return ProviderOperationRef(
        provider="jules",
        provider_operation_id="provider-clock",
        provider_url=None,
        controller_task_id="task-clock",
        operation_id="op-clock",
    )


def artifact_ready():
    return AgentObservation(
        provider="jules",
        provider_operation_id="provider-clock",
        observed_at="2026-08-31T00:00:00Z",
        provider_updated_at=None,
        provider_raw_state={},
        mapped_state=ControllerState.ARTIFACT_READY,
    )


class OperationFollowClockTests(unittest.TestCase):
    def test_clock_reversal_after_handoff_observation_fails_closed(self):
        adapter = OneObservationAdapter(artifact_ready())
        result = follow_bound_operation(
            task=task(),
            operation=operation(),
            adapter=adapter,
            max_elapsed_seconds=10,
            max_observations=3,
            poll_interval_seconds=1,
            clock=SequenceClock([5.0, 4.0]),
            sleeper=lambda _: None,
        )
        self.assertEqual(FollowStopReason.UNCERTAIN, result.stop_reason)
        self.assertEqual(ControllerState.UNCERTAIN, result.outcome_state)
        self.assertEqual("MONOTONIC_CLOCK_REVERSED", result.failure_reason)
        self.assertEqual(1, adapter.calls)
        self.assertEqual(1, result.observation_count)


if __name__ == "__main__":
    unittest.main()
