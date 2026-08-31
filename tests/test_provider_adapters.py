import inspect
import unittest

from agent_controller.provider_adapters import (
    CodexObservationAdapter,
    JulesObservationAdapter,
)
from agent_controller.provider_clients import ProviderReadClient
from agent_controller.provider_contract import (
    AgentAdapter,
    AwaitingInput,
    ControllerState,
    ProviderOperationRef,
)


class FixtureReadClient:
    def __init__(self, raw_state):
        self.raw_state = raw_state
        self.calls = []

    def get_operation_raw(self, operation):
        self.calls.append(operation)
        return self.raw_state


class TestProviderObservationAdapters(unittest.TestCase):
    def make_operation(self, provider):
        return ProviderOperationRef(
            provider=provider,
            provider_operation_id=f"{provider}-operation-1",
            provider_url=None,
            controller_task_id="controller-task-1",
            operation_id="operation-1",
        )

    def test_jules_adapter_delegates_client_then_mapper(self):
        client = FixtureReadClient(
            {
                "state": "AWAITING_PLAN_APPROVAL",
                "plan_id": "plan-1",
                "updated_at": "2026-08-24T01:40:00Z",
            }
        )
        adapter = JulesObservationAdapter(
            client=client,
            observed_at=lambda: "2026-08-24T01:41:00Z",
        )
        operation = self.make_operation("jules")

        observation = adapter.observe(operation)

        self.assertEqual(client.calls, [operation])
        self.assertEqual(observation.provider, "jules")
        self.assertEqual(observation.mapped_state, ControllerState.PLAN_REVIEW_REQUIRED)
        self.assertEqual(observation.awaiting_input, AwaitingInput.PLAN_APPROVAL)
        self.assertEqual(observation.provider_refs, ("plan-1",))

    def test_codex_adapter_delegates_client_then_mapper(self):
        client = FixtureReadClient(
            {
                "status": "waiting_for_user",
                "reason": "plan_review",
                "task_id": "task-1",
                "updated_at": "2026-08-24T01:40:00Z",
            }
        )
        adapter = CodexObservationAdapter(
            client=client,
            observed_at=lambda: "2026-08-24T01:41:00Z",
        )
        operation = self.make_operation("codex")

        observation = adapter.observe(operation)

        self.assertEqual(client.calls, [operation])
        self.assertEqual(observation.provider, "codex")
        self.assertEqual(observation.mapped_state, ControllerState.PLAN_REVIEW_REQUIRED)
        self.assertEqual(observation.awaiting_input, AwaitingInput.PLAN_APPROVAL)
        self.assertEqual(observation.provider_refs, ("task-1",))

    def test_provider_target_mismatch_is_rejected_before_client_read(self):
        client = FixtureReadClient({"status": "RUNNING"})
        jules = JulesObservationAdapter(client, lambda: "2026-08-24T01:41:00Z")
        codex = CodexObservationAdapter(client, lambda: "2026-08-24T01:41:00Z")

        with self.assertRaises(ValueError):
            jules.observe(self.make_operation("codex"))
        with self.assertRaises(ValueError):
            codex.observe(self.make_operation("jules"))

        self.assertEqual(client.calls, [])

    def test_observation_adapters_are_intentionally_not_full_agent_adapters(self):
        client = FixtureReadClient({"status": "RUNNING"})
        self.assertIsInstance(client, ProviderReadClient)
        self.assertNotIsInstance(
            JulesObservationAdapter(client, lambda: "2026-08-24T01:41:00Z"),
            AgentAdapter,
        )
        self.assertNotIsInstance(
            CodexObservationAdapter(client, lambda: "2026-08-24T01:41:00Z"),
            AgentAdapter,
        )

    def test_observation_adapters_expose_no_dispatch_or_mutation_surface(self):
        forbidden = (
            "dispatch",
            "approve",
            "send",
            "retry",
            "cancel",
            "create",
            "update",
            "delete",
            "merge",
            "deploy",
        )
        for adapter_type in (JulesObservationAdapter, CodexObservationAdapter):
            source = inspect.getsource(adapter_type)
            for name in forbidden:
                self.assertNotIn(f"def {name}", source)


if __name__ == "__main__":
    unittest.main()
