import unittest

from agent_controller.provider_adapters import (
    CodexObservationAdapter,
    JulesObservationAdapter,
)
from agent_controller.provider_artifacts import (
    CodexArtifactAdapter,
    JulesArtifactAdapter,
)
from agent_controller.provider_contract import (
    AgentAdapter,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
)
from agent_controller.provider_runtime import (
    AdapterCapabilities,
    CodexAgentAdapter,
    JulesAgentAdapter,
)


class FakeDispatchClient:
    def __init__(self, provider):
        self.provider = provider
        self.calls = []

    def dispatch(self, task):
        self.calls.append(task)
        return ProviderOperationRef(
            provider=self.provider,
            provider_operation_id=f"{self.provider}-opaque-1",
            provider_url=None,
            controller_task_id=task.controller_task_id,
            operation_id=task.operation_id,
        )


class FakeObservationClient:
    def __init__(self, payload):
        self.payload = payload

    def get_operation_raw(self, operation):
        return self.payload


class FakeArtifactClient:
    def list_artifacts_raw(self, operation):
        return []


def make_task(provider):
    return TaskBinding(
        controller_task_id="task-1",
        operation_id="op-1",
        provider=provider,
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="start-sha",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="IMPLEMENT",
        allowed_effects=("CREATE_COMMIT",),
        forbidden_effects=("MERGE",),
        approval_policy_id="policy-1",
        created_at="2026-08-24T01:00:00Z",
    )


def make_jules(capabilities):
    return JulesAgentAdapter(
        dispatch_client=FakeDispatchClient("jules"),
        observation=JulesObservationAdapter(
            FakeObservationClient({"status": "WORKING"}),
            lambda: "2026-08-24T01:01:00Z",
        ),
        artifacts=JulesArtifactAdapter(
            FakeArtifactClient(),
            lambda: "2026-08-24T01:02:00Z",
        ),
        capabilities=capabilities,
    )


def make_codex(capabilities):
    return CodexAgentAdapter(
        dispatch_client=FakeDispatchClient("codex"),
        observation=CodexObservationAdapter(
            FakeObservationClient({"status": "running"}),
            lambda: "2026-08-24T01:01:00Z",
        ),
        artifacts=CodexArtifactAdapter(
            FakeArtifactClient(),
            lambda: "2026-08-24T01:02:00Z",
        ),
        capabilities=capabilities,
    )


class TestProviderRuntime(unittest.TestCase):
    def test_both_composed_adapters_satisfy_same_agent_adapter_protocol(self):
        self.assertIsInstance(make_jules(AdapterCapabilities()), AgentAdapter)
        self.assertIsInstance(make_codex(AdapterCapabilities()), AgentAdapter)

    def test_dispatch_preserves_opaque_identity_and_controller_binding(self):
        for provider, adapter in (
            ("jules", make_jules(AdapterCapabilities())),
            ("codex", make_codex(AdapterCapabilities())),
        ):
            task = make_task(provider)
            operation = adapter.dispatch(task)
            self.assertEqual(operation.provider, provider)
            self.assertEqual(operation.provider_operation_id, f"{provider}-opaque-1")
            self.assertEqual(operation.controller_task_id, task.controller_task_id)
            self.assertEqual(operation.operation_id, task.operation_id)

    def test_bad_dispatch_binding_is_rejected(self):
        class BadDispatch:
            def dispatch(self, task):
                return ProviderOperationRef(
                    provider="jules",
                    provider_operation_id="opaque",
                    provider_url=None,
                    controller_task_id="other-task",
                    operation_id=task.operation_id,
                )

        adapter = make_jules(AdapterCapabilities())
        adapter = JulesAgentAdapter(
            BadDispatch(), adapter.observation, adapter.artifacts, adapter.capabilities
        )
        with self.assertRaisesRegex(ValueError, "CONTROLLER_TASK_ID_MISMATCH"):
            adapter.dispatch(make_task("jules"))

    def test_capability_asymmetry_is_explicit_but_outside_core_protocol(self):
        jules_caps = AdapterCapabilities(
            frozenset({"PLAN_APPROVAL", "REVISION", "CONTINUED_TURN"})
        )
        codex_caps = AdapterCapabilities(
            frozenset({"REVIEW", "STREAM", "CONTINUED_TURN"})
        )
        jules = make_jules(jules_caps)
        codex = make_codex(codex_caps)

        self.assertTrue(jules.capabilities.supports("PLAN_APPROVAL"))
        self.assertFalse(codex.capabilities.supports("PLAN_APPROVAL"))
        self.assertTrue(codex.capabilities.supports("REVIEW"))
        self.assertFalse(jules.capabilities.supports("REVIEW"))
        self.assertNotIn("capabilities", AgentAdapter.__dict__)

    def test_wrong_task_provider_is_rejected_before_dispatch_client_call(self):
        adapter = make_jules(AdapterCapabilities())
        with self.assertRaisesRegex(ValueError, "task.provider='jules'"):
            adapter.dispatch(make_task("codex"))
        self.assertEqual(adapter.dispatch_client.calls, [])


if __name__ == "__main__":
    unittest.main()
