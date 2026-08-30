import inspect
import unittest

from agent_controller.provider_clients import ProviderReadClient
from agent_controller.provider_contract import (
    AgentAdapter,
    ArtifactEvidence,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)
from agent_controller.provider_mappers import (
    map_codex_observation,
    map_jules_observation,
)


def run_provider_neutral_flow(adapter: AgentAdapter, task: TaskBinding):
    """PN1 proof helper: exercise only the mandatory adapter surface."""

    operation = adapter.dispatch(task)
    observation = adapter.observe(operation)
    artifacts = adapter.collect_artifacts(operation)
    return operation, observation, artifacts


class FixtureReadClient:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get_operation_raw(self, operation):
        self.calls.append(operation.provider_operation_id)
        return self.payload


class JulesFixtureAdapter:
    def __init__(self, client=None):
        self.client = client or FixtureReadClient(
            {
                "state": "AWAITING_PLAN_APPROVAL",
                "plan_id": "plan-7",
                "updateTime": "2026-08-24T01:29:59Z",
            }
        )

    def dispatch(self, task):
        return ProviderOperationRef(
            provider="jules",
            provider_operation_id="jules-session-42",
            provider_url="https://example.invalid/jules/42",
            controller_task_id=task.controller_task_id,
            operation_id=task.operation_id,
        )

    def observe(self, operation):
        raw_state = self.client.get_operation_raw(operation)
        return map_jules_observation(
            provider_operation_id=operation.provider_operation_id,
            raw_state=raw_state,
            observed_at="2026-08-24T01:30:00Z",
        )

    def collect_artifacts(self, operation):
        return []


class CodexFixtureAdapter:
    def __init__(self, client=None):
        self.client = client or FixtureReadClient(
            {
                "status": "waiting_for_user",
                "reason": "plan_review",
                "task_id": "task-99",
                "updated_at": "2026-08-24T01:29:58Z",
            }
        )

    def dispatch(self, task):
        return ProviderOperationRef(
            provider="codex",
            provider_operation_id="codex-task-99",
            provider_url="https://example.invalid/codex/99",
            controller_task_id=task.controller_task_id,
            operation_id=task.operation_id,
        )

    def observe(self, operation):
        raw_state = self.client.get_operation_raw(operation)
        return map_codex_observation(
            provider_operation_id=operation.provider_operation_id,
            raw_state=raw_state,
            observed_at="2026-08-24T01:30:00Z",
        )

    def collect_artifacts(self, operation):
        return []


class JulesArtifactFixtureAdapter(JulesFixtureAdapter):
    def __init__(self):
        super().__init__(
            FixtureReadClient(
                {
                    "state": "COMPLETED",
                    "artifact_id": "jules-artifact-1",
                    "updateTime": "2026-08-24T01:34:59Z",
                }
            )
        )

    def collect_artifacts(self, operation):
        return [
            ArtifactEvidence(
                provider="jules",
                provider_operation_id=operation.provider_operation_id,
                artifact_kind="commit",
                provider_artifact_id="jules-artifact-1",
                provider_reported_ref="refs/heads/jules-work",
                provider_reported_sha="jules-reported-sha",
                content_hash=None,
                observed_at="2026-08-24T01:35:00Z",
                freshness_basis="provider_updated_at",
            )
        ]


class CodexArtifactFixtureAdapter(CodexFixtureAdapter):
    def __init__(self):
        super().__init__(
            FixtureReadClient(
                {
                    "status": "done",
                    "result": "success",
                    "artifact_id": "codex-artifact-1",
                    "updated_at": "2026-08-24T01:34:58Z",
                }
            )
        )

    def collect_artifacts(self, operation):
        return [
            ArtifactEvidence(
                provider="codex",
                provider_operation_id=operation.provider_operation_id,
                artifact_kind="commit",
                provider_artifact_id="codex-artifact-1",
                provider_reported_ref="refs/heads/codex-work",
                provider_reported_sha="codex-reported-sha",
                content_hash=None,
                observed_at="2026-08-24T01:35:00Z",
                freshness_basis="provider_updated_at",
            )
        ]


class TestProviderNeutralFlow(unittest.TestCase):
    def make_task(self, provider):
        return TaskBinding(
            controller_task_id="controller-task-pn1",
            operation_id="operation-pn1",
            provider=provider,
            repo="oimus1976/agent-controller",
            expected_start_ref="refs/heads/main",
            expected_start_sha="1cda192b8013f40faa3deabfe44955a1394630e5",
            objective_scope=ObjectiveScope(
                allowed_paths=("agent_controller/**", "tests/**"),
                denied_paths=None,
            ),
            requested_capability="IMPLEMENT",
            allowed_effects=("CREATE_BRANCH", "CREATE_COMMIT"),
            forbidden_effects=("MERGE", "PUSH_DEFAULT_BRANCH"),
            approval_policy_id="pn1-fixture-policy",
            created_at="2026-08-24T01:25:00Z",
        )

    def test_read_client_contract_is_read_only_and_minimal(self):
        client = FixtureReadClient({"status": "RUNNING"})
        self.assertIsInstance(client, ProviderReadClient)
        source = inspect.getsource(ProviderReadClient)
        self.assertIn("def get_operation_raw", source)
        for forbidden in ("approve", "send", "retry", "cancel", "dispatch", "create"):
            self.assertNotIn(f"def {forbidden}", source)

    def test_jules_and_codex_satisfy_same_runtime_contract(self):
        self.assertIsInstance(JulesFixtureAdapter(), AgentAdapter)
        self.assertIsInstance(CodexFixtureAdapter(), AgentAdapter)

    def test_adapter_observation_reads_client_then_maps(self):
        jules_client = FixtureReadClient(
            {"state": "IN_PROGRESS", "updateTime": "2026-08-24T01:30:00Z"}
        )
        codex_client = FixtureReadClient(
            {"status": "running", "updated_at": "2026-08-24T01:30:00Z"}
        )

        jules = JulesFixtureAdapter(jules_client)
        codex = CodexFixtureAdapter(codex_client)

        jules_op = jules.dispatch(self.make_task("jules"))
        codex_op = codex.dispatch(self.make_task("codex"))

        self.assertEqual(jules.observe(jules_op).mapped_state, ControllerState.EXECUTING)
        self.assertEqual(codex.observe(codex_op).mapped_state, ControllerState.EXECUTING)
        self.assertEqual(jules_client.calls, ["jules-session-42"])
        self.assertEqual(codex_client.calls, ["codex-task-99"])

    def test_different_provider_states_map_to_same_controller_state(self):
        results = []
        for provider, adapter in (
            ("jules", JulesFixtureAdapter()),
            ("codex", CodexFixtureAdapter()),
        ):
            _, observation, artifacts = run_provider_neutral_flow(
                adapter, self.make_task(provider)
            )
            results.append(observation)
            self.assertEqual(artifacts, [])

        self.assertNotEqual(results[0].provider_raw_state, results[1].provider_raw_state)
        self.assertEqual(results[0].mapped_state, results[1].mapped_state)
        self.assertEqual(results[0].mapped_state, ControllerState.PLAN_REVIEW_REQUIRED)
        self.assertEqual(results[0].awaiting_input, AwaitingInput.PLAN_APPROVAL)
        self.assertEqual(results[1].awaiting_input, AwaitingInput.PLAN_APPROVAL)

    def test_same_flow_collects_provider_specific_artifacts_without_trusting_them(self):
        for provider, adapter in (
            ("jules", JulesArtifactFixtureAdapter()),
            ("codex", CodexArtifactFixtureAdapter()),
        ):
            operation, observation, artifacts = run_provider_neutral_flow(
                adapter, self.make_task(provider)
            )

            self.assertEqual(operation.provider, provider)
            self.assertEqual(observation.mapped_state, ControllerState.ARTIFACT_READY)
            self.assertEqual(observation.terminal_claim, TerminalClaim.SUCCESS)
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].provider, provider)
            self.assertFalse(artifacts[0].independently_verified)
            self.assertIsNone(artifacts[0].verified_sha)

    def test_controller_flow_never_branches_on_provider_name(self):
        normalized = []
        for provider, adapter in (
            ("jules", JulesFixtureAdapter()),
            ("codex", CodexFixtureAdapter()),
        ):
            _, observation, _ = run_provider_neutral_flow(
                adapter, self.make_task(provider)
            )
            normalized.append(
                (
                    observation.mapped_state,
                    observation.awaiting_input,
                    observation.terminal_claim,
                )
            )

        self.assertEqual(normalized[0], normalized[1])

    def test_fixture_adapters_delegate_observation_mapping(self):
        jules_source = inspect.getsource(JulesFixtureAdapter.observe)
        codex_source = inspect.getsource(CodexFixtureAdapter.observe)

        self.assertIn("get_operation_raw", jules_source)
        self.assertIn("get_operation_raw", codex_source)
        self.assertIn("map_jules_observation", jules_source)
        self.assertIn("map_codex_observation", codex_source)
        self.assertNotIn("AgentObservation(", jules_source)
        self.assertNotIn("AgentObservation(", codex_source)


if __name__ == "__main__":
    unittest.main()
