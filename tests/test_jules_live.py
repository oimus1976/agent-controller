import os
import unittest
from json import loads
from urllib.parse import parse_qs, urlparse

from agent_controller.jules_live import (
    JulesApiClient,
    JulesDispatchClient,
    JulesReadClient,
    _branch_from_ref,
)
from agent_controller.provider_adapters import JulesObservationAdapter
from agent_controller.provider_contract import (
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)


def make_task(
    provider="jules",
    repo="oimus1976/agent-controller",
    ref="refs/heads/main",
    sha="1234567890abcdef1234567890abcdef12345678",
):
    return TaskBinding(
        controller_task_id="task-jules-123",
        operation_id="op-jules-123",
        provider=provider,
        repo=repo,
        expected_start_ref=ref,
        expected_start_sha=sha,
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="IMPLEMENT",
        allowed_effects=("SESSION_CREATE",),
        forbidden_effects=("AUTO_CREATE_PR",),
        approval_policy_id="policy-1",
        created_at="2026-08-24T01:00:00Z",
    )


class TestJulesLiveAdapter(unittest.TestCase):
    def test_branch_from_ref_parsing(self):
        self.assertEqual(_branch_from_ref("refs/heads/feature/test"), "feature/test")
        self.assertEqual(_branch_from_ref("heads/main"), "main")
        self.assertEqual(_branch_from_ref("dev"), "dev")

        with self.assertRaises(ValueError):
            _branch_from_ref("")
        with self.assertRaises(ValueError):
            _branch_from_ref("refs/heads/")

    def test_missing_api_key_fails_closed_before_network(self):
        old_key = os.environ.pop("JULES_API_KEY", None)
        try:
            client = JulesApiClient(api_key=None)
            with self.assertRaisesRegex(ValueError, "JULES_API_KEY is required"):
                client.get_session("session-1")
        finally:
            if old_key is not None:
                os.environ["JULES_API_KEY"] = old_key

    def test_api_key_header_sent_and_not_leaked_on_error(self):
        fake_key = "secret-jules-api-key-99999"

        def failing_transport(req):
            self.assertEqual(req.headers.get("X-goog-api-key"), fake_key)
            raise RuntimeError(f"Server refused request containing key {fake_key}")

        client = JulesApiClient(api_key=fake_key, transport=failing_transport)
        with self.assertRaises(RuntimeError) as ctx:
            client.get_session("session-1")

        err_text = str(ctx.exception)
        self.assertNotIn(fake_key, err_text)
        self.assertIn("[REDACTED]", err_text)

    def test_source_resolution(self):
        client = JulesApiClient(api_key="fake-key")
        self.assertEqual(
            client.resolve_source("oimus1976/agent-controller"),
            "sources/github.com/oimus1976/agent-controller",
        )
        self.assertEqual(
            client.resolve_source("sources/github.com/oimus1976/agent-controller"),
            "sources/github.com/oimus1976/agent-controller",
        )

    def test_dispatch_session_creation(self):
        captured_requests = []

        def mock_transport(req):
            captured_requests.append(req)
            body = loads(req.data.decode("utf-8")) if req.data else {}
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "name": "sessions/sess-abc-123",
                    "id": "sess-abc-123",
                    "state": "QUEUED",
                    "url": "https://jules.google.com/session/sess-abc-123",
                }),
            )

        api_client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        dispatch_client = JulesDispatchClient(api_client)

        task = make_task()
        ref = dispatch_client.dispatch(task, prompt="Implement live Jules adapter")

        self.assertEqual(ref.provider, "jules")
        self.assertEqual(ref.provider_operation_id, "sess-abc-123")
        self.assertEqual(ref.controller_task_id, task.controller_task_id)
        self.assertEqual(ref.operation_id, task.operation_id)
        self.assertEqual(ref.provider_url, "https://jules.google.com/session/sess-abc-123")

        self.assertEqual(len(captured_requests), 1)
        sent_body = loads(captured_requests[0].data.decode("utf-8"))
        self.assertEqual(sent_body["prompt"], "Implement live Jules adapter")
        self.assertEqual(
            sent_body["sourceContext"]["source"],
            "sources/github.com/oimus1976/agent-controller",
        )
        self.assertEqual(
            sent_body["sourceContext"]["githubRepoContext"]["startingBranch"],
            "main",
        )
        self.assertTrue(sent_body["requirePlanApproval"])
        self.assertEqual(sent_body["automationMode"], "AUTOMATION_MODE_UNSPECIFIED")

    def test_read_client_and_observation_adapter_mapping(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "id": "sess-abc-123",
                    "state": "AWAITING_PLAN_APPROVAL",
                    "updateTime": "2026-08-24T02:00:00Z",
                }),
            )

        api_client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        read_client = JulesReadClient(api_client)
        adapter = JulesObservationAdapter(
            client=read_client,
            observed_at=lambda: "2026-08-24T02:01:00Z",
        )

        op = ProviderOperationRef(
            provider="jules",
            provider_operation_id="sess-abc-123",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )

        observation = adapter.observe(op)
        self.assertEqual(observation.provider, "jules")
        self.assertEqual(observation.mapped_state, ControllerState.PLAN_REVIEW_REQUIRED)
        self.assertEqual(observation.provider_updated_at, "2026-08-24T02:00:00Z")

    def test_jules_completion_is_provider_claim_not_controller_pass(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "id": "sess-abc-123",
                    "state": "COMPLETED",
                    "updateTime": "2026-08-24T02:00:00Z",
                }),
            )

        api_client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        read_client = JulesReadClient(api_client)
        adapter = JulesObservationAdapter(
            client=read_client,
            observed_at=lambda: "2026-08-24T02:01:00Z",
        )

        op = ProviderOperationRef(
            provider="jules",
            provider_operation_id="sess-abc-123",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )

        observation = adapter.observe(op)
        self.assertEqual(observation.mapped_state, ControllerState.ARTIFACT_READY)
        self.assertEqual(observation.terminal_claim, TerminalClaim.SUCCESS)
        # Verify mapped_state is NOT a Controller PASS state (Controller PASS is determined independently via objective verification)
        self.assertNotEqual(observation.mapped_state, "PASS")

    def test_unknown_or_malformed_state_fails_closed_to_uncertain(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "id": "sess-abc-123",
                    "state": "SOME_FUTURE_UNKNOWN_STATE",
                }),
            )

        api_client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        read_client = JulesReadClient(api_client)
        adapter = JulesObservationAdapter(
            client=read_client,
            observed_at=lambda: "2026-08-24T02:01:00Z",
        )

        op = ProviderOperationRef(
            provider="jules",
            provider_operation_id="sess-abc-123",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )

        observation = adapter.observe(op)
        self.assertEqual(observation.mapped_state, ControllerState.UNCERTAIN)
        self.assertEqual(observation.uncertainty_reason, "JULES_STATUS_UNKNOWN")


def json_bytes(obj):
    import json
    return json.dumps(obj).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
