import os
import unittest
from json import loads

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


class FakeGitHubClient:
    def __init__(self, ref_shas=None):
        self.ref_shas = ref_shas or {}
        self.calls = []

    def get_ref_sha(self, repo, ref):
        self.calls.append((repo, ref))
        return self.ref_shas.get((repo, ref))


class TestJulesLiveAdapter(unittest.TestCase):
    def test_branch_from_ref_parsing(self):
        self.assertEqual(_branch_from_ref("refs/heads/feature/test"), "feature/test")
        self.assertEqual(_branch_from_ref("heads/main"), "main")
        self.assertEqual(_branch_from_ref("dev"), "dev")

        with self.assertRaises(ValueError):
            _branch_from_ref("")
        with self.assertRaises(ValueError):
            _branch_from_ref("refs/heads/")
        with self.assertRaisesRegex(ValueError, "must be a branch ref"):
            _branch_from_ref("refs/tags/v1.0.0")
        with self.assertRaisesRegex(ValueError, "must be a branch ref"):
            _branch_from_ref("refs/pull/1/head")

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

    def test_list_sources_pagination_multi_page(self):
        requested_urls = []

        def mock_transport(req):
            requested_urls.append(req.full_url)
            if "pageToken=token-page-2" in req.full_url:
                return (
                    200,
                    {"Content-Type": "application/json"},
                    json_bytes({
                        "sources": [
                            {
                                "name": "sources/page-2-src",
                                "githubRepo": {"owner": "oimus1976", "repo": "agent-controller"},
                            }
                        ]
                    }),
                )
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [
                        {
                            "name": "sources/page-1-src",
                            "githubRepo": {"owner": "other", "repo": "repo"},
                        }
                    ],
                    "nextPageToken": "token-page-2",
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        sources = client.list_sources()

        self.assertEqual(len(sources), 2)
        self.assertEqual(sources[0]["name"], "sources/page-1-src")
        self.assertEqual(sources[1]["name"], "sources/page-2-src")
        self.assertEqual(len(requested_urls), 2)
        self.assertIn("v1alpha/sources", requested_urls[0])
        self.assertIn("pageToken=token-page-2", requested_urls[1])

    def test_list_sources_pagination_cycle_fails_closed(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [{"name": "sources/src-1"}],
                    "nextPageToken": "looping-token",
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        with self.assertRaisesRegex(RuntimeError, "Detected pagination cycle"):
            client.list_sources()

    def test_list_sources_pagination_max_pages_fails_closed(self):
        page_counter = [0]

        def mock_transport(req):
            page_counter[0] += 1
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [{"name": f"sources/src-{page_counter[0]}"}],
                    "nextPageToken": f"token-{page_counter[0]}",
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        with self.assertRaisesRegex(RuntimeError, "Exceeded maximum page limit"):
            client.list_sources(max_pages=3)

    def test_list_sources_malformed_token_fails_closed(self):
        for bad_token in (12345, False, True, None, "", "   "):
            def mock_transport(req):
                return (
                    200,
                    {"Content-Type": "application/json"},
                    json_bytes({
                        "sources": [{"name": "sources/src-1"}],
                        "nextPageToken": bad_token,
                    }),
                )

            client = JulesApiClient(api_key="fake-key", transport=mock_transport)
            with self.assertRaisesRegex(RuntimeError, "Malformed 'nextPageToken'"):
                client.list_sources()

    def test_list_sources_omitted_next_page_token_completes_cleanly(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [{"name": "sources/src-1"}],
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        sources = client.list_sources()
        self.assertEqual(len(sources), 1)

    def test_source_resolution_from_sources_api(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [
                        {
                            "name": "sources/opaque-source-id-123",
                            "githubRepo": {
                                "owner": "oimus1976",
                                "repo": "agent-controller",
                            },
                        },
                        {
                            "name": "sources/opaque-source-id-456",
                            "githubRepo": {
                                "owner": "other",
                                "repo": "repo",
                            },
                        },
                    ]
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        self.assertEqual(
            client.resolve_source("oimus1976/agent-controller"),
            "sources/opaque-source-id-123",
        )
        self.assertEqual(
            client.resolve_source("sources/opaque-source-id-123"),
            "sources/opaque-source-id-123",
        )

    def test_source_resolution_case_insensitive_matching(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [
                        {
                            "name": "sources/opaque-source-id-123",
                            "githubRepo": {
                                "owner": "Oimus1976",
                                "repo": "Agent-Controller",
                            },
                        }
                    ]
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        self.assertEqual(
            client.resolve_source("oimus1976/agent-controller"),
            "sources/opaque-source-id-123",
        )

    def test_source_resolution_fails_closed_on_malformed_entry(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({"sources": ["not-a-mapping"]}),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        with self.assertRaisesRegex(RuntimeError, "Malformed source entry"):
            client.resolve_source("oimus1976/agent-controller")

    def test_cross_page_ambiguous_sources_fails_closed(self):
        def mock_transport(req):
            if "pageToken=token-page-2" in req.full_url:
                return (
                    200,
                    {"Content-Type": "application/json"},
                    json_bytes({
                        "sources": [
                            {
                                "name": "sources/opaque-source-id-456",
                                "githubRepo": {
                                    "owner": "oimus1976",
                                    "repo": "agent-controller",
                                },
                            }
                        ]
                    }),
                )
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [
                        {
                            "name": "sources/opaque-source-id-123",
                            "githubRepo": {
                                "owner": "oimus1976",
                                "repo": "agent-controller",
                            },
                        }
                    ],
                    "nextPageToken": "token-page-2",
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        with self.assertRaisesRegex(RuntimeError, "Ambiguous Jules sources"):
            client.resolve_source("oimus1976/agent-controller")

    def test_source_resolution_fails_closed_on_zero_or_ambiguous_matches(self):
        def mock_transport(req):
            return (
                200,
                {"Content-Type": "application/json"},
                json_bytes({
                    "sources": [
                        {
                            "name": "sources/opaque-1",
                            "githubRepo": {"owner": "oimus1976", "repo": "agent-controller"},
                        },
                        {
                            "name": "sources/opaque-2",
                            "githubRepo": {"owner": "oimus1976", "repo": "agent-controller"},
                        },
                    ]
                }),
            )

        client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        with self.assertRaisesRegex(RuntimeError, "Ambiguous Jules sources"):
            client.resolve_source("oimus1976/agent-controller")

        empty_client = JulesApiClient(
            api_key="fake-key",
            transport=lambda req: (200, {}, json_bytes({"sources": []})),
        )
        with self.assertRaisesRegex(RuntimeError, "No matching Jules source"):
            empty_client.resolve_source("oimus1976/agent-controller")

    def test_dispatch_session_creation_with_exact_starting_sha(self):
        captured_requests = []

        def mock_transport(req):
            captured_requests.append(req)
            if req.method == "GET" and "v1alpha/sources" in req.full_url:
                return (
                    200,
                    {"Content-Type": "application/json"},
                    json_bytes({
                        "sources": [
                            {
                                "name": "sources/opaque-source-id-123",
                                "githubRepo": {
                                    "owner": "oimus1976",
                                    "repo": "agent-controller",
                                },
                            }
                        ]
                    }),
                )
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
        task = make_task(sha="1234567890ABCDEF1234567890ABCDEF12345678")  # uppercase sha
        fake_github = FakeGitHubClient(
            ref_shas={("oimus1976/agent-controller", "refs/heads/main"): "1234567890abcdef1234567890abcdef12345678"}  # lowercase
        )
        dispatch_client = JulesDispatchClient(api_client, github_client=fake_github)

        ref = dispatch_client.dispatch(task, prompt="Implement live Jules adapter")

        self.assertEqual(ref.provider, "jules")
        self.assertEqual(ref.provider_operation_id, "sess-abc-123")
        self.assertEqual(ref.controller_task_id, task.controller_task_id)
        self.assertEqual(ref.operation_id, task.operation_id)
        self.assertEqual(ref.provider_url, "https://jules.google.com/session/sess-abc-123")

        self.assertEqual(len(captured_requests), 2)  # list_sources + create_session
        sent_body = loads(captured_requests[1].data.decode("utf-8"))
        self.assertEqual(sent_body["prompt"], "Implement live Jules adapter")
        self.assertEqual(
            sent_body["sourceContext"]["source"],
            "sources/opaque-source-id-123",
        )
        self.assertEqual(
            sent_body["sourceContext"]["githubRepoContext"]["startingBranch"],
            "main",
        )
        self.assertTrue(sent_body["requirePlanApproval"])
        self.assertEqual(sent_body["automationMode"], "AUTOMATION_MODE_UNSPECIFIED")

    def test_dispatch_invalid_repo_format_fails_closed(self):
        api_client = JulesApiClient(api_key="fake-key")
        task = make_task(repo="invalid-repo-format")
        fake_github = FakeGitHubClient()
        dispatch_client = JulesDispatchClient(api_client, github_client=fake_github)

        with self.assertRaisesRegex(ValueError, "TaskBinding.repo must be in OWNER/REPO format"):
            dispatch_client.dispatch(task)

    def test_dispatch_empty_prompt_fails_closed(self):
        api_client = JulesApiClient(api_key="fake-key")
        task = make_task()
        fake_github = FakeGitHubClient(
            ref_shas={("oimus1976/agent-controller", "refs/heads/main"): task.expected_start_sha}
        )
        dispatch_client = JulesDispatchClient(api_client, github_client=fake_github)

        with self.assertRaisesRegex(ValueError, "prompt must be a non-empty string when specified"):
            dispatch_client.dispatch(task, prompt="   ")

    def test_sha_drift_between_reads_prevents_jules_session_creation(self):
        created_sessions = []

        def mock_transport(req):
            if req.method == "POST":
                created_sessions.append(req)
            if req.method == "GET" and "v1alpha/sources" in req.full_url:
                return (
                    200,
                    {"Content-Type": "application/json"},
                    json_bytes({
                        "sources": [
                            {
                                "name": "sources/opaque-source-id-123",
                                "githubRepo": {
                                    "owner": "oimus1976",
                                    "repo": "agent-controller",
                                },
                            }
                        ]
                    }),
                )
            return (200, {}, json_bytes({}))

        api_client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        task = make_task(sha="initial-matching-sha")

        class DriftGitHubClient:
            def __init__(self):
                self.call_count = 0

            def get_ref_sha(self, repo, ref):
                self.call_count += 1
                if self.call_count == 1:
                    return "initial-matching-sha"
                return "drifted-different-sha"

        dispatch_client = JulesDispatchClient(api_client, github_client=DriftGitHubClient())

        with self.assertRaisesRegex(RuntimeError, "head SHA drifted"):
            dispatch_client.dispatch(task)

        self.assertEqual(len(created_sessions), 0)

    def test_starting_sha_mismatch_prevents_jules_session_creation(self):
        created_sessions = []

        def mock_transport(req):
            if req.method == "POST":
                created_sessions.append(req)
            return (200, {}, json_bytes({}))

        api_client = JulesApiClient(api_key="fake-key", transport=mock_transport)
        task = make_task(sha="expected-sha-123")
        fake_github = FakeGitHubClient(
            ref_shas={("oimus1976/agent-controller", "refs/heads/main"): "different-current-sha-456"}
        )
        dispatch_client = JulesDispatchClient(api_client, github_client=fake_github)

        with self.assertRaisesRegex(RuntimeError, "does not match expected starting SHA"):
            dispatch_client.dispatch(task)

        self.assertEqual(len(created_sessions), 0)

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
