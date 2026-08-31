import math
import unittest
from unittest.mock import patch

from agent_controller.jules_live import (
    DEFAULT_JULES_REQUEST_TIMEOUT_SECONDS,
    JulesApiClient,
    JulesReadClient,
)
from agent_controller.operation_follow import FollowStopReason, follow_bound_operation
from agent_controller.provider_adapters import JulesObservationAdapter
from agent_controller.provider_contract import (
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
)


class FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, body=b"{}"):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


def make_task():
    return TaskBinding(
        controller_task_id="task-timeout",
        operation_id="op-timeout",
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="1234567890abcdef1234567890abcdef12345678",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="IMPLEMENT",
        allowed_effects=("SESSION_CREATE",),
        forbidden_effects=("AUTO_CREATE_PR",),
        approval_policy_id="policy-1",
        created_at="2026-09-01T00:00:00Z",
    )


def make_operation():
    return ProviderOperationRef(
        provider="jules",
        provider_operation_id="session-timeout",
        provider_url="https://jules.google.com/session/session-timeout",
        controller_task_id="task-timeout",
        operation_id="op-timeout",
    )


class JulesTimeoutTests(unittest.TestCase):
    def test_default_real_transport_uses_finite_timeout(self):
        seen = []

        def fake_urlopen(req, *, timeout):
            seen.append(timeout)
            return FakeResponse()

        with patch("agent_controller.jules_live.urlopen", side_effect=fake_urlopen):
            JulesApiClient(api_key="fake-key").get_session("session-1")

        self.assertEqual(seen, [DEFAULT_JULES_REQUEST_TIMEOUT_SECONDS])
        self.assertTrue(math.isfinite(seen[0]))
        self.assertGreater(seen[0], 0)

    def test_explicit_real_transport_timeout_is_forwarded(self):
        seen = []

        def fake_urlopen(req, *, timeout):
            seen.append(timeout)
            return FakeResponse()

        with patch("agent_controller.jules_live.urlopen", side_effect=fake_urlopen):
            client = JulesApiClient(api_key="fake-key", request_timeout_seconds=7.5)
            client.list_sources()
            client.get_session("session-1")

        self.assertEqual(seen, [7.5, 7.5])

    def test_malformed_timeout_fails_before_network_or_fake_transport(self):
        calls = []

        def fake_transport(req):
            calls.append(req)
            return 200, {}, b"{}"

        bad_values = (True, False, 0, -1, float("nan"), float("inf"), -float("inf"), "5")
        for value in bad_values:
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    JulesApiClient(
                        api_key="fake-key",
                        transport=fake_transport,
                        request_timeout_seconds=value,  # type: ignore[arg-type]
                    )
        self.assertEqual(calls, [])

    def test_timeout_error_is_sanitized(self):
        fake_key = "secret-jules-timeout-key"

        def fake_urlopen(req, *, timeout):
            raise TimeoutError(f"timed out with key {fake_key}")

        with patch("agent_controller.jules_live.urlopen", side_effect=fake_urlopen):
            client = JulesApiClient(api_key=fake_key, request_timeout_seconds=1)
            with self.assertRaises(RuntimeError) as ctx:
                client.get_session("session-1")

        text = str(ctx.exception)
        self.assertNotIn(fake_key, text)
        self.assertIn("[REDACTED]", text)

    def test_get_session_timeout_reaches_follow_as_read_uncertainty_without_retry(self):
        calls = []

        def timeout_transport(req):
            calls.append(req.full_url)
            raise TimeoutError("read timed out")

        client = JulesApiClient(
            api_key="fake-key",
            transport=timeout_transport,
            request_timeout_seconds=1,
        )
        adapter = JulesObservationAdapter(
            client=JulesReadClient(client),
            observed_at=lambda: "2026-09-01T00:00:00Z",
        )

        result = follow_bound_operation(
            task=make_task(),
            operation=make_operation(),
            adapter=adapter,  # type: ignore[arg-type]
            max_elapsed_seconds=30,
            max_observations=5,
            poll_interval_seconds=1,
            clock=lambda: 0.0,
            sleeper=lambda _: None,
        )

        self.assertEqual(result.stop_reason, FollowStopReason.PROVIDER_READ_ERROR)
        self.assertEqual(result.outcome_state, ControllerState.UNCERTAIN)
        self.assertEqual(result.observation_count, 0)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
