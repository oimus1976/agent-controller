import unittest

from agent_controller.provider_contract import AwaitingInput, ControllerState, TerminalClaim
from agent_controller.provider_mappers import (
    map_codex_observation,
    map_jules_observation,
)


class TestProviderMappers(unittest.TestCase):
    def test_jules_plan_approval_maps_to_provider_neutral_state(self):
        raw = {
            "status": "AWAITING_PLAN_APPROVAL",
            "plan_id": "plan-7",
            "updated_at": "2026-08-24T01:29:59Z",
        }
        observation = map_jules_observation(
            provider_operation_id="jules-session-42",
            raw_state=raw,
            observed_at="2026-08-24T01:30:00Z",
        )

        self.assertEqual(observation.mapped_state, ControllerState.PLAN_REVIEW_REQUIRED)
        self.assertEqual(observation.awaiting_input, AwaitingInput.PLAN_APPROVAL)
        self.assertEqual(observation.provider_refs, ("plan-7",))
        self.assertEqual(observation.provider_raw_state, raw)

    def test_codex_plan_review_maps_to_same_provider_neutral_state(self):
        raw = {
            "status": "waiting_for_user",
            "reason": "plan_review",
            "task_id": "task-99",
            "updated_at": "2026-08-24T01:29:58Z",
        }
        observation = map_codex_observation(
            provider_operation_id="codex-task-99",
            raw_state=raw,
            observed_at="2026-08-24T01:30:00Z",
        )

        self.assertEqual(observation.mapped_state, ControllerState.PLAN_REVIEW_REQUIRED)
        self.assertEqual(observation.awaiting_input, AwaitingInput.PLAN_APPROVAL)
        self.assertEqual(observation.provider_refs, ("task-99",))
        self.assertEqual(observation.provider_raw_state, raw)

    def test_jules_and_codex_running_states_normalize_to_executing(self):
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"status": "WORKING"},
            observed_at="2026-08-24T01:30:00Z",
        )
        codex = map_codex_observation(
            provider_operation_id="codex-1",
            raw_state={"status": "executing"},
            observed_at="2026-08-24T01:30:00Z",
        )

        self.assertEqual(jules.mapped_state, ControllerState.EXECUTING)
        self.assertEqual(codex.mapped_state, ControllerState.EXECUTING)

    def test_success_is_only_a_terminal_claim_not_independent_verification(self):
        for observation in (
            map_jules_observation(
                provider_operation_id="jules-1",
                raw_state={"status": "COMPLETED"},
                observed_at="2026-08-24T01:35:00Z",
            ),
            map_codex_observation(
                provider_operation_id="codex-1",
                raw_state={"status": "done", "result": "success"},
                observed_at="2026-08-24T01:35:00Z",
            ),
        ):
            self.assertEqual(observation.mapped_state, ControllerState.ARTIFACT_READY)
            self.assertEqual(observation.terminal_claim, TerminalClaim.SUCCESS)

    def test_failure_maps_to_blocked_terminal_claim(self):
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"status": "FAILED"},
            observed_at="2026-08-24T01:35:00Z",
        )
        codex = map_codex_observation(
            provider_operation_id="codex-1",
            raw_state={"status": "done", "result": "failed"},
            observed_at="2026-08-24T01:35:00Z",
        )

        for observation in (jules, codex):
            self.assertEqual(observation.mapped_state, ControllerState.BLOCKED)
            self.assertEqual(observation.terminal_claim, TerminalClaim.FAILURE)

    def test_unknown_states_fail_closed_to_uncertain(self):
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"status": "SOMETHING_NEW"},
            observed_at="2026-08-24T01:35:00Z",
        )
        codex = map_codex_observation(
            provider_operation_id="codex-1",
            raw_state={"status": "mystery", "result": "maybe"},
            observed_at="2026-08-24T01:35:00Z",
        )

        self.assertEqual(jules.mapped_state, ControllerState.UNCERTAIN)
        self.assertTrue(jules.uncertainty_reason.startswith("JULES_STATUS_UNKNOWN:"))
        self.assertEqual(codex.mapped_state, ControllerState.UNCERTAIN)
        self.assertTrue(codex.uncertainty_reason.startswith("CODEX_STATE_UNKNOWN:"))

    def test_missing_or_malformed_states_fail_closed(self):
        cases = (
            map_jules_observation(
                provider_operation_id="jules-1",
                raw_state={},
                observed_at="2026-08-24T01:35:00Z",
            ),
            map_jules_observation(
                provider_operation_id="jules-1",
                raw_state="not-a-mapping",
                observed_at="2026-08-24T01:35:00Z",
            ),
            map_codex_observation(
                provider_operation_id="codex-1",
                raw_state={},
                observed_at="2026-08-24T01:35:00Z",
            ),
            map_codex_observation(
                provider_operation_id="codex-1",
                raw_state=None,
                observed_at="2026-08-24T01:35:00Z",
            ),
        )

        for observation in cases:
            self.assertEqual(observation.mapped_state, ControllerState.UNCERTAIN)
            self.assertIsNotNone(observation.uncertainty_reason)

    def test_generic_user_wait_does_not_masquerade_as_plan_approval(self):
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"status": "AWAITING_USER"},
            observed_at="2026-08-24T01:35:00Z",
        )
        codex = map_codex_observation(
            provider_operation_id="codex-1",
            raw_state={"status": "waiting_for_user", "reason": "question"},
            observed_at="2026-08-24T01:35:00Z",
        )

        for observation in (jules, codex):
            self.assertEqual(observation.mapped_state, ControllerState.REVIEW_REQUIRED)
            self.assertEqual(observation.awaiting_input, AwaitingInput.USER_FEEDBACK)
            self.assertNotEqual(observation.awaiting_input, AwaitingInput.PLAN_APPROVAL)

    def test_secret_and_config_credentials_are_redacted_from_normalized_evidence(self):
        raw = {
            "status": "WORKING",
            "access_token": "top-secret-token",
            "nested": {
                "api-key": "provider-key",
                "Authorization": "Bearer abc",
                "safe": "keep-me",
            },
            "items": [{"password": "hunter2"}, {"value": "visible"}],
        }

        for mapper, operation_id in (
            (map_jules_observation, "jules-1"),
            (map_codex_observation, "codex-1"),
        ):
            observation = mapper(
                provider_operation_id=operation_id,
                raw_state=raw,
                observed_at="2026-08-24T01:35:00Z",
            )
            sanitized = observation.provider_raw_state
            self.assertEqual(sanitized["access_token"], "[REDACTED]")
            self.assertEqual(sanitized["nested"]["api-key"], "[REDACTED]")
            self.assertEqual(sanitized["nested"]["Authorization"], "[REDACTED]")
            self.assertEqual(sanitized["items"][0]["password"], "[REDACTED]")
            self.assertEqual(sanitized["nested"]["safe"], "keep-me")
            self.assertEqual(sanitized["items"][1]["value"], "visible")
            self.assertNotIn("top-secret-token", repr(sanitized))
            self.assertNotIn("provider-key", repr(sanitized))
            self.assertNotIn("Bearer abc", repr(sanitized))
            self.assertNotIn("hunter2", repr(sanitized))


if __name__ == "__main__":
    unittest.main()
