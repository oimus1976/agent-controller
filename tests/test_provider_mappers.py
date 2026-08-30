import unittest

from agent_controller.provider_contract import AwaitingInput, ControllerState, TerminalClaim
from agent_controller.provider_mappers import (
    map_codex_observation,
    map_jules_observation,
)


class TestProviderMappers(unittest.TestCase):
    def test_jules_plan_approval_maps_to_provider_neutral_state(self):
        raw = {
            "state": "AWAITING_PLAN_APPROVAL",
            "plan_id": "plan-7",
            "updateTime": "2026-08-24T01:29:59Z",
        }
        observation = map_jules_observation(
            provider_operation_id="jules-session-42",
            raw_state=raw,
            observed_at="2026-08-24T01:30:00Z",
        )
        self.assertEqual(observation.mapped_state, ControllerState.PLAN_REVIEW_REQUIRED)
        self.assertEqual(observation.awaiting_input, AwaitingInput.PLAN_APPROVAL)
        self.assertEqual(observation.provider_refs, ("plan-7",))
        self.assertEqual(
            dict(observation.provider_raw_state),
            {
                "state": "AWAITING_PLAN_APPROVAL",
                "plan_id": "plan-7",
                "updated_at": "2026-08-24T01:29:59Z",
            },
        )

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
        self.assertEqual(dict(observation.provider_raw_state), raw)

    def test_jules_and_codex_running_states_normalize_to_executing(self):
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"state": "IN_PROGRESS"},
            observed_at="2026-08-24T01:30:00Z",
        )
        codex = map_codex_observation(
            provider_operation_id="codex-1",
            raw_state={"status": "executing"},
            observed_at="2026-08-24T01:30:00Z",
        )
        self.assertEqual(jules.mapped_state, ControllerState.EXECUTING)
        self.assertEqual(codex.mapped_state, ControllerState.EXECUTING)

    def test_legacy_jules_statuses_fail_closed_to_uncertain(self):
        for legacy_status in ("WORKING", "RUNNING", "SUCCEEDED", "ERROR", "PLAN_GENERATING"):
            jules = map_jules_observation(
                provider_operation_id="jules-1",
                raw_state={"state": legacy_status},
                observed_at="2026-08-24T01:30:00Z",
            )
            self.assertEqual(jules.mapped_state, ControllerState.UNCERTAIN)
            self.assertEqual(jules.uncertainty_reason, "JULES_STATUS_UNKNOWN")

    def test_success_is_only_a_terminal_claim_not_independent_verification(self):
        for observation in (
            map_jules_observation(
                provider_operation_id="jules-1",
                raw_state={"state": "COMPLETED"},
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

    def test_codex_completion_without_explicit_result_fails_closed(self):
        for status in ("done", "completed"):
            observation = map_codex_observation(
                provider_operation_id="codex-1",
                raw_state={"status": status},
                observed_at="2026-08-24T01:35:00Z",
            )
            self.assertEqual(observation.mapped_state, ControllerState.UNCERTAIN)
            self.assertEqual(observation.terminal_claim, TerminalClaim.NONE)
            self.assertEqual(observation.uncertainty_reason, "CODEX_STATE_UNKNOWN")

    def test_failure_maps_to_blocked_terminal_claim(self):
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"state": "FAILED"},
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

    def test_unknown_states_fail_closed_to_uncertain_without_echoing_unknown_text(self):
        secret = "Bearer-super-secret"
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"state": secret},
            observed_at="2026-08-24T01:35:00Z",
        )
        codex = map_codex_observation(
            provider_operation_id="codex-1",
            raw_state={"status": "mystery", "reason": secret, "result": secret},
            observed_at="2026-08-24T01:35:00Z",
        )
        self.assertEqual(jules.mapped_state, ControllerState.UNCERTAIN)
        self.assertEqual(jules.uncertainty_reason, "JULES_STATUS_UNKNOWN")
        self.assertEqual(codex.mapped_state, ControllerState.UNCERTAIN)
        self.assertEqual(codex.uncertainty_reason, "CODEX_STATE_UNKNOWN")
        for observation in (jules, codex):
            serialized = repr(observation.to_dict())
            self.assertNotIn(secret, serialized)
            self.assertNotIn("mystery", serialized)

    def test_missing_or_malformed_states_fail_closed(self):
        cases = (
            map_jules_observation(provider_operation_id="jules-1", raw_state={}, observed_at="2026-08-24T01:35:00Z"),
            map_jules_observation(provider_operation_id="jules-1", raw_state="not-a-mapping", observed_at="2026-08-24T01:35:00Z"),
            map_codex_observation(provider_operation_id="codex-1", raw_state={}, observed_at="2026-08-24T01:35:00Z"),
            map_codex_observation(provider_operation_id="codex-1", raw_state=None, observed_at="2026-08-24T01:35:00Z"),
        )
        for observation in cases:
            self.assertEqual(observation.mapped_state, ControllerState.UNCERTAIN)
            self.assertIsNotNone(observation.uncertainty_reason)

    def test_generic_user_wait_does_not_masquerade_as_plan_approval(self):
        jules = map_jules_observation(
            provider_operation_id="jules-1",
            raw_state={"state": "AWAITING_USER_FEEDBACK"},
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

    def test_arbitrary_provider_payload_is_not_retained_in_normalized_evidence(self):
        raw_jules = {
            "state": "IN_PROGRESS",
            "access_token": "top-secret-token",
            "url": "https://provider.example/callback?access_token=url-secret",
            "headers": {"X-Custom": "Bearer header-secret"},
            "nested": {"safe": "not-needed-for-normalized-evidence"},
        }
        raw_codex = {
            "status": "running",
            "access_token": "top-secret-token",
            "url": "https://provider.example/callback?access_token=url-secret",
            "headers": {"X-Custom": "Bearer header-secret"},
            "nested": {"safe": "not-needed-for-normalized-evidence"},
        }
        for mapper, operation_id, raw in (
            (map_jules_observation, "jules-1", raw_jules),
            (map_codex_observation, "codex-1", raw_codex),
        ):
            observation = mapper(
                provider_operation_id=operation_id,
                raw_state=raw,
                observed_at="2026-08-24T01:35:00Z",
            )
            retained = repr(observation.to_dict()["provider_raw_state"])
            for secret in ("top-secret-token", "url-secret", "header-secret"):
                self.assertNotIn(secret, retained)
            self.assertNotIn("provider.example", retained)
            self.assertNotIn("not-needed-for-normalized-evidence", retained)


if __name__ == "__main__":
    unittest.main()
