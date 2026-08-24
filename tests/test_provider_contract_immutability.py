import unittest

from agent_controller.provider_contract import (
    AgentObservation,
    ControllerState,
    ObjectiveScope,
    TaskBinding,
)


class TestProviderContractImmutability(unittest.TestCase):
    def test_task_scope_and_effects_do_not_follow_mutated_input_lists(self):
        allowed_paths = ["agent_controller/**"]
        denied_paths = ["secrets/**"]
        allowed_effects = ["CREATE_COMMIT"]
        forbidden_effects = ["MERGE"]

        task = TaskBinding(
            controller_task_id="task-1",
            operation_id="op-1",
            provider="jules",
            repo="owner/repo",
            expected_start_ref="refs/heads/main",
            expected_start_sha="start-sha",
            objective_scope=ObjectiveScope(
                allowed_paths=allowed_paths,
                denied_paths=denied_paths,
            ),
            requested_capability="IMPLEMENT",
            allowed_effects=allowed_effects,
            forbidden_effects=forbidden_effects,
            approval_policy_id="policy-1",
            created_at="2026-08-24T01:00:00Z",
        )

        allowed_paths.append("**")
        denied_paths.clear()
        allowed_effects.append("MERGE")
        forbidden_effects.clear()

        self.assertEqual(task.objective_scope.allowed_paths, ("agent_controller/**",))
        self.assertEqual(task.objective_scope.denied_paths, ("secrets/**",))
        self.assertEqual(task.allowed_effects, ("CREATE_COMMIT",))
        self.assertEqual(task.forbidden_effects, ("MERGE",))

    def test_observation_raw_state_is_deeply_detached_and_immutable(self):
        nested = {"status": "WORKING", "items": [{"value": "original"}]}
        observation = AgentObservation(
            provider="jules",
            provider_operation_id="provider-op-1",
            observed_at="2026-08-24T01:00:00Z",
            provider_updated_at=None,
            provider_raw_state=nested,
            mapped_state=ControllerState.EXECUTING,
        )

        nested["status"] = "FAILED"
        nested["items"][0]["value"] = "mutated"

        self.assertEqual(observation.provider_raw_state["status"], "WORKING")
        self.assertEqual(observation.provider_raw_state["items"][0]["value"], "original")
        with self.assertRaises(TypeError):
            observation.provider_raw_state["status"] = "FAILED"
        with self.assertRaises(TypeError):
            observation.provider_raw_state["items"][0]["value"] = "mutated"


if __name__ == "__main__":
    unittest.main()
