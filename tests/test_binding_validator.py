import unittest

from agent_controller.binding_validator import (
    validate_artifact_binding,
    validate_evidence_chain,
    validate_observation_binding,
    validate_operation_binding,
)
from agent_controller.provider_contract import (
    AgentObservation,
    ArtifactEvidence,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)


def task(provider="jules"):
    return TaskBinding(
        controller_task_id="task-1",
        operation_id="operation-1",
        provider=provider,
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="start-sha",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",), denied_paths=None),
        requested_capability="IMPLEMENT",
        allowed_effects=("CREATE_COMMIT",),
        forbidden_effects=("MERGE",),
        approval_policy_id="policy-1",
        created_at="2026-08-24T01:00:00Z",
    )


def operation(provider="jules", provider_operation_id="provider-op-1"):
    return ProviderOperationRef(
        provider=provider,
        provider_operation_id=provider_operation_id,
        provider_url=None,
        controller_task_id="task-1",
        operation_id="operation-1",
    )


def observation(provider="jules", provider_operation_id="provider-op-1"):
    return AgentObservation(
        provider=provider,
        provider_operation_id=provider_operation_id,
        observed_at="2026-08-24T01:01:00Z",
        provider_updated_at=None,
        provider_raw_state={"status": "WORKING"},
        mapped_state=ControllerState.EXECUTING,
        awaiting_input=AwaitingInput.NONE,
        terminal_claim=TerminalClaim.NONE,
    )


def artifact(provider="jules", provider_operation_id="provider-op-1"):
    return ArtifactEvidence(
        provider=provider,
        provider_operation_id=provider_operation_id,
        artifact_kind="commit",
        provider_artifact_id="artifact-1",
        provider_reported_ref="refs/heads/work",
        provider_reported_sha="head-sha",
        content_hash=None,
        observed_at="2026-08-24T01:02:00Z",
        freshness_basis="provider_report",
    )


class TestBindingValidator(unittest.TestCase):
    def test_valid_complete_chain_passes(self):
        result = validate_evidence_chain(
            task=task(), operation=operation(), observation=observation(), artifact=artifact()
        )
        self.assertTrue(result.valid)
        self.assertIsNone(result.reason)

    def test_controller_task_id_mismatch_fails_closed(self):
        op = ProviderOperationRef(
            provider="jules",
            provider_operation_id="provider-op-1",
            provider_url=None,
            controller_task_id="other-task",
            operation_id="operation-1",
        )
        result = validate_operation_binding(task=task(), operation=op)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "CONTROLLER_TASK_ID_MISMATCH")

    def test_controller_operation_id_mismatch_fails_closed(self):
        op = ProviderOperationRef(
            provider="jules",
            provider_operation_id="provider-op-1",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="other-operation",
        )
        result = validate_operation_binding(task=task(), operation=op)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "OPERATION_ID_MISMATCH")

    def test_task_provider_mismatch_fails_closed(self):
        result = validate_operation_binding(task=task("jules"), operation=operation("codex"))
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "PROVIDER_MISMATCH")

    def test_missing_provider_operation_id_fails_closed(self):
        result = validate_operation_binding(task=task(), operation=operation(provider_operation_id=""))
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "PROVIDER_OPERATION_ID_MISSING")

    def test_observation_provider_mismatch_fails_closed(self):
        result = validate_observation_binding(
            operation=operation("jules"), observation=observation("codex")
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "OBSERVATION_PROVIDER_MISMATCH")

    def test_observation_operation_id_mismatch_fails_closed(self):
        result = validate_observation_binding(
            operation=operation(), observation=observation(provider_operation_id="other-op")
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "OBSERVATION_OPERATION_ID_MISMATCH")

    def test_artifact_provider_mismatch_fails_closed(self):
        result = validate_artifact_binding(
            operation=operation("jules"), artifact=artifact("codex")
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ARTIFACT_PROVIDER_MISMATCH")

    def test_artifact_operation_id_mismatch_fails_closed(self):
        result = validate_artifact_binding(
            operation=operation(), artifact=artifact(provider_operation_id="other-op")
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ARTIFACT_OPERATION_ID_MISMATCH")

    def test_complete_chain_reports_first_mismatch_deterministically(self):
        op = ProviderOperationRef(
            provider="codex",
            provider_operation_id="provider-op-1",
            provider_url=None,
            controller_task_id="other-task",
            operation_id="operation-1",
        )
        result = validate_evidence_chain(
            task=task("jules"), operation=op, observation=observation("codex"), artifact=artifact("codex")
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "CONTROLLER_TASK_ID_MISMATCH")


if __name__ == "__main__":
    unittest.main()
