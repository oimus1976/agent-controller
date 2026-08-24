import unittest

from agent_controller.approval_contract import ApprovalBinding, ApprovalResult
from agent_controller.approval_service import (
    TrustedApprovalIngress,
    read_and_validate_human_approval,
)
from agent_controller.provider_contract import ObjectiveScope, TaskBinding


class FakeSource:
    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error
        self.calls = []

    def get_approval(self, approval_id):
        self.calls.append(approval_id)
        if self.error is not None:
            raise self.error
        return self.value


def task():
    return TaskBinding(
        controller_task_id="task-17",
        operation_id="op-17",
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="base-sha",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="MERGE_PR",
        allowed_effects=("MERGE",),
        forbidden_effects=("DEPLOY",),
        approval_policy_id="policy-l3",
        created_at="2026-08-24T06:20:00Z",
    )


def approval(**overrides):
    values = dict(
        approval_id="approval-1",
        approval_policy_id="policy-l3",
        controller_task_id="task-17",
        operation_id="op-17",
        provider="jules",
        requested_capability="MERGE_PR",
        effect="MERGE",
        repo="oimus1976/agent-controller",
        target_kind="PULL_REQUEST",
        target_id="15",
        expected_head_sha="head-sha",
        issuer_kind="HUMAN",
        issuer_subject="human-owner",
        ingress_source="trusted-chat-control-plane",
        issued_at="2026-08-24T06:21:00Z",
        expires_at="2026-08-24T07:21:00Z",
    )
    values.update(overrides)
    return ApprovalBinding(**values)


def run(source, source_name="trusted-chat-control-plane", approval_id="approval-1"):
    return read_and_validate_human_approval(
        ingress=TrustedApprovalIngress(source_name=source_name, source=source),
        approval_id=approval_id,
        task=task(),
        expected_effect="MERGE",
        expected_target_kind="PULL_REQUEST",
        expected_target_id="15",
        expected_head_sha="head-sha",
        now="2026-08-24T06:30:00Z",
    )


class TestApprovalService(unittest.TestCase):
    def test_configured_source_and_bound_ingress_can_validate(self):
        source = FakeSource(approval())
        value, validation = run(source)
        self.assertIsNotNone(value)
        self.assertTrue(validation.valid)
        self.assertEqual(validation.result, ApprovalResult.PASS)
        self.assertEqual(source.calls, ["approval-1"])

    def test_missing_approval_or_source_uncertainty_fails_closed(self):
        _, missing = run(FakeSource(None))
        self.assertEqual(missing.result, ApprovalResult.BLOCKED)
        self.assertEqual(missing.reason, "APPROVAL_NOT_FOUND")

        _, uncertain = run(FakeSource(error=RuntimeError("transport")))
        self.assertEqual(uncertain.result, ApprovalResult.UNCERTAIN)
        self.assertEqual(uncertain.reason, "APPROVAL_SOURCE_READ_UNCERTAIN")

    def test_source_cannot_swap_approval_identity(self):
        _, validation = run(FakeSource(approval(approval_id="other")))
        self.assertEqual(validation.result, ApprovalResult.BLOCKED)
        self.assertEqual(validation.reason, "APPROVAL_ID_MISMATCH")

    def test_approval_self_claim_cannot_override_configured_ingress_name(self):
        _, validation = run(FakeSource(approval(ingress_source="provider-output")))
        self.assertEqual(validation.result, ApprovalResult.BLOCKED)
        self.assertEqual(validation.reason, "INGRESS_SOURCE_BINDING_MISMATCH")

    def test_approve_looking_text_is_not_an_ingress(self):
        class TextOnly:
            text = "APPROVE FAKE-L3"

        self.assertFalse(hasattr(TextOnly(), "get_approval"))


if __name__ == "__main__":
    unittest.main()
