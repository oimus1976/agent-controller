import json
import os
import tempfile
import unittest

from agent_controller.approval_consumption import validate_and_consume_human_approval
from agent_controller.approval_contract import ApprovalBinding, ApprovalResult
from agent_controller.approval_service import TrustedApprovalIngress
from agent_controller.provider_contract import ObjectiveScope, TaskBinding


class FakeSource:
    def __init__(self, value):
        self.value = value

    def get_approval(self, approval_id):
        return self.value if approval_id == self.value.approval_id else None


class FakeTargetReader:
    def __init__(self, facts=None, error=None):
        self.facts = facts
        self.error = error
        self.calls = []

    def get_target_facts(self, *, repo, target_kind, target_id):
        self.calls.append((repo, target_kind, target_id))
        if self.error is not None:
            raise self.error
        return self.facts


def task(provider="jules"):
    return TaskBinding(
        controller_task_id="task-17",
        operation_id="op-17",
        provider=provider,
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


def approval(provider="jules"):
    return ApprovalBinding(
        approval_id="approval-1",
        approval_policy_id="policy-l3",
        controller_task_id="task-17",
        operation_id="op-17",
        provider=provider,
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


def fresh_facts(**overrides):
    data = {
        "repo": "oimus1976/agent-controller",
        "target_kind": "PULL_REQUEST",
        "target_id": "15",
        "head_sha": "head-sha",
    }
    data.update(overrides)
    return data


class TestApprovalConsumption(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tempdir.name, "ledger.json")

    def tearDown(self):
        self.tempdir.cleanup()

    def run_flow(self, candidate=None, target_task=None, reader=None, receipt_id="receipt-1"):
        candidate = candidate or approval()
        return validate_and_consume_human_approval(
            ingress=TrustedApprovalIngress(
                source_name="trusted-chat-control-plane",
                source=FakeSource(candidate),
            ),
            approval_id=candidate.approval_id,
            task=target_task or task(),
            expected_effect="MERGE",
            expected_target_kind="PULL_REQUEST",
            expected_target_id="15",
            expected_head_sha="head-sha",
            target_reader=reader or FakeTargetReader(fresh_facts()),
            ledger_path=self.ledger,
            now="2026-08-24T06:30:00Z",
            receipt_id=receipt_id,
        )

    def test_fresh_target_consumes_once_without_executing_effect(self):
        result = self.run_flow()
        self.assertTrue(result.validation.valid)
        self.assertEqual(result.consumption.result, ApprovalResult.PASS)
        with open(self.ledger, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["status"], "CONSUMED")

    def test_head_changed_after_approval_is_stale_and_not_consumed(self):
        result = self.run_flow(reader=FakeTargetReader(fresh_facts(head_sha="new-head")))
        self.assertFalse(result.validation.valid)
        self.assertEqual(result.validation.result, ApprovalResult.STALE)
        self.assertEqual(result.validation.reason, "TARGET_HEAD_STALE")
        self.assertIsNone(result.consumption)
        self.assertFalse(os.path.exists(self.ledger))

    def test_other_target_fact_changes_are_stale_and_not_consumed(self):
        cases = (
            (fresh_facts(repo="other/repo"), "TARGET_REPO_STALE"),
            (fresh_facts(target_kind="REPOSITORY_REF"), "TARGET_KIND_STALE"),
            (fresh_facts(target_id="16"), "TARGET_ID_STALE"),
        )
        for facts, reason in cases:
            with self.subTest(reason=reason):
                path = self.ledger + reason
                result = validate_and_consume_human_approval(
                    ingress=TrustedApprovalIngress("trusted-chat-control-plane", FakeSource(approval())),
                    approval_id="approval-1",
                    task=task(),
                    expected_effect="MERGE",
                    expected_target_kind="PULL_REQUEST",
                    expected_target_id="15",
                    expected_head_sha="head-sha",
                    target_reader=FakeTargetReader(facts),
                    ledger_path=path,
                    now="2026-08-24T06:30:00Z",
                    receipt_id="receipt-1",
                )
                self.assertEqual(result.validation.result, ApprovalResult.STALE)
                self.assertEqual(result.validation.reason, reason)
                self.assertFalse(os.path.exists(path))

    def test_target_read_uncertainty_is_not_consumed(self):
        result = self.run_flow(reader=FakeTargetReader(error=RuntimeError("read")))
        self.assertEqual(result.validation.result, ApprovalResult.UNCERTAIN)
        self.assertEqual(result.validation.reason, "TARGET_READ_UNCERTAIN")
        self.assertFalse(os.path.exists(self.ledger))

    def test_invalid_target_payload_is_uncertain_and_not_consumed(self):
        result = self.run_flow(reader=FakeTargetReader(facts="not-a-mapping"))
        self.assertEqual(result.validation.result, ApprovalResult.UNCERTAIN)
        self.assertEqual(result.validation.reason, "TARGET_FACTS_INVALID")
        self.assertFalse(os.path.exists(self.ledger))

    def test_repeated_fresh_consume_is_replayed(self):
        first = self.run_flow(receipt_id="receipt-1")
        second = self.run_flow(receipt_id="receipt-2")
        self.assertEqual(first.consumption.result, ApprovalResult.PASS)
        self.assertEqual(second.validation.result, ApprovalResult.REPLAYED)
        self.assertEqual(second.consumption.result, ApprovalResult.REPLAYED)

    def test_same_flow_supports_codex_bound_operation(self):
        result = self.run_flow(candidate=approval(provider="codex"), target_task=task(provider="codex"))
        self.assertTrue(result.validation.valid)
        self.assertEqual(result.consumption.result, ApprovalResult.PASS)


if __name__ == "__main__":
    unittest.main()
