import json
import os
import tempfile
import unittest

from agent_controller.approval_consumption import validate_and_consume_human_approval
from agent_controller.approval_contract import ApprovalBinding, ApprovalResult
from agent_controller.approval_ledger import consume_approval_once
from agent_controller.approval_service import TrustedApprovalIngress
from agent_controller.approval_validator import validate_approval_binding
from agent_controller.provider_contract import ObjectiveScope, TaskBinding


def make_task(*, allowed=("MERGE",), forbidden=("DEPLOY",)):
    return TaskBinding(
        controller_task_id="task-17",
        operation_id="op-17",
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="base-sha",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="MERGE_PR",
        allowed_effects=allowed,
        forbidden_effects=forbidden,
        approval_policy_id="policy-l3",
        created_at="2026-08-24T06:20:00Z",
    )


def make_approval(**overrides):
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
    )
    values.update(overrides)
    return ApprovalBinding(**values)


class Source:
    def __init__(self, value):
        self.value = value

    def get_approval(self, approval_id):
        return self.value


class Reader:
    def __init__(self, facts):
        self.facts = facts

    def get_target_facts(self, *, repo, target_kind, target_id):
        return self.facts


class TestApprovalHardening(unittest.TestCase):
    def test_effect_must_be_allowed_by_task(self):
        result = validate_approval_binding(
            task=make_task(allowed=("READY",)),
            approval=make_approval(),
            expected_effect="MERGE",
            expected_target_kind="PULL_REQUEST",
            expected_target_id="15",
            expected_head_sha="head-sha",
            trusted_ingress_sources=("trusted-chat-control-plane",),
            now="2026-08-24T06:30:00Z",
        )
        self.assertEqual(result.result, ApprovalResult.BLOCKED)
        self.assertEqual(result.reason, "EFFECT_NOT_ALLOWED_BY_TASK")

    def test_forbidden_effect_blocks_even_if_also_allowlisted(self):
        result = validate_approval_binding(
            task=make_task(allowed=("MERGE",), forbidden=("MERGE",)),
            approval=make_approval(),
            expected_effect="MERGE",
            expected_target_kind="PULL_REQUEST",
            expected_target_id="15",
            expected_head_sha="head-sha",
            trusted_ingress_sources=("trusted-chat-control-plane",),
            now="2026-08-24T06:30:00Z",
        )
        self.assertEqual(result.result, ApprovalResult.BLOCKED)
        self.assertEqual(result.reason, "EFFECT_FORBIDDEN_BY_TASK")

    def test_missing_objective_fact_is_uncertain_not_stale(self):
        with tempfile.TemporaryDirectory() as tempdir:
            result = validate_and_consume_human_approval(
                ingress=TrustedApprovalIngress("trusted-chat-control-plane", Source(make_approval())),
                approval_id="approval-1",
                task=make_task(),
                expected_effect="MERGE",
                expected_target_kind="PULL_REQUEST",
                expected_target_id="15",
                expected_head_sha="head-sha",
                target_reader=Reader({
                    "repo": "oimus1976/agent-controller",
                    "target_kind": "PULL_REQUEST",
                    "target_id": "15",
                }),
                ledger_path=os.path.join(tempdir, "ledger.json"),
                now="2026-08-24T06:30:00Z",
                receipt_id="receipt-1",
            )
            self.assertEqual(result.validation.result, ApprovalResult.UNCERTAIN)
            self.assertEqual(result.validation.reason, "TARGET_FACT_MISSING:head_sha")

    def test_receipt_id_cannot_be_reused_for_different_approval(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = os.path.join(tempdir, "ledger.json")
            first = consume_approval_once(
                ledger_path=path,
                approval=make_approval(approval_id="approval-1"),
                consumed_at="2026-08-24T06:30:00Z",
                receipt_id="receipt-shared",
            )
            second = consume_approval_once(
                ledger_path=path,
                approval=make_approval(approval_id="approval-2", controller_task_id="task-18"),
                consumed_at="2026-08-24T06:31:00Z",
                receipt_id="receipt-shared",
            )
            self.assertEqual(first.result, ApprovalResult.PASS)
            self.assertEqual(second.result, ApprovalResult.BLOCKED)
            self.assertEqual(second.reason, "RECEIPT_ID_REUSED")
            with open(path, "r", encoding="utf-8") as handle:
                self.assertEqual(len(json.load(handle)), 1)


if __name__ == "__main__":
    unittest.main()
