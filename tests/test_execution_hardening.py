import json
import os
import tempfile
import unittest

from agent_controller.approval_contract import ApprovalReceipt
from agent_controller.approval_store import ApprovalLedgerStore
from agent_controller.execution_contract import ExecutionClaimResult
from agent_controller.execution_handoff import validate_and_claim_execution
from agent_controller.execution_store import ExecutionClaimStore
from agent_controller.provider_contract import ObjectiveScope, TaskBinding


def task():
    return TaskBinding(
        controller_task_id="task-20",
        operation_id="op-20",
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="base-sha",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability="MERGE_PR",
        allowed_effects=("MERGE",),
        forbidden_effects=("DEPLOY",),
        approval_policy_id="policy-l3",
        created_at="2026-08-24T08:18:00Z",
    )


def receipt_dict():
    return ApprovalReceipt(
        approval_id="approval-20",
        approval_policy_id="policy-l3",
        controller_task_id="task-20",
        operation_id="op-20",
        provider="jules",
        requested_capability="MERGE_PR",
        effect="MERGE",
        repo="oimus1976/agent-controller",
        target_kind="PULL_REQUEST",
        target_id="18",
        expected_head_sha="head-sha",
        consumed_at="2026-08-24T08:20:00Z",
        receipt_id="approval-receipt-20",
    ).to_dict()


class Reader:
    def get_target_facts(self, *, repo, target_kind, target_id):
        return {
            "repo": repo,
            "target_kind": target_kind,
            "target_id": target_id,
            "head_sha": "head-sha",
        }


class TestExecutionHardening(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.approvals = ApprovalLedgerStore(os.path.join(self.tempdir.name, "approvals.json"))
        self.executions = ExecutionClaimStore(os.path.join(self.tempdir.name, "executions.json"))

    def tearDown(self):
        self.tempdir.cleanup()

    def claim(self):
        return validate_and_claim_execution(
            approval_store=self.approvals,
            approval_receipt_id="approval-receipt-20",
            task=task(),
            expected_effect="MERGE",
            expected_target_kind="PULL_REQUEST",
            expected_target_id="18",
            expected_head_sha="head-sha",
            target_reader=Reader(),
            execution_store=self.executions,
            execution_claim_id="claim-20",
            now="2026-08-24T08:21:00Z",
        )

    def test_malformed_authority_field_in_approval_ledger_fails_closed(self):
        item = receipt_dict()
        item["effect"] = ["MERGE"]
        with open(self.approvals.ledger_path, "w", encoding="utf-8") as handle:
            json.dump([item], handle)
        result = self.claim()
        self.assertEqual(result.result, ExecutionClaimResult.BLOCKED)
        self.assertEqual(result.reason, "APPROVAL_LEDGER_CORRUPT")
        self.assertFalse(os.path.exists(self.executions.ledger_path))

    def test_malformed_authority_field_in_execution_ledger_fails_closed(self):
        with open(self.approvals.ledger_path, "w", encoding="utf-8") as handle:
            json.dump([receipt_dict()], handle)
        first = self.claim()
        self.assertEqual(first.result, ExecutionClaimResult.PASS)

        with open(self.executions.ledger_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data[0]["requested_capability"] = {"name": "MERGE_PR"}
        with open(self.executions.ledger_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

        result = self.claim()
        self.assertEqual(result.result, ExecutionClaimResult.BLOCKED)
        self.assertEqual(result.reason, "EXECUTION_LEDGER_CORRUPT")

    def test_wrong_store_types_fail_closed_before_target_read(self):
        result = validate_and_claim_execution(
            approval_store=object(),
            approval_receipt_id="approval-receipt-20",
            task=task(),
            expected_effect="MERGE",
            expected_target_kind="PULL_REQUEST",
            expected_target_id="18",
            expected_head_sha="head-sha",
            target_reader=Reader(),
            execution_store=self.executions,
            execution_claim_id="claim-20",
            now="2026-08-24T08:21:00Z",
        )
        self.assertEqual(result.result, ExecutionClaimResult.UNCERTAIN)
        self.assertEqual(result.reason, "APPROVAL_STORE_INVALID")


if __name__ == "__main__":
    unittest.main()
