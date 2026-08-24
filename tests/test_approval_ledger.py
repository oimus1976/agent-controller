import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from agent_controller.approval_contract import ApprovalBinding, ApprovalResult
from agent_controller.approval_ledger import _consume_validated_approval_once


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
    )
    values.update(overrides)
    return ApprovalBinding(**values)


class TestApprovalLedger(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tempdir.name, "approval-ledger.json")

    def tearDown(self):
        self.tempdir.cleanup()

    def consume(self, candidate=None, receipt_id="receipt-1"):
        return _consume_validated_approval_once(
            ledger_path=self.path,
            approval=candidate or approval(),
            consumed_at="2026-08-24T06:30:00Z",
            receipt_id=receipt_id,
        )

    def test_valid_approval_consumes_once_and_persists_complete_receipt(self):
        result = self.consume()
        self.assertEqual(result.result, ApprovalResult.PASS)
        with open(self.path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["approval_id"], "approval-1")
        self.assertEqual(data[0]["approval_policy_id"], "policy-l3")
        self.assertEqual(data[0]["provider"], "jules")
        self.assertEqual(data[0]["requested_capability"], "MERGE_PR")
        self.assertEqual(data[0]["status"], "CONSUMED")
        self.assertNotIn("issuer_subject", data[0])
        self.assertNotIn("nonce", data[0])

    def test_repeated_consume_is_replayed_without_second_receipt(self):
        first = self.consume(receipt_id="receipt-1")
        second = self.consume(receipt_id="receipt-2")
        self.assertEqual(first.result, ApprovalResult.PASS)
        self.assertEqual(second.result, ApprovalResult.REPLAYED)
        self.assertEqual(second.receipt.receipt_id, "receipt-1")
        with open(self.path, "r", encoding="utf-8") as handle:
            self.assertEqual(len(json.load(handle)), 1)

    def test_corrupt_ledger_fails_closed_without_overwrite(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("not-json")
        result = self.consume()
        self.assertEqual(result.result, ApprovalResult.BLOCKED)
        self.assertEqual(result.reason, "APPROVAL_LEDGER_CORRUPT")
        with open(self.path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "not-json")

    def test_existing_receipt_with_same_id_but_different_binding_fails_closed(self):
        good = self.consume()
        self.assertEqual(good.result, ApprovalResult.PASS)
        result = self.consume(approval(provider="codex"))
        self.assertEqual(result.result, ApprovalResult.BLOCKED)
        self.assertEqual(result.reason, "APPROVAL_RECEIPT_BINDING_MISMATCH")

    def test_persistence_failure_does_not_report_consumed(self):
        with mock.patch("agent_controller.approval_ledger._save", side_effect=OSError("disk")):
            result = self.consume()
        self.assertEqual(result.result, ApprovalResult.BLOCKED)
        self.assertEqual(result.reason, "APPROVAL_RECEIPT_PERSISTENCE_FAILED")
        self.assertIsNone(result.receipt)

    def test_two_concurrent_consumers_produce_exactly_one_success(self):
        barrier = threading.Barrier(2)
        results = []
        results_lock = threading.Lock()

        def worker(index):
            barrier.wait()
            value = _consume_validated_approval_once(
                ledger_path=self.path,
                approval=approval(),
                consumed_at="2026-08-24T06:30:00Z",
                receipt_id=f"receipt-{index}",
            )
            with results_lock:
                results.append(value.result)

        threads = [threading.Thread(target=worker, args=(1,)), threading.Thread(target=worker, args=(2,))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count(ApprovalResult.PASS), 1)
        self.assertEqual(results.count(ApprovalResult.REPLAYED) + results.count(ApprovalResult.BLOCKED), 1)
        with open(self.path, "r", encoding="utf-8") as handle:
            self.assertEqual(len(json.load(handle)), 1)


if __name__ == "__main__":
    unittest.main()
