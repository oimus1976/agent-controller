import inspect
import json
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from unittest import mock

import agent_controller.execution_contract as execution_contract
import agent_controller.execution_handoff as execution_handoff
import agent_controller.execution_ledger as execution_ledger
import agent_controller.execution_store as execution_store
from agent_controller.approval_contract import ApprovalReceipt
from agent_controller.execution_contract import ExecutionClaimResult
from agent_controller.execution_handoff import validate_and_claim_execution
from agent_controller.execution_ledger import _claim_execution_once
from agent_controller.execution_store import ExecutionClaimStore
from agent_controller.provider_contract import ObjectiveScope, TaskBinding


def task(provider="jules", capability="MERGE_PR", effect="MERGE"):
    return TaskBinding(
        controller_task_id="task-20",
        operation_id="op-20",
        provider=provider,
        repo="oimus1976/agent-controller",
        expected_start_ref="refs/heads/main",
        expected_start_sha="base-sha",
        objective_scope=ObjectiveScope(allowed_paths=("agent_controller/**",)),
        requested_capability=capability,
        allowed_effects=(effect,),
        forbidden_effects=("DEPLOY",),
        approval_policy_id="policy-l3",
        created_at="2026-08-24T08:18:00Z",
    )


def receipt(provider="jules", **overrides):
    values = dict(
        approval_id="approval-20",
        approval_policy_id="policy-l3",
        controller_task_id="task-20",
        operation_id="op-20",
        provider=provider,
        requested_capability="MERGE_PR",
        effect="MERGE",
        repo="oimus1976/agent-controller",
        target_kind="PULL_REQUEST",
        target_id="18",
        expected_head_sha="head-sha",
        consumed_at="2026-08-24T08:20:00Z",
        receipt_id="approval-receipt-20",
        status="CONSUMED",
    )
    values.update(overrides)
    return ApprovalReceipt(**values)


class Reader:
    def __init__(self, facts=None, error=None):
        self.facts = facts
        self.error = error

    def get_target_facts(self, *, repo, target_kind, target_id):
        if self.error:
            raise self.error
        return self.facts


def fresh(**overrides):
    facts = {
        "repo": "oimus1976/agent-controller",
        "target_kind": "PULL_REQUEST",
        "target_id": "18",
        "head_sha": "head-sha",
    }
    facts.update(overrides)
    return facts


class TestExecutionHandoff(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = ExecutionClaimStore(os.path.join(self.tempdir.name, "claims.json"))

    def tearDown(self):
        self.tempdir.cleanup()

    def run_flow(self, candidate=None, bound_task=None, reader=None, claim_id="claim-20"):
        return validate_and_claim_execution(
            receipt=candidate or receipt(),
            task=bound_task or task(),
            expected_effect="MERGE",
            expected_target_kind="PULL_REQUEST",
            expected_target_id="18",
            expected_head_sha="head-sha",
            target_reader=reader or Reader(fresh()),
            execution_store=self.store,
            execution_claim_id=claim_id,
            now="2026-08-24T08:21:00Z",
        )

    def test_exact_consumed_receipt_and_fresh_target_claims_once(self):
        result = self.run_flow()
        self.assertTrue(result.valid)
        self.assertEqual(result.result, ExecutionClaimResult.PASS)
        self.assertEqual(result.claim.approval_receipt_id, "approval-receipt-20")
        with open(self.store.ledger_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(len(data), 1)
        self.assertNotIn("issuer_subject", data[0])
        self.assertNotIn("nonce", data[0])

    def test_receipt_must_be_consumed(self):
        result = self.run_flow(receipt(status="AVAILABLE"))
        self.assertEqual(result.result, ExecutionClaimResult.BLOCKED)
        self.assertFalse(os.path.exists(self.store.ledger_path))

    def test_exact_binding_mismatch_blocks(self):
        cases = (
            (receipt(approval_policy_id="other"), "APPROVAL_POLICY_MISMATCH"),
            (receipt(controller_task_id="other"), "CONTROLLER_TASK_ID_MISMATCH"),
            (receipt(operation_id="other"), "OPERATION_ID_MISMATCH"),
            (receipt(provider="codex"), "PROVIDER_MISMATCH"),
            (receipt(requested_capability="APPROVE_PLAN"), "CAPABILITY_MISMATCH"),
            (receipt(effect="READY"), "EFFECT_MISMATCH"),
            (receipt(repo="other/repo"), "REPO_MISMATCH"),
            (receipt(target_id="19"), "TARGET_ID_MISMATCH"),
            (receipt(expected_head_sha="old"), "EXPECTED_HEAD_MISMATCH"),
        )
        for candidate, reason in cases:
            with self.subTest(reason=reason):
                result = self.run_flow(candidate)
                self.assertEqual(result.result, ExecutionClaimResult.BLOCKED)
                self.assertEqual(result.reason, reason)

    def test_task_effect_policy_cannot_be_widened(self):
        result = self.run_flow(bound_task=replace(task(), allowed_effects=("READY",)))
        self.assertEqual(result.reason, "EFFECT_NOT_ALLOWED_BY_TASK")
        result = self.run_flow(bound_task=replace(task(), forbidden_effects=("MERGE",)))
        self.assertEqual(result.reason, "EFFECT_FORBIDDEN_BY_TASK")

    def test_stale_or_uncertain_target_does_not_claim(self):
        stale = self.run_flow(reader=Reader(fresh(head_sha="new-head")))
        self.assertEqual(stale.result, ExecutionClaimResult.STALE)
        self.assertFalse(os.path.exists(self.store.ledger_path))

        uncertain = self.run_flow(reader=Reader(error=RuntimeError("read")))
        self.assertEqual(uncertain.result, ExecutionClaimResult.UNCERTAIN)
        self.assertFalse(os.path.exists(self.store.ledger_path))

        missing = self.run_flow(reader=Reader({"repo": "oimus1976/agent-controller", "target_kind": "PULL_REQUEST", "target_id": "18"}))
        self.assertEqual(missing.result, ExecutionClaimResult.UNCERTAIN)
        self.assertEqual(missing.reason, "TARGET_FACT_MISSING:head_sha")

    def test_repeated_claim_from_same_receipt_is_replayed(self):
        first = self.run_flow(claim_id="claim-1")
        second = self.run_flow(claim_id="claim-2")
        self.assertEqual(first.result, ExecutionClaimResult.PASS)
        self.assertEqual(second.result, ExecutionClaimResult.REPLAYED)
        self.assertEqual(second.claim.execution_claim_id, "claim-1")

    def test_claim_id_cannot_be_reused_for_another_receipt(self):
        first = self.run_flow(claim_id="shared")
        self.assertEqual(first.result, ExecutionClaimResult.PASS)
        other = receipt(approval_id="approval-21", receipt_id="approval-receipt-21")
        second = self.run_flow(other, claim_id="shared")
        self.assertEqual(second.result, ExecutionClaimResult.BLOCKED)
        self.assertEqual(second.reason, "EXECUTION_CLAIM_ID_REUSED")

    def test_corrupt_or_duplicate_ledger_fails_closed(self):
        with open(self.store.ledger_path, "w", encoding="utf-8") as handle:
            handle.write("not-json")
        result = self.run_flow()
        self.assertEqual(result.reason, "EXECUTION_LEDGER_CORRUPT")

        os.remove(self.store.ledger_path)
        good = self.run_flow(claim_id="claim-1")
        self.assertEqual(good.result, ExecutionClaimResult.PASS)
        with open(self.store.ledger_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        data.append(dict(data[0]))
        with open(self.store.ledger_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        result = self.run_flow(claim_id="claim-2")
        self.assertEqual(result.reason, "EXECUTION_LEDGER_CORRUPT")

    def test_persistence_failure_does_not_report_pass(self):
        with mock.patch("agent_controller.execution_ledger._save", side_effect=OSError("disk")):
            result = self.run_flow()
        self.assertEqual(result.result, ExecutionClaimResult.BLOCKED)
        self.assertEqual(result.reason, "EXECUTION_CLAIM_PERSISTENCE_FAILED")

    def test_two_concurrent_low_level_claims_have_exactly_one_pass(self):
        path = os.path.join(self.tempdir.name, "concurrent.json")
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def worker(i):
            barrier.wait()
            value = _claim_execution_once(
                ledger_path=path,
                receipt=receipt(),
                execution_claim_id=f"claim-{i}",
                claimed_at="2026-08-24T08:21:00Z",
            )
            with lock:
                results.append(value.result)

        threads = [threading.Thread(target=worker, args=(1,)), threading.Thread(target=worker, args=(2,))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(ExecutionClaimResult.PASS), 1)
        self.assertEqual(len(results), 2)

    def test_store_identity_is_fixed_and_supported_api_has_no_path_override(self):
        self.assertEqual(self.store.ledger_path, os.path.realpath(os.path.abspath(self.store.ledger_path)))
        params = inspect.signature(validate_and_claim_execution).parameters
        self.assertIn("execution_store", params)
        self.assertNotIn("ledger_path", params)

    def test_codex_uses_same_core_and_provider_plan_cannot_satisfy_merge(self):
        codex = self.run_flow(candidate=receipt(provider="codex"), bound_task=task(provider="codex"))
        self.assertEqual(codex.result, ExecutionClaimResult.PASS)

        plan_receipt = receipt(requested_capability="APPROVE_PLAN", effect="PROVIDER_PLAN_APPROVAL")
        plan_task = task(capability="APPROVE_PLAN", effect="PROVIDER_PLAN_APPROVAL")
        result = self.run_flow(candidate=plan_receipt, bound_task=plan_task)
        self.assertEqual(result.reason, "EFFECT_MISMATCH")

    def test_pn3_public_surface_has_no_high_risk_effect_executor(self):
        modules = (execution_contract, execution_handoff, execution_ledger, execution_store)
        forbidden = {"merge", "merge_pr", "mark_ready", "ready", "deploy", "release", "approve_plan", "execute_owner_machine"}
        for module in modules:
            public = {
                name.lower() for name, value in vars(module).items()
                if not name.startswith("_")
                and (inspect.isfunction(value) or inspect.isclass(value))
                and getattr(value, "__module__", None) == module.__name__
            }
            self.assertTrue(public.isdisjoint(forbidden), (module.__name__, public))


if __name__ == "__main__":
    unittest.main()
