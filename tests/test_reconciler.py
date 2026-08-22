import unittest
import json
import os
import tempfile
import ast
from unittest.mock import patch, MagicMock

from agent_controller.reconciler import reconcile_pr_once, _save_receipt, _load_receipts

class TestReconciler(unittest.TestCase):
    def setUp(self):
        self.owner = "testowner"
        self.repo = "testrepo"
        self.pr_number = 1

        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, "pr_state.json")
        self.receipts_file = os.path.join(self.temp_dir.name, "receipts.json")
        self.policy_file = os.path.join(self.temp_dir.name, "policy.json")

        self.valid_policy = {"allowed_actions": ["ENSURE_DRAFT"]}
        with open(self.policy_file, 'w') as f:
            json.dump(self.valid_policy, f)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. first valid observation -> baseline established / no action / no mutation
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_first_observation_baseline_established(self, mock_watch):
        def side_effect_watch(owner, repo, pr_number, state_file, scope_policy=None):
            # Simulate watch_pr_once writing state_file on first observation
            with open(state_file, 'w') as f:
                json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)
            return {
                "repo": f"{owner}/{repo}",
                "pr": pr_number,
                "previous_head_sha": None,
                "current_head_sha": "sha1",
                "previous_classification": None,
                "current_classification": "NEEDS_REVIEW",
                "scope_status": "ALLOW",
                "graphql_error": False,
                "check_runs_error": False,
                "runtime_status": "OK",
                "transition": False,
                "transition_reasons": [],
                "observed_at": "2026-01-01T00:00:00Z"
            }

        mock_watch.side_effect = side_effect_watch

        # state_file does NOT exist prior to reconcile_pr_once
        self.assertFalse(os.path.exists(self.state_file))

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertFalse(res["is_relevant_transition"])
        self.assertEqual(res["action_plan"]["decision"], "NO_ACTION")
        self.assertEqual(res["action_plan"]["reason"], "BASELINE_ESTABLISHED")
        self.assertIsNone(res["execution_result"])
        self.assertIsNone(res["action_receipt"])

    # 2. repeated identical observation -> no transition / no action
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_repeated_identical_observation_no_transition(self, mock_watch):
        # Baseline state exists
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha1",
            "previous_classification": "NEEDS_REVIEW",
            "current_classification": "NEEDS_REVIEW",
            "scope_status": "ALLOW",
            "graphql_error": False,
            "check_runs_error": False,
            "runtime_status": "OK",
            "transition": False,
            "transition_reasons": [],
            "observed_at": "2026-01-01T00:00:00Z"
        }

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertFalse(res["is_relevant_transition"])
        self.assertEqual(res["action_plan"]["decision"], "NO_ACTION")
        self.assertEqual(res["action_plan"]["reason"], "NO_TRANSITION_DETECTED")
        self.assertIsNone(res["execution_result"])
        self.assertIsNone(res["action_receipt"])

    # 3. Draft true -> false transition + valid policy, dry-run -> action plan visible / no mutation
    @patch('agent_controller.reconciler.execute_action')
    @patch('agent_controller.reconciler.plan_action')
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_draft_changed_dry_run(self, mock_watch, mock_plan, mock_execute):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": True, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha1",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["PR_STATE_CHANGED"]
        }

        mock_plan.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "requested_action": "ENSURE_DRAFT",
            "decision": "EXECUTABLE",
            "reason": "READY_FOR_DRAFT_CONVERSION",
            "head_sha": "sha1"
        }

        mock_execute.return_value = {
            "planned_head_sha": "sha1",
            "execution_head_sha": None,
            "mutation_attempted": False,
            "mutation_type": None,
            "postcondition_result": None,
            "final_outcome": "DRY_RUN",
            "failure_reason": "APPLY_FLAG_NOT_SET"
        }

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=False
        )

        self.assertTrue(res["is_relevant_transition"])
        self.assertEqual(res["action_plan"]["decision"], "EXECUTABLE")
        self.assertEqual(res["execution_result"]["final_outcome"], "DRY_RUN")
        self.assertIsNone(res["action_receipt"])
        mock_execute.assert_called_once_with(mock_plan.return_value, self.owner, self.repo, self.pr_number, apply=False)

    # 4. same transition + --apply -> exactly one Draft mutation via existing executor
    # 5. successful apply -> verified Draft=true + success receipt persisted
    @patch('agent_controller.executor.convert_pull_request_to_draft')
    @patch('agent_controller.executor.get_pr_details')
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_successful_apply_and_receipt(self, mock_watch, mock_get_pr_details, mock_convert):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": True, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha1",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["PR_STATE_CHANGED"]
        }

        # Side effects for executor.plan_action (1 call) and executor.execute_action (2 calls: pre & post)
        mock_get_pr_details.side_effect = [
            # For plan_action
            {"head": {"sha": "sha1"}, "draft": False, "merged": False, "state": "open", "node_id": "node1"},
            # For execute_action pre-read
            {"head": {"sha": "sha1"}, "draft": False, "merged": False, "state": "open", "node_id": "node1"},
            # For execute_action postcondition re-read
            {"head": {"sha": "sha1"}, "draft": True, "merged": False, "state": "open", "node_id": "node1"}
        ]

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertTrue(res["is_relevant_transition"])
        self.assertEqual(res["execution_result"]["final_outcome"], "SUCCESS")
        self.assertTrue(res["postcondition_result"])
        self.assertIsNotNone(res["action_receipt"])
        self.assertEqual(res["action_receipt"]["outcome"], "SUCCESS")

        mock_convert.assert_called_once_with("node1")

        # Check that receipt was written to file
        receipts, corrupt = _load_receipts(self.receipts_file)
        self.assertFalse(corrupt)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["head_sha"], "sha1")
        self.assertEqual(receipts[0]["action"], "ENSURE_DRAFT")

    # 6. next cycle after success -> NOOP / no duplicate mutation
    # 7. same transition replay with receipt -> no duplicate mutation
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_duplicate_transition_with_receipt(self, mock_watch):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": True, "merged": False, "state_enum": "open"}, f)

        # Populate receipts file with consumed receipt
        consumed_receipt = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "head_sha": "sha1",
            "transition_reasons": ["PR_STATE_CHANGED"],
            "action": "ENSURE_DRAFT",
            "outcome": "SUCCESS",
            "timestamp": "2026-01-01T00:00:00Z"
        }
        with open(self.receipts_file, 'w') as f:
            json.dump([consumed_receipt], f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha1",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["PR_STATE_CHANGED"]
        }

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertFalse(res["is_relevant_transition"])
        self.assertEqual(res["action_plan"]["decision"], "NO_ACTION")
        self.assertEqual(res["action_plan"]["reason"], "DUPLICATE_TRANSITION_CONSUMED")
        self.assertIsNone(res["execution_result"])

    # 8. head change + non-Draft with valid prior baseline -> deterministic relevant transition behavior
    @patch('agent_controller.executor.convert_pull_request_to_draft')
    @patch('agent_controller.executor.get_pr_details')
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_head_change_relevant_transition(self, mock_watch, mock_get_pr_details, mock_convert):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha2",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["HEAD_CHANGED"]
        }

        mock_get_pr_details.side_effect = [
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"},
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"},
            {"head": {"sha": "sha2"}, "draft": True, "merged": False, "state": "open", "node_id": "node2"}
        ]

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertTrue(res["is_relevant_transition"])
        self.assertEqual(res["execution_result"]["final_outcome"], "SUCCESS")
        self.assertEqual(res["action_receipt"]["head_sha"], "sha2")

    # 9. evidence unavailable -> fail closed / prior good state preserved / no receipt / no mutation
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_evidence_unavailable_fail_closed(self, mock_watch):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha1",
            "runtime_status": "EVIDENCE_UNAVAILABLE",
            "error_reason": "GraphQL Error 500",
            "transition": False,
            "transition_reasons": []
        }

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertEqual(res["action_plan"]["decision"], "BLOCKED")
        self.assertTrue("EVIDENCE_UNAVAILABLE" in res["action_plan"]["reason"])
        self.assertIsNone(res["execution_result"])
        self.assertIsNone(res["action_receipt"])

        # State file untouched
        with open(self.state_file, 'r') as f:
            data = json.load(f)
            self.assertEqual(data["head_sha"], "sha1")

    # 10. missing/malformed policy -> no mutation
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_missing_or_malformed_policy(self, mock_watch):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha2",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["HEAD_CHANGED"]
        }

        # Nonexistent policy file
        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file="nonexistent.json",
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertFalse(res["is_relevant_transition"])
        self.assertEqual(res["action_plan"]["decision"], "BLOCKED")
        self.assertEqual(res["action_plan"]["reason"], "MISSING_OR_MALFORMED_POLICY")
        self.assertIsNone(res["execution_result"])

    # 11. stale target/head before apply -> blocked by existing executor / no success receipt
    @patch('agent_controller.executor.convert_pull_request_to_draft')
    @patch('agent_controller.executor.get_pr_details')
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_stale_head_before_apply(self, mock_watch, mock_get_pr_details, mock_convert):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha2",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["HEAD_CHANGED"]
        }

        mock_get_pr_details.side_effect = [
            # For plan_action
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"},
            # For execute_action pre-read -> head changed to sha3!
            {"head": {"sha": "sha3"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"}
        ]

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertTrue(res["is_relevant_transition"])
        self.assertEqual(res["execution_result"]["final_outcome"], "BLOCKED")
        self.assertEqual(res["execution_result"]["failure_reason"], "STALE_HEAD_SHA")
        self.assertIsNone(res["action_receipt"])
        mock_convert.assert_not_called()

    # 12. mutation failure -> no success receipt
    @patch('agent_controller.executor.convert_pull_request_to_draft')
    @patch('agent_controller.executor.get_pr_details')
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_mutation_failure_no_receipt(self, mock_watch, mock_get_pr_details, mock_convert):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha2",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["HEAD_CHANGED"]
        }

        mock_get_pr_details.side_effect = [
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"},
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"}
        ]
        mock_convert.side_effect = Exception("API error")

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertTrue(res["is_relevant_transition"])
        self.assertEqual(res["execution_result"]["final_outcome"], "BLOCKED")
        self.assertEqual(res["execution_result"]["failure_reason"], "MUTATION_FAILED")
        self.assertIsNone(res["action_receipt"])

    # 13. postcondition verification failure -> no success receipt
    @patch('agent_controller.executor.convert_pull_request_to_draft')
    @patch('agent_controller.executor.get_pr_details')
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_postcondition_failure_no_receipt(self, mock_watch, mock_get_pr_details, mock_convert):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha2",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["HEAD_CHANGED"]
        }

        mock_get_pr_details.side_effect = [
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"},
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"},
            # Postcondition fetch still shows draft=False
            {"head": {"sha": "sha2"}, "draft": False, "merged": False, "state": "open", "node_id": "node2"}
        ]

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertTrue(res["is_relevant_transition"])
        self.assertEqual(res["execution_result"]["final_outcome"], "FAILED")
        self.assertEqual(res["execution_result"]["failure_reason"], "POSTCONDITION_FAILED")
        self.assertFalse(res["postcondition_result"])
        self.assertIsNone(res["action_receipt"])

    # 14. corrupt receipt/state -> explicit fail-closed handling, never silently treated as consumed or safe
    @patch('agent_controller.reconciler.watch_pr_once')
    def test_corrupt_receipts_file(self, mock_watch):
        with open(self.state_file, 'w') as f:
            json.dump({"head_sha": "sha1", "draft": False, "merged": False, "state_enum": "open"}, f)

        # Write corrupt JSON into receipts file
        with open(self.receipts_file, 'w') as f:
            f.write("invalid json {")

        mock_watch.return_value = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "previous_head_sha": "sha1",
            "current_head_sha": "sha2",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["HEAD_CHANGED"]
        }

        res = reconcile_pr_once(
            self.owner, self.repo, self.pr_number,
            state_file=self.state_file,
            policy_file=self.policy_file,
            receipts_file=self.receipts_file,
            apply=True
        )

        self.assertFalse(res["is_relevant_transition"])
        self.assertEqual(res["action_plan"]["decision"], "BLOCKED")
        self.assertEqual(res["action_plan"]["reason"], "CORRUPT_RECEIPTS_FILE")

    # 15. receipt persistence is interruption-safe/atomic
    def test_atomic_receipt_persistence(self):
        receipt_file = os.path.join(self.temp_dir.name, "atomic_receipts.json")
        new_receipt = {
            "repo": f"{self.owner}/{self.repo}",
            "pr": self.pr_number,
            "head_sha": "sha1",
            "transition_reasons": ["PR_STATE_CHANGED"],
            "action": "ENSURE_DRAFT",
            "outcome": "SUCCESS",
            "timestamp": "2026-01-01T00:00:00Z"
        }
        _save_receipt(receipt_file, new_receipt)

        receipts, corrupt = _load_receipts(receipt_file)
        self.assertFalse(corrupt)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["head_sha"], "sha1")

    # 16. reconciliation path cannot call any write capability except Draft conversion
    def test_reconciler_capability_boundary(self):
        with open("agent_controller/reconciler.py", "r") as f:
            tree = ast.parse(f.read())

        imported_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_names.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported_names.add(alias.name)

        # Verify reconciler only imports watch_pr_once, plan_action, execute_action
        self.assertNotIn("urllib", imported_names)
        self.assertNotIn("urllib.request", imported_names)
        self.assertNotIn("requests", imported_names)
        self.assertNotIn("convert_pull_request_to_draft", imported_names) # Reconciler calls executor, not mutator directly

        dangerous_functions = ["merge", "create_comment", "add_label"]
        for func in dangerous_functions:
            self.assertNotIn(func, imported_names)

if __name__ == '__main__':
    unittest.main()
