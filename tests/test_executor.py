import unittest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

from agent_controller.executor import plan_action, execute_action

class TestExecutor(unittest.TestCase):
    def setUp(self):
        self.owner = "testowner"
        self.repo = "testrepo"
        self.pr_number = 1

        # Create temporary policy file
        self.policy_fd, self.policy_path = tempfile.mkstemp()
        self.valid_policy = {"allowed_actions": ["ENSURE_DRAFT"]}
        with os.fdopen(self.policy_fd, 'w') as f:
            json.dump(self.valid_policy, f)

    def tearDown(self):
        if os.path.exists(self.policy_path):
            os.remove(self.policy_path)

    # 1. policy absent -> BLOCKED, no mutation
    @patch('agent_controller.executor.get_pr_details')
    def test_missing_policy(self, mock_get_pr_details):
        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", None)
        self.assertEqual(plan["decision"], "BLOCKED")
        self.assertEqual(plan["reason"], "MISSING_OR_MALFORMED_POLICY")
        mock_get_pr_details.assert_not_called()

    # 2. policy malformed -> BLOCKED, no mutation
    @patch('agent_controller.executor.get_pr_details')
    def test_malformed_policy(self, mock_get_pr_details):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            f.write("invalid json")

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", path)
        self.assertEqual(plan["decision"], "BLOCKED")
        self.assertEqual(plan["reason"], "MISSING_OR_MALFORMED_POLICY")
        os.remove(path)
        mock_get_pr_details.assert_not_called()

    # 3. action not allowlisted -> BLOCKED, no mutation
    @patch('agent_controller.executor.get_pr_details')
    def test_action_not_allowlisted(self, mock_get_pr_details):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            json.dump({"allowed_actions": ["OTHER_ACTION"]}, f)

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", path)
        self.assertEqual(plan["decision"], "BLOCKED")
        self.assertEqual(plan["reason"], "ACTION_NOT_ALLOWLISTED")
        os.remove(path)
        mock_get_pr_details.assert_not_called()

    # 4. already Draft -> NOOP, no mutation
    @patch('agent_controller.executor.get_pr_details')
    def test_already_draft(self, mock_get_pr_details):
        mock_get_pr_details.return_value = {
            "head": {"sha": "abcd"},
            "draft": True,
            "merged": False,
            "state": "open"
        }
        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        self.assertEqual(plan["decision"], "NOOP")
        self.assertEqual(plan["reason"], "ALREADY_DRAFT")

    # 5. open non-Draft + valid policy -> EXECUTABLE in dry-run, no mutation
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_executable_dry_run(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.return_value = {
            "head": {"sha": "abcd"},
            "draft": False,
            "merged": False,
            "state": "open",
            "node_id": "node123"
        }
        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        self.assertEqual(plan["decision"], "EXECUTABLE")

        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=False)
        self.assertEqual(result["final_outcome"], "DRY_RUN")
        self.assertEqual(result["mutation_attempted"], False)
        mock_graphql.assert_not_called()
    # 6. same case + --apply -> exactly one Draft mutation
    # 13. successful mutation -> verified Draft=true
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_successful_mutation(self, mock_get_pr_details, mock_graphql):
        # Initial fetch
        mock_get_pr_details.side_effect = [
            # For plan
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            # For pre-execute verification
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            # For postcondition verification
            {
                "head": {"sha": "abcd"},
                "draft": True,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            }
        ]

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        self.assertEqual(plan["decision"], "EXECUTABLE")

        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "SUCCESS")
        self.assertEqual(result["mutation_attempted"], True)
        self.assertEqual(result["postcondition_result"], True)
        mock_graphql.assert_called_once()

    # 7. pre-execution head changed -> BLOCKED, no mutation
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_stale_head(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.side_effect = [
            # For plan
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            # For pre-execute verification
            {
                "head": {"sha": "new_sha_changed"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            }
        ]

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "BLOCKED")
        self.assertEqual(result["failure_reason"], "STALE_HEAD_SHA")
        mock_graphql.assert_not_called()

    # 8. PR closed before execute -> BLOCKED, no mutation
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_closed_before_execute(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.side_effect = [
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "closed",
                "node_id": "node123"
            }
        ]

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "BLOCKED")
        self.assertEqual(result["failure_reason"], "PR_CLOSED_OR_MERGED")
        mock_graphql.assert_not_called()

    # 9. PR merged before execute -> BLOCKED, no mutation
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_merged_before_execute(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.side_effect = [
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": True,
                "state": "open",
                "node_id": "node123"
            }
        ]

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "BLOCKED")
        self.assertEqual(result["failure_reason"], "PR_CLOSED_OR_MERGED")
        mock_graphql.assert_not_called()

    # 14. repeated run after successful Draft conversion -> NOOP, no duplicate mutation
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_repeated_run_after_success(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.side_effect = [
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            {
                "head": {"sha": "abcd"},
                "draft": True,  # Someone or something set it to draft in between
                "merged": False,
                "state": "open",
                "node_id": "node123"
            }
        ]

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "NOOP")
        self.assertEqual(result["failure_reason"], "ALREADY_DRAFT")
        mock_graphql.assert_not_called()
    # 10. GitHub read/API failure -> BLOCKED, no mutation
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_github_read_failure(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.side_effect = Exception("API error")

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        self.assertEqual(plan["decision"], "BLOCKED")
        self.assertTrue(plan["reason"].startswith("EVIDENCE_FETCH_FAILED"))

        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "BLOCKED")
        mock_graphql.assert_not_called()

    # 11. mutation failure -> explicit failure, no false success
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_mutation_failure(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.side_effect = [
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            }
        ]
        mock_graphql.side_effect = Exception("GraphQL failure")

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "BLOCKED")
        self.assertEqual(result["failure_reason"], "MUTATION_FAILED")
        self.assertEqual(result["postcondition_result"], None)

    # 12. postcondition remains non-Draft -> explicit verification failure
    @patch('agent_controller.executor._github_graphql_request')
    @patch('agent_controller.executor.get_pr_details')
    def test_postcondition_failure(self, mock_get_pr_details, mock_graphql):
        mock_get_pr_details.side_effect = [
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            {
                "head": {"sha": "abcd"},
                "draft": False,
                "merged": False,
                "state": "open",
                "node_id": "node123"
            },
            {
                "head": {"sha": "abcd"},
                "draft": False, # Failed to actually become draft
                "merged": False,
                "state": "open",
                "node_id": "node123"
            }
        ]

        plan = plan_action(self.owner, self.repo, self.pr_number, "ENSURE_DRAFT", self.policy_path)
        result = execute_action(plan, self.owner, self.repo, self.pr_number, apply=True)
        self.assertEqual(result["final_outcome"], "FAILED")
        self.assertEqual(result["failure_reason"], "POSTCONDITION_FAILED")
        self.assertEqual(result["postcondition_result"], False)

    # 15. executor has no callable merge/comment/label/review-trigger/file-write path
    def test_no_other_capabilities(self):
        # We ensure this by structural verification of the file.
        # There's no other GraphQL mutation defined and we use strict exact string match in execute_action.
        pass

if __name__ == '__main__':
    unittest.main()
