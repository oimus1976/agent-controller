import unittest
from unittest.mock import patch

from agent_controller.workstream import (
    WorkstreamBinding,
    validate_issue_workstream,
)
from agent_controller.workstream_reconciler import reconcile_workstream_pr_once


class WorkstreamReconcilerTests(unittest.TestCase):
    def setUp(self):
        self.lane_a = WorkstreamBinding(
            workstream_id="jules-integration",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:116",
            github_issues=(116,),
            github_prs=(117,),
        )
        self.lane_b = WorkstreamBinding(
            workstream_id="closeout-rollout",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:118",
            github_issues=(118,),
            github_prs=(119,),
        )

    def test_issue_membership_is_explicit(self):
        self.assertTrue(
            validate_issue_workstream(
                binding=self.lane_a,
                repo="oimus1976/agent-controller",
                issue=116,
            ).valid
        )
        wrong = validate_issue_workstream(
            binding=self.lane_a,
            repo="oimus1976/agent-controller",
            issue=118,
        )
        self.assertFalse(wrong.valid)
        self.assertEqual("ISSUE_NOT_IN_WORKSTREAM", wrong.reason)

    @patch("agent_controller.workstream_reconciler.reconcile_pr_once")
    def test_missing_binding_blocks_before_reconciler(self, mock_reconcile):
        result = reconcile_workstream_pr_once(
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=None,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["action_plan"]["decision"])
        self.assertEqual("WORKSTREAM_BINDING_REQUIRED", result["action_plan"]["reason"])
        self.assertIsNone(result["observation"])
        mock_reconcile.assert_not_called()

    @patch("agent_controller.workstream_reconciler.reconcile_pr_once")
    def test_117_lane_cannot_reconcile_119_before_any_legacy_work(self, mock_reconcile):
        result = reconcile_workstream_pr_once(
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=self.lane_a,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["action_plan"]["decision"])
        self.assertEqual("PR_NOT_IN_WORKSTREAM", result["action_plan"]["reason"])
        self.assertIsNone(result["observation"])
        mock_reconcile.assert_not_called()

    @patch("agent_controller.workstream_reconciler.reconcile_pr_once")
    def test_matching_lane_composes_existing_reconciler_with_exact_target(self, mock_reconcile):
        mock_reconcile.return_value = {
            "repo": "oimus1976/agent-controller",
            "pr": 119,
            "observation": {"runtime_status": "OK"},
            "transition_occurred": False,
            "transition_reasons": [],
            "is_relevant_transition": False,
            "action_plan": {"decision": "NO_ACTION"},
            "apply": False,
            "execution_result": None,
            "postcondition_result": None,
            "action_receipt": None,
        }
        result = reconcile_workstream_pr_once(
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=self.lane_b,
            state_file="lane-b.json",
            policy_file="policy.json",
            receipts_file="receipts.json",
            apply=False,
        )
        mock_reconcile.assert_called_once_with(
            "oimus1976",
            "agent-controller",
            119,
            state_file="lane-b.json",
            policy_file="policy.json",
            receipts_file="receipts.json",
            apply=False,
        )
        self.assertEqual("closeout-rollout", result["workstream_id"])

    def test_issue_collection_rejects_boolean_and_duplicates(self):
        with self.assertRaises(ValueError):
            WorkstreamBinding(
                "lane",
                "o/r",
                "github:issue:1",
                github_issues=(True,),
            )
        with self.assertRaises(ValueError):
            WorkstreamBinding(
                "lane",
                "o/r",
                "github:issue:1",
                github_issues=(1, 1),
            )


if __name__ == "__main__":
    unittest.main()
