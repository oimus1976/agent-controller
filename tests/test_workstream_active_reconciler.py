import unittest
from unittest.mock import patch

from agent_controller.workstream import WorkstreamBinding
from agent_controller.workstream_reconciler import reconcile_active_workstream_pr_once


class ActiveWorkstreamReconcilerTests(unittest.TestCase):
    def setUp(self):
        self.a = WorkstreamBinding(
            workstream_id="jules-integration",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:116",
            github_issues=(116,),
            github_prs=(117,),
        )
        self.b = WorkstreamBinding(
            workstream_id="closeout-rollout",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:118",
            github_issues=(118,),
            github_prs=(119,),
        )

    @patch("agent_controller.workstream_reconciler.reconcile_workstream_pr_once")
    def test_active_lane_routes_exact_binding_and_target(self, mock_reconcile):
        mock_reconcile.return_value = {"workstream_id": "closeout-rollout"}
        result = reconcile_active_workstream_pr_once(
            "oimus1976",
            "agent-controller",
            119,
            workstream_id="closeout-rollout",
            bindings=(self.a, self.b),
            state_file="b.json",
            policy_file="policy.json",
            receipts_file="receipts.json",
            apply=True,
        )
        mock_reconcile.assert_called_once_with(
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=self.b,
            state_file="b.json",
            policy_file="policy.json",
            receipts_file="receipts.json",
            apply=True,
        )
        self.assertEqual("closeout-rollout", result["workstream_id"])

    @patch("agent_controller.workstream_reconciler.reconcile_workstream_pr_once")
    def test_overlapping_active_set_blocks_before_single_lane_reconcile(self, mock_reconcile):
        overlap = WorkstreamBinding(
            workstream_id="overlap",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:999",
            github_prs=(119,),
        )
        result = reconcile_active_workstream_pr_once(
            "oimus1976",
            "agent-controller",
            119,
            workstream_id="closeout-rollout",
            bindings=(self.a, self.b, overlap),
            apply=True,
        )
        self.assertEqual("BLOCKED", result["action_plan"]["decision"])
        self.assertEqual(
            "PR_BOUND_TO_MULTIPLE_WORKSTREAMS",
            result["action_plan"]["reason"],
        )
        mock_reconcile.assert_not_called()

    @patch("agent_controller.workstream_reconciler.reconcile_workstream_pr_once")
    def test_unknown_workstream_id_blocks_before_reconcile(self, mock_reconcile):
        result = reconcile_active_workstream_pr_once(
            "oimus1976",
            "agent-controller",
            119,
            workstream_id="not-active",
            bindings=(self.a, self.b),
            apply=True,
        )
        self.assertEqual("UNKNOWN_WORKSTREAM_ID", result["action_plan"]["reason"])
        mock_reconcile.assert_not_called()


if __name__ == "__main__":
    unittest.main()
