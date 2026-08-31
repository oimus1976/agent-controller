import unittest
from unittest.mock import patch

from agent_controller.executor import execute_workstream_action
from agent_controller.workstream import WorkstreamBinding


class ExecutorWorkstreamTests(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "repo": "oimus1976/agent-controller",
            "pr": 119,
            "requested_action": "ENSURE_DRAFT",
            "decision": "EXECUTABLE",
            "reason": "READY_FOR_DRAFT_CONVERSION",
            "head_sha": "sha-119",
        }

    @patch("agent_controller.executor.convert_pull_request_to_draft")
    @patch("agent_controller.executor.get_pr_details")
    def test_wrong_lane_blocks_before_github_or_mutator(self, mock_get_pr_details, mock_mutator):
        lane_a = WorkstreamBinding(
            workstream_id="lane-a",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:116",
            github_prs=(117,),
        )
        result = execute_workstream_action(
            self.plan,
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=lane_a,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("PR_NOT_IN_WORKSTREAM", result["failure_reason"])
        self.assertFalse(result["mutation_attempted"])
        mock_get_pr_details.assert_not_called()
        mock_mutator.assert_not_called()

    @patch("agent_controller.executor.get_pr_details")
    def test_matching_lane_reaches_existing_dry_run_gate(self, mock_get_pr_details):
        lane_b = WorkstreamBinding(
            workstream_id="lane-b",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:118",
            github_prs=(119,),
        )
        result = execute_workstream_action(
            self.plan,
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=lane_b,
            apply=False,
        )
        self.assertEqual("DRY_RUN", result["final_outcome"])
        self.assertEqual("APPLY_FLAG_NOT_SET", result["failure_reason"])
        mock_get_pr_details.assert_not_called()

    def test_lane_aware_boundary_requires_binding(self):
        result = execute_workstream_action(
            self.plan,
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=None,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("WORKSTREAM_BINDING_REQUIRED", result["failure_reason"])


if __name__ == "__main__":
    unittest.main()
