import unittest
from unittest.mock import patch

from agent_controller.inspector import inspect_pr


class InspectorPrStateEvidenceTests(unittest.TestCase):
    @patch("agent_controller.inspector.get_actions_runs")
    @patch("agent_controller.inspector.get_pr_review_threads_graphql")
    @patch("agent_controller.inspector.get_pr_files")
    @patch("agent_controller.inspector.get_pr_issue_comments")
    @patch("agent_controller.inspector.get_pr_review_comments")
    @patch("agent_controller.inspector.get_pr_reviews")
    @patch("agent_controller.inspector.get_pr_details")
    def test_missing_draft_and_merged_are_not_normalized_to_false(
        self,
        mock_details,
        mock_reviews,
        mock_review_comments,
        mock_issue_comments,
        mock_files,
        mock_threads,
        mock_actions,
    ):
        mock_details.return_value = {
            "head": {"sha": "head-1"},
            "base": {"ref": "main"},
            "state": "open",
            "changed_files": 1,
        }
        mock_reviews.return_value = []
        mock_review_comments.return_value = []
        mock_issue_comments.return_value = []
        mock_files.return_value = [{"filename": "src/app.py", "changes": 1}]
        mock_threads.return_value = []
        mock_actions.return_value = {
            "total_count": 1,
            "workflow_runs": [
                {
                    "head_sha": "head-1",
                    "event": "pull_request",
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        }

        evidence = inspect_pr(
            "owner",
            "repo",
            7,
            scope_policy={"allowed_paths": ["src/**"]},
        )

        self.assertIsNone(evidence["draft"])
        self.assertIsNone(evidence["merged"])
        self.assertEqual("open", evidence["state"])
        self.assertEqual("PASS", evidence["actions_ci_status"])


if __name__ == "__main__":
    unittest.main()
