import unittest
from unittest.mock import patch

from agent_controller.inspector import evaluate_actions_ci, inspect_pr


HEAD = "abc123"


def response(*runs):
    return {"total_count": len(runs), "workflow_runs": list(runs)}


def run(status="completed", conclusion="success", head_sha=HEAD, event="pull_request"):
    return {
        "id": 1,
        "status": status,
        "conclusion": conclusion,
        "head_sha": head_sha,
        "event": event,
    }


class ActionsCiTests(unittest.TestCase):
    def test_pass_requires_all_exact_head_pr_runs_successful(self):
        self.assertEqual(evaluate_actions_ci(response(run(), run()), HEAD), "PASS")

    def test_failure_blocks_even_if_another_run_is_pending(self):
        self.assertEqual(
            evaluate_actions_ci(
                response(run(conclusion="failure"), run(status="in_progress", conclusion=None)),
                HEAD,
            ),
            "FAIL",
        )

    def test_pending_is_explicit(self):
        self.assertEqual(
            evaluate_actions_ci(response(run(status="queued", conclusion=None)), HEAD),
            "PENDING",
        )

    def test_missing_is_distinct_from_unavailable(self):
        self.assertEqual(evaluate_actions_ci(response(), HEAD), "MISSING")
        self.assertEqual(evaluate_actions_ci(None, HEAD), "UNAVAILABLE")
        self.assertEqual(evaluate_actions_ci({"workflow_runs": []}, HEAD), "UNAVAILABLE")

    def test_partial_or_mismatched_evidence_is_unavailable(self):
        self.assertEqual(
            evaluate_actions_ci({"total_count": 2, "workflow_runs": [run()]}, HEAD),
            "UNAVAILABLE",
        )
        self.assertEqual(evaluate_actions_ci(response(run(head_sha="other")), HEAD), "UNAVAILABLE")
        self.assertEqual(evaluate_actions_ci(response(run(event="push")), HEAD), "UNAVAILABLE")

    @patch("agent_controller.inspector.get_pr_files")
    @patch("agent_controller.inspector.get_actions_runs")
    @patch("agent_controller.inspector.get_pr_review_threads_graphql")
    @patch("agent_controller.inspector.get_pr_issue_comments")
    @patch("agent_controller.inspector.get_pr_review_comments")
    @patch("agent_controller.inspector.get_pr_reviews")
    @patch("agent_controller.inspector.get_pr_details")
    def test_clean_review_requires_ci_pass(
        self,
        mock_details,
        mock_reviews,
        mock_review_comments,
        mock_issue_comments,
        mock_graphql,
        mock_actions,
        mock_files,
    ):
        mock_details.return_value = {
            "head": {"sha": HEAD},
            "base": {"ref": "main"},
            "draft": True,
            "merged": False,
            "state": "open",
            "changed_files": 1,
        }
        mock_reviews.return_value = []
        mock_review_comments.return_value = []
        mock_issue_comments.return_value = [
            {
                "user": {"login": "chatgpt-codex-connector[bot]"},
                "body": f"Didn't find any major issues. Reviewed commit: {HEAD}",
            }
        ]
        mock_graphql.return_value = []
        mock_files.return_value = [{"filename": "src/code.py", "changes": 1}]

        for ci_response, expected_status, expected_classification in [
            (response(run()), "PASS", "REVIEW_READY"),
            (response(run(conclusion="failure")), "FAIL", "NEEDS_REVIEW"),
            (response(run(status="in_progress", conclusion=None)), "PENDING", "NEEDS_REVIEW"),
            (response(), "MISSING", "NEEDS_REVIEW"),
        ]:
            with self.subTest(expected_status=expected_status):
                mock_actions.return_value = ci_response
                result = inspect_pr("owner", "repo", 1, scope_policy={"allowed_paths": ["src/*"]})
                self.assertEqual(result["actions_ci_status"], expected_status)
                self.assertEqual(result["classification"], expected_classification)

    @patch("agent_controller.inspector.get_pr_files")
    @patch("agent_controller.inspector.get_actions_runs")
    @patch("agent_controller.inspector.get_pr_review_threads_graphql")
    @patch("agent_controller.inspector.get_pr_issue_comments")
    @patch("agent_controller.inspector.get_pr_review_comments")
    @patch("agent_controller.inspector.get_pr_reviews")
    @patch("agent_controller.inspector.get_pr_details")
    def test_actions_fetch_failure_is_unavailable_and_fail_closed(
        self,
        mock_details,
        mock_reviews,
        mock_review_comments,
        mock_issue_comments,
        mock_graphql,
        mock_actions,
        mock_files,
    ):
        mock_details.return_value = {
            "head": {"sha": HEAD},
            "base": {"ref": "main"},
            "draft": True,
            "merged": False,
            "state": "open",
            "changed_files": 1,
        }
        mock_reviews.return_value = []
        mock_review_comments.return_value = []
        mock_issue_comments.return_value = []
        mock_graphql.return_value = []
        mock_actions.side_effect = Exception("403")
        mock_files.return_value = [{"filename": "src/code.py", "changes": 1}]

        result = inspect_pr("owner", "repo", 1, scope_policy={"allowed_paths": ["src/*"]})
        self.assertEqual(result["actions_ci_status"], "UNAVAILABLE")
        self.assertTrue(result["check_runs_error"])
        self.assertEqual(result["classification"], "NEEDS_REVIEW")


if __name__ == "__main__":
    unittest.main()
