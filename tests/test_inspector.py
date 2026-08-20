import unittest
from unittest.mock import patch
from agent_controller.inspector import classify_pr, inspect_pr

class TestInspector(unittest.TestCase):

    def test_classify_pr_implementation_ready_no_changes(self):
        evidence = {
            'head_sha': '12345',
            'changed_files': 0,
            'draft': False,
            'merged': False,
            'state': 'open'
        }
        self.assertEqual(classify_pr(evidence), "IMPLEMENTATION_READY")

    def test_classify_pr_implementation_ready_unresolved_comments(self):
        evidence = {
            'head_sha': '12345',
            'changed_files': 1,
            'draft': True,
            'merged': False,
            'state': 'open',
            'review_comments': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'commit_id': '12345'
                }
            ]
        }
        self.assertEqual(classify_pr(evidence), "IMPLEMENTATION_READY")

    def test_classify_pr_stale_review(self):
        # Review is clean but bound to an old commit
        evidence = {
            'head_sha': 'current_head_sha_98765',
            'changed_files': 2,
            'draft': True,
            'merged': False,
            'state': 'open',
            'issue_comments': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'body': "Didn't find any major issues for commit old_head_sha_12345."
                }
            ],
            'reviews': []
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_classify_pr_current_head_review_binding(self):
        # Known expected fixture facts for oimus1976/calendar-csv2ics-converter PR #5
        # head SHA: b201119ec5b82aef81630ec375d208d2c113f033
        # Draft, open, unmerged
        # non-empty test-only diff
        # latest-head Codex top-level clean comment contains: "Didn't find any major issues"
        # that comment explicitly identifies reviewed commit b201119ec5
        head_sha = "b201119ec5b82aef81630ec375d208d2c113f033"
        evidence = {
            'head_sha': head_sha,
            'changed_files': 1,
            'draft': True,
            'merged': False,
            'state': 'open',
            'issue_comments': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'body': f"Codex Review: Didn't find any major issues. Another round soon, please!\n\n**Reviewed commit:** `{head_sha[:10]}`"
                }
            ]
        }
        self.assertEqual(classify_pr(evidence), "REVIEW_READY")

    @patch('agent_controller.inspector.get_check_runs')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_inspect_pr_end_to_end_mocked(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_check_runs):
        mock_details.return_value = {
            'head': {'sha': 'b201119ec5b82aef81630ec375d208d2c113f033'},
            'base': {'ref': 'main'},
            'draft': True,
            'merged': False,
            'state': 'open',
            'changed_files': 1
        }
        mock_reviews.return_value = []
        mock_review_comments.return_value = []
        mock_issue_comments.return_value = [
            {
                'user': {'login': 'chatgpt-codex-connector[bot]'},
                'body': "Codex Review: Didn't find any major issues.\n**Reviewed commit:** `b201119ec5`"
            }
        ]
        mock_check_runs.return_value = {'check_runs': []}

        result = inspect_pr("oimus1976", "calendar-csv2ics-converter", 5)
        self.assertEqual(result['classification'], "REVIEW_READY")
        self.assertEqual(result['head_sha'], "b201119ec5b82aef81630ec375d208d2c113f033")

if __name__ == '__main__':
    unittest.main()
