import unittest
from unittest.mock import patch
from agent_controller.inspector import classify_pr, inspect_pr

class TestInspector(unittest.TestCase):

    def test_classify_pr_not_implementation_ready_no_changes(self):
        evidence = {
            'head_sha': '12345',
            'changed_files': 0,
            'draft': False,
            'merged': False,
            'state': 'open'
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

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

    def test_classify_pr_spoofed_non_codex_clean_comment_rejection(self):
        evidence = {
            'head_sha': '12345',
            'changed_files': 1,
            'draft': True,
            'merged': False,
            'state': 'open',
            'issue_comments': [
                {
                    'user': {'login': 'malicious-user'},
                    'body': "Codex Review: Didn't find any major issues for commit 12345."
                }
            ],
            'reviews': []
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_classify_pr_resolved_vs_unresolved_inline_codex_thread(self):
        head_sha = "12345"
        # Unresolved thread
        evidence_unresolved = {
            'head_sha': head_sha,
            'changed_files': 1,
            'review_threads_graphql': {
                'data': {'repository': {'pullRequest': {'reviewThreads': {'nodes': [
                    {
                        'isResolved': False,
                        'comments': {'nodes': [
                            {'author': {'login': 'chatgpt-codex-connector[bot]'}, 'originalCommit': {'oid': head_sha}}
                        ]}
                    }
                ]}}}}
            }
        }
        self.assertEqual(classify_pr(evidence_unresolved), "IMPLEMENTATION_READY")

        # Resolved thread
        evidence_resolved = {
            'head_sha': head_sha,
            'changed_files': 1,
            'review_threads_graphql': {
                'data': {'repository': {'pullRequest': {'reviewThreads': {'nodes': [
                    {
                        'isResolved': True,
                        'comments': {'nodes': [
                            {'author': {'login': 'chatgpt-codex-connector[bot]'}, 'originalCommit': {'oid': head_sha}}
                        ]}
                    }
                ]}}}}
            }
        }
        self.assertEqual(classify_pr(evidence_resolved), "NEEDS_REVIEW")

    def test_classify_pr_current_head_changes_requested_blocking(self):
        evidence = {
            'head_sha': '12345',
            'changed_files': 1,
            'reviews': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'commit_id': '12345',
                    'state': 'CHANGES_REQUESTED',
                    'body': 'Please fix these issues.'
                }
            ]
        }
        self.assertEqual(classify_pr(evidence), "IMPLEMENTATION_READY")

    def test_inspect_pr_check_run_fetch_failure_semantics(self):
        # We need to mock to test inspect_pr
        pass

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
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_inspect_pr_end_to_end_mocked(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_check_runs):
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
        mock_graphql.return_value = None
        mock_check_runs.return_value = {'check_runs': []}

        result = inspect_pr("oimus1976", "calendar-csv2ics-converter", 5)
        self.assertEqual(result['classification'], "REVIEW_READY")
        self.assertEqual(result['head_sha'], "b201119ec5b82aef81630ec375d208d2c113f033")
        self.assertFalse(result['check_runs_error'])

    @patch('agent_controller.inspector.get_check_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_inspect_pr_check_run_fetch_failure(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_check_runs):
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
        mock_issue_comments.return_value = []
        mock_graphql.return_value = None
        mock_check_runs.side_effect = Exception("API Error")

        result = inspect_pr("oimus1976", "calendar-csv2ics-converter", 5)
        self.assertTrue(result['check_runs_error'])
        self.assertIsNone(result['check_runs'])
        self.assertEqual(result['classification'], "NEEDS_REVIEW")

if __name__ == '__main__':
    unittest.main()
