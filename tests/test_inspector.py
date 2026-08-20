import unittest
from unittest.mock import patch
from agent_controller.inspector import classify_pr, inspect_pr

class TestInspector(unittest.TestCase):

    def test_classify_pr_not_implementation_ready_no_changes(self):
        evidence = {
            'head_sha': '12345',
            'has_implementation_diff': False,
            'draft': False,
            'merged': False,
            'state': 'open'
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    @patch('agent_controller.inspector.get_pr_files')
    @patch('agent_controller.inspector.get_check_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_has_implementation_diff_logic(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_check_runs, mock_files):
        mock_details.return_value = {
            'head': {'sha': '12345'},
            'base': {'ref': 'main'},
            'draft': False,
            'merged': False,
            'state': 'open',
            'changed_files': 1
        }
        # Files with changes
        mock_files.return_value = [{'filename': 'src/code.py', 'changes': 10, 'status': 'modified'}]
        mock_reviews.return_value = []
        mock_review_comments.return_value = []
        mock_issue_comments.return_value = []
        mock_graphql.return_value = None
        mock_check_runs.return_value = {'check_runs': []}

        result = inspect_pr("owner", "repo", 1)
        self.assertTrue(result['has_implementation_diff'])
        self.assertEqual(len(result['diff_summary']), 1)

        # Files with no changes
        mock_files.return_value = [{'filename': 'src/code.py', 'changes': 0, 'status': 'modified'}]
        result = inspect_pr("owner", "repo", 1)
        self.assertFalse(result['has_implementation_diff'])

    def test_classify_pr_implementation_ready_reachable(self):
        evidence = {
            'head_sha': '12345',
            'has_implementation_diff': True,
            'draft': False,
            'merged': False,
            'state': 'open',
            'reviews': [],
            'issue_comments': [],
            'review_comments': []
        }
        self.assertEqual(classify_pr(evidence), "IMPLEMENTATION_READY")

    def test_classify_pr_unresolved_comments_needs_review(self):
        evidence = {
            'head_sha': '12345',
            'has_implementation_diff': True,
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
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_classify_pr_stale_review(self):
        # Review is clean but bound to an old commit
        evidence = {
            'head_sha': 'current_head_sha_98765',
            'has_implementation_diff': True,
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
            'has_implementation_diff': True,
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
        self.assertEqual(classify_pr(evidence), "IMPLEMENTATION_READY") # Reachable because no actual review found

    def test_classify_pr_resolved_vs_unresolved_inline_codex_thread(self):
        head_sha = "12345"
        # Unresolved thread
        evidence_unresolved = {
            'head_sha': head_sha,
            'has_implementation_diff': True,
            'review_threads_graphql': [
                {
                    'isResolved': False,
                    'comments': {'nodes': [
                        {'author': {'login': 'chatgpt-codex-connector[bot]'}, 'originalCommit': {'oid': head_sha}}
                    ]}
                }
            ]
        }
        self.assertEqual(classify_pr(evidence_unresolved), "NEEDS_REVIEW")

        # Resolved thread
        evidence_resolved = {
            'head_sha': head_sha,
            'has_implementation_diff': True,
            'state': 'open',
            'merged': False,
            'issue_comments': [{'user': {'login': 'chatgpt-codex-connector[bot]'}, 'body': 'some general non-clean review'}],
            'review_threads_graphql': [
                {
                    'isResolved': True,
                    'comments': {'nodes': [
                        {'author': {'login': 'chatgpt-codex-connector[bot]'}, 'originalCommit': {'oid': head_sha}}
                    ]}
                }
            ]
        }
        self.assertEqual(classify_pr(evidence_resolved), "NEEDS_REVIEW") # Should be NEEDS_REVIEW because it doesn't have clean evidence either

    def test_classify_pr_current_head_changes_requested_blocking(self):
        evidence = {
            'head_sha': '12345',
            'has_implementation_diff': True,
            'reviews': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'commit_id': '12345',
                    'state': 'CHANGES_REQUESTED',
                    'body': 'Please fix these issues.'
                }
            ]
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_classify_pr_graphql_fail_closed(self):
        evidence = {
            'head_sha': '12345',
            'has_implementation_diff': True,
            'graphql_error': True,
            'issue_comments': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'body': "Didn't find any major issues for commit 12345."
                }
            ]
        }
        # Even with clean comment, if graphql_error is True, block REVIEW_READY
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_classify_pr_check_run_error_blocking(self):
        evidence = {
            'head_sha': '12345',
            'has_implementation_diff': True,
            'check_runs_error': True,
            'issue_comments': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'body': "Didn't find any major issues for commit 12345."
                }
            ]
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_classify_pr_codex_clean_review_reaction(self):
        evidence = {
            'head_sha': '12345',
            'has_implementation_diff': True,
            'state': 'open',
            'merged': False,
            'issue_comments': [
                {
                    'user': {'login': 'some-user'},
                    'body': "@codex review",
                    'reactions': [
                        {
                            'user': {'login': 'chatgpt-codex-connector[bot]'},
                            'content': '+1'
                        }
                    ]
                }
            ]
        }
        # A reaction without explicit SHA binding must not yield REVIEW_READY
        self.assertNotEqual(classify_pr(evidence), "REVIEW_READY")
        # Since it has a review interaction but we failed closed on binding it, it should be NEEDS_REVIEW
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    @patch('agent_controller.inspector._github_graphql_request')
    def test_graphql_pagination(self, mock_gql):
        # Mocking > 100 threads and > 100 comments
        from agent_controller.inspector import get_pr_review_threads_graphql

        # First call gets threads page 1
        call1 = {
            'data': {'repository': {'pullRequest': {'reviewThreads': {
                'pageInfo': {'hasNextPage': True, 'endCursor': 't_cursor1'},
                'nodes': [
                    {'id': 't1', 'isResolved': False, 'comments': {'pageInfo': {'hasNextPage': True, 'endCursor': 'c_cursor1'}, 'nodes': [{'body': 'c1'}]}}
                ]
            }}}}
        }
        # Second call is the nested comments for t1
        call2 = {
            'data': {'node': {'comments': {
                'pageInfo': {'hasNextPage': False, 'endCursor': 'c_cursor2'},
                'nodes': [{'body': 'c2'}]
            }}}
        }
        # Third call is threads page 2
        call3 = {
            'data': {'repository': {'pullRequest': {'reviewThreads': {
                'pageInfo': {'hasNextPage': False, 'endCursor': 't_cursor2'},
                'nodes': [
                    {'id': 't2', 'isResolved': True, 'comments': {'pageInfo': {'hasNextPage': False, 'endCursor': 'c_cursor_t2'}, 'nodes': [{'body': 'c3'}]}}
                ]
            }}}}
        }

        mock_gql.side_effect = [call1, call2, call3]

        threads = get_pr_review_threads_graphql('owner', 'repo', 1)
        self.assertEqual(len(threads), 2)
        self.assertEqual(len(threads[0]['comments']['nodes']), 2)
        self.assertEqual(threads[0]['comments']['nodes'][0]['body'], 'c1')
        self.assertEqual(threads[0]['comments']['nodes'][1]['body'], 'c2')
        self.assertEqual(len(threads[1]['comments']['nodes']), 1)

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
            'has_implementation_diff': True,
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

    @patch('agent_controller.inspector.get_pr_files')
    @patch('agent_controller.inspector.get_check_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_inspect_pr_end_to_end_mocked(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_check_runs, mock_files):
        mock_details.return_value = {
            'head': {'sha': 'b201119ec5b82aef81630ec375d208d2c113f033'},
            'base': {'ref': 'main'},
            'draft': True,
            'merged': False,
            'state': 'open',
            'changed_files': 1
        }
        mock_files.return_value = [{'filename': 'test.py', 'changes': 5}]
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

    @patch('agent_controller.inspector.get_pr_files')
    @patch('agent_controller.inspector.get_check_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_inspect_pr_check_run_fetch_failure(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_check_runs, mock_files):
        mock_details.return_value = {
            'head': {'sha': 'b201119ec5b82aef81630ec375d208d2c113f033'},
            'base': {'ref': 'main'},
            'draft': True,
            'merged': False,
            'state': 'open',
            'changed_files': 1
        }
        mock_files.return_value = [{'filename': 'test.py', 'changes': 5}]
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
