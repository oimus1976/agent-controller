import unittest
from unittest.mock import patch
from agent_controller.inspector import (
    build_canonical_review_evidence,
    classify_pr,
    inspect_pr,
)
from agent_controller.review_evidence import (
    REQUIRED_GITHUB_SURFACES,
    ReviewSurfaceStatus,
)


def canonical(evidence):
    evidence = dict(evidence)
    evidence.setdefault("repo", "owner/repo")
    evidence.setdefault("pr", 1)
    evidence.setdefault("reviews", [])
    evidence.setdefault("issue_comments", [])
    evidence.setdefault("review_threads_graphql", [])
    surfaces = tuple(
        ReviewSurfaceStatus(name, "COMPLETE", True)
        for name in REQUIRED_GITHUB_SURFACES
    )
    evidence["canonical_review_evidence"] = build_canonical_review_evidence(
        repo=evidence["repo"],
        pr_number=evidence["pr"],
        head_sha=evidence["head_sha"],
        reviews=evidence["reviews"],
        issue_comments=evidence["issue_comments"],
        review_threads_graphql=evidence["review_threads_graphql"],
        surfaces=surfaces,
    ).to_dict()
    return evidence

class TestInspector(unittest.TestCase):

    def test_classify_pr_not_implementation_ready_no_changes(self):
        evidence = {
            'head_sha': '12345',
            'scope_status': 'UNKNOWN',
            'draft': False,
            'merged': False,
            'state': 'open'
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_evaluate_scope(self):
        from agent_controller.inspector import evaluate_scope

        self.assertEqual(evaluate_scope([{'filename': 'src/code.py', 'changes': 1}], {}), "UNKNOWN")

        policy = {'allowed_paths': ['src/*.py']}
        files = [{'filename': 'src/code.py', 'changes': 1}]
        self.assertEqual(evaluate_scope(files, policy), "SATISFIED")

        policy = {'denied_paths': ['tests/*'], 'allowed_paths': ['src/*.py']}
        files = [{'filename': 'tests/test_code.py', 'changes': 1}]
        self.assertEqual(evaluate_scope(files, policy), "VIOLATION")

        files = [{'filename': 'src/code.py', 'changes': 1}, {'filename': 'tests/test_code.py', 'changes': 1}]
        self.assertEqual(evaluate_scope(files, policy), "VIOLATION")

        policy = {'allowed_paths': ['*']}
        files = [{'filename': 'README.md', 'changes': 1}]
        self.assertEqual(evaluate_scope(files, policy), "SATISFIED")

        policy = {'allowed_paths': ['*'], 'allow_docs_only': True}
        self.assertEqual(evaluate_scope(files, policy), "SATISFIED")

        self.assertEqual(evaluate_scope(files, None), "UNKNOWN")

    def test_classify_pr_implementation_ready_reachable(self):
        evidence = {
            'head_sha': 'a' * 40,
            'scope_status': 'SATISFIED',
            'draft': False,
            'merged': False,
            'state': 'open',
            'reviews': [],
            'issue_comments': [],
            'review_comments': []
        }
        self.assertEqual(classify_pr(canonical(evidence)), "IMPLEMENTATION_READY")

    def test_classify_pr_unresolved_comments_needs_review(self):
        evidence = {
            'head_sha': '12345',
            'scope_status': 'SATISFIED',
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
        evidence = {
            'head_sha': 'current_head_sha_98765',
            'scope_status': 'SATISFIED',
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
            'head_sha': 'a' * 40,
            'scope_status': 'SATISFIED',
            'draft': True,
            'merged': False,
            'state': 'open',
            'issue_comments': [
                {
                    'user': {'login': 'malicious-user'},
                    'body': f"Codex Review: Didn't find any major issues for commit {'a' * 40}."
                }
            ],
            'reviews': []
        }
        self.assertEqual(classify_pr(canonical(evidence)), "IMPLEMENTATION_READY")

    def test_classify_pr_resolved_vs_unresolved_inline_codex_thread(self):
        head_sha = "12345"
        evidence_unresolved = {
            'head_sha': head_sha,
            'scope_status': 'SATISFIED',
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

        evidence_resolved = {
            'head_sha': head_sha,
            'scope_status': 'SATISFIED',
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
        self.assertEqual(classify_pr(evidence_resolved), "NEEDS_REVIEW")

    def test_classify_pr_current_head_changes_requested_blocking(self):
        evidence = {
            'head_sha': '12345',
            'scope_status': 'SATISFIED',
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
            'scope_status': 'SATISFIED',
            'graphql_error': True,
            'issue_comments': [
                {
                    'user': {'login': 'chatgpt-codex-connector[bot]'},
                    'body': "Didn't find any major issues for commit 12345."
                }
            ]
        }
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    def test_classify_pr_check_run_error_blocking(self):
        evidence = {
            'head_sha': '12345',
            'scope_status': 'SATISFIED',
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
            'scope_status': 'SATISFIED',
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
        self.assertNotEqual(classify_pr(evidence), "REVIEW_READY")
        self.assertEqual(classify_pr(evidence), "NEEDS_REVIEW")

    @patch('agent_controller.inspector._github_graphql_request')
    def test_graphql_pagination(self, mock_gql):
        from agent_controller.inspector import get_pr_review_threads_graphql

        call1 = {
            'data': {'repository': {'pullRequest': {'reviewThreads': {
                'pageInfo': {'hasNextPage': True, 'endCursor': 't_cursor1'},
                'nodes': [
                    {'id': 't1', 'isResolved': False, 'comments': {'pageInfo': {'hasNextPage': True, 'endCursor': 'c_cursor1'}, 'nodes': [{'body': 'c1'}]}}
                ]
            }}}}
        }
        call2 = {
            'data': {'node': {'comments': {
                'pageInfo': {'hasNextPage': False, 'endCursor': 'c_cursor2'},
                'nodes': [{'body': 'c2'}]
            }}}
        }
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

    @patch('agent_controller.inspector._github_graphql_request')
    def test_graphql_rejects_partial_thread_page_with_top_level_errors(self, mock_gql):
        from agent_controller.inspector import get_pr_review_threads_graphql

        mock_gql.return_value = {
            'data': {'repository': {'pullRequest': {'reviewThreads': {
                'pageInfo': {'hasNextPage': False, 'endCursor': None},
                'nodes': [],
            }}}},
            'errors': [{'message': 'reviewThreads was only partially resolved'}],
        }

        with self.assertRaisesRegex(Exception, 'top-level errors'):
            get_pr_review_threads_graphql('owner', 'repo', 1)

    @patch('agent_controller.inspector._github_graphql_request')
    def test_graphql_rejects_partial_comment_page_with_top_level_errors(self, mock_gql):
        from agent_controller.inspector import get_pr_review_threads_graphql

        thread_page = {
            'data': {'repository': {'pullRequest': {'reviewThreads': {
                'pageInfo': {'hasNextPage': False, 'endCursor': None},
                'nodes': [{
                    'id': 't1',
                    'isResolved': False,
                    'comments': {
                        'pageInfo': {'hasNextPage': True, 'endCursor': 'c1'},
                        'nodes': [{'body': 'first'}],
                    },
                }],
            }}}},
        }
        partial_comment_page = {
            'data': {'node': {'comments': {
                'pageInfo': {'hasNextPage': False, 'endCursor': None},
                'nodes': [{'body': 'partial'}],
            }}},
            'errors': [{'message': 'comments was only partially resolved'}],
        }
        mock_gql.side_effect = [thread_page, partial_comment_page]

        with self.assertRaisesRegex(Exception, 'top-level errors'):
            get_pr_review_threads_graphql('owner', 'repo', 1)

    def test_classify_pr_current_head_review_binding(self):
        head_sha = "b201119ec5b82aef81630ec375d208d2c113f033"
        evidence = {
            'head_sha': head_sha,
            'scope_status': 'SATISFIED',
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
        self.assertEqual(classify_pr(canonical(evidence)), "REVIEW_READY")

    def test_prior_head_activity_does_not_make_current_head_pending(self):
        head_sha = "b" * 40
        stale_sha = "a" * 40
        evidence = {
            "head_sha": head_sha,
            "scope_status": "SATISFIED",
            "draft": True,
            "merged": False,
            "state": "open",
            "issue_comments": [
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": f"Reviewed commit: {stale_sha[:10]}",
                },
                {
                    "user": {"login": "owner"},
                    "body": f"@codex review\nhead={stale_sha}",
                    "reactions": {"total_count": 1},
                },
            ],
            "reviews": [
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "commit_id": stale_sha,
                    "state": "COMMENTED",
                }
            ],
        }
        snapshot = canonical(evidence)["canonical_review_evidence"]
        self.assertEqual("ABSENT", snapshot["verdict"])

    def test_unbracketed_codex_graphql_login_is_blocking(self):
        head_sha = "b" * 40
        evidence = {
            "head_sha": head_sha,
            "scope_status": "SATISFIED",
            "draft": True,
            "merged": False,
            "state": "open",
            "review_threads_graphql": [
                {
                    "isResolved": False,
                    "comments": {
                        "nodes": [
                            {
                                "author": {"login": "chatgpt-codex-connector"},
                                "originalCommit": {"oid": head_sha},
                            }
                        ]
                    },
                }
            ],
        }
        snapshot = canonical(evidence)["canonical_review_evidence"]
        self.assertEqual("BLOCKING", snapshot["verdict"])


    def test_unknown_current_head_thread_review_id_fails_closed(self):
        head_sha = "b" * 40
        bot = "chatgpt-codex-connector[bot]"
        for formal_input in ("empty", "stale", "pending", "clean"):
            for resolved in (False, True):
                with self.subTest(formal_input=formal_input, resolved=resolved):
                    reviews = [] if formal_input == "empty" else [{
                        "id": 1,
                        "user": {"login": bot},
                        "commit_id": "a" * 40 if formal_input == "stale" else head_sha,
                        "state": "APPROVED" if formal_input == "clean" else "COMMENTED",
                    }]
                    evidence = canonical({
                        "head_sha": head_sha, "scope_status": "SATISFIED",
                        "draft": True, "merged": False, "state": "open",
                        "reviews": reviews,
                        "review_threads_graphql": [{
                            "isResolved": resolved,
                            "comments": {"nodes": [{
                                "author": {"login": bot},
                                "originalCommit": {"oid": head_sha},
                                "pullRequestReview": {"databaseId": 2},
                                "body": "P1: unresolved current-head finding",
                            }]},
                        }],
                    })
                    snapshot = evidence["canonical_review_evidence"]
                    self.assertFalse(snapshot["collection_complete"])
                    self.assertEqual("UNCERTAIN", snapshot["verdict"])
                    self.assertIn("INLINE_THREAD_REVIEW_NOT_IN_FORMAL_REVIEWS", snapshot["errors"])
                    self.assertEqual("NEEDS_REVIEW", classify_pr(evidence))

    def test_associated_current_head_thread_review_id_preserves_behavior(self):
        head_sha = "b" * 40
        bot = "chatgpt-codex-connector[bot]"
        for resolved in (False, True):
            with self.subTest(resolved=resolved):
                evidence = canonical({
                    "head_sha": head_sha,
                    "reviews": [{
                        "id": 2, "user": {"login": bot},
                        "commit_id": head_sha, "state": "CHANGES_REQUESTED",
                    }],
                    "review_threads_graphql": [{
                        "isResolved": resolved,
                        "comments": {"nodes": [{
                            "author": {"login": bot},
                            "originalCommit": {"oid": head_sha},
                            "pullRequestReview": {"databaseId": 2},
                        }]},
                    }],
                })
                snapshot = evidence["canonical_review_evidence"]
                self.assertTrue(snapshot["collection_complete"])
                self.assertEqual("PENDING" if resolved else "BLOCKING", snapshot["verdict"])
                self.assertEqual([], snapshot["errors"])

    def test_irrelevant_thread_review_ids_do_not_create_mismatch(self):
        head_sha = "b" * 40
        bot = "chatgpt-codex-connector[bot]"
        for author, thread_head in ((bot, "a" * 40), ("human", head_sha)):
            with self.subTest(author=author, thread_head=thread_head):
                evidence = canonical({
                    "head_sha": head_sha,
                    "review_threads_graphql": [{
                        "isResolved": False,
                        "comments": {"nodes": [{
                            "author": {"login": author},
                            "originalCommit": {"oid": thread_head},
                            "pullRequestReview": {"databaseId": 2},
                        }, {
                            "author": {"login": bot},
                            "originalCommit": {"oid": head_sha},
                            "pullRequestReview": {"databaseId": 2},
                        }]},
                    }],
                })
                snapshot = evidence["canonical_review_evidence"]
                self.assertTrue(snapshot["collection_complete"])
                self.assertEqual("ABSENT", snapshot["verdict"])
                self.assertEqual([], snapshot["errors"])


    def test_collected_inactive_formal_review_thread_remains_excluded(self):
        head_sha = "b" * 40
        bot = "chatgpt-codex-connector[bot]"
        for state, review_head in (("DISMISSED", head_sha), ("COMMENTED", "a" * 40)):
            with self.subTest(state=state, review_head=review_head):
                snapshot = canonical({
                    "head_sha": head_sha,
                    "reviews": [{
                        "id": 2, "user": {"login": bot},
                        "commit_id": review_head, "state": state,
                    }],
                    "review_threads_graphql": [{
                        "isResolved": False,
                        "comments": {"nodes": [{
                            "author": {"login": bot},
                            "originalCommit": {"oid": head_sha},
                            "pullRequestReview": {"databaseId": 2},
                        }]},
                    }],
                })["canonical_review_evidence"]
                self.assertTrue(snapshot["collection_complete"])
                self.assertEqual("ABSENT", snapshot["verdict"])
                self.assertEqual([], snapshot["errors"])

    def test_unusable_thread_review_id_remains_blocking(self):
        for review_id in (None, "2", True):
            with self.subTest(review_id=review_id):
                snapshot = canonical({
                    "head_sha": "b" * 40,
                    "review_threads_graphql": [{
                        "isResolved": False,
                        "comments": {"nodes": [{
                            "author": {"login": "chatgpt-codex-connector[bot]"},
                            "originalCommit": {"oid": "b" * 40},
                            "pullRequestReview": {"databaseId": review_id},
                        }]},
                    }],
                })["canonical_review_evidence"]
                self.assertTrue(snapshot["collection_complete"])
                self.assertEqual("BLOCKING", snapshot["verdict"])
                self.assertEqual([], snapshot["errors"])


    def test_malformed_current_head_thread_resolution_fails_closed(self):
        head_sha = "b" * 40
        bot = "chatgpt-codex-connector[bot]"
        resolutions = ({}, *({"isResolved": value} for value in (
            None, 0, "", [], 1, "false", "true", [1], {},
        )))
        for review_id in (None, 2):
            for resolution in resolutions:
                with self.subTest(review_id=review_id, resolution=resolution):
                    evidence = canonical({
                        "head_sha": head_sha, "scope_status": "SATISFIED",
                        "draft": True, "merged": False, "state": "open",
                        "reviews": [{
                            "id": 2, "user": {"login": bot},
                            "commit_id": head_sha, "state": "APPROVED",
                        }],
                        "review_threads_graphql": [{
                            **resolution,
                            "comments": {"nodes": [{
                                "author": {"login": bot},
                                "originalCommit": {"oid": head_sha},
                                "pullRequestReview": {"databaseId": review_id},
                            }]},
                        }],
                    })
                    snapshot = evidence["canonical_review_evidence"]
                    self.assertFalse(snapshot["collection_complete"])
                    self.assertEqual("UNCERTAIN", snapshot["verdict"])
                    self.assertIn("INLINE_THREAD_RESOLUTION_MALFORMED", snapshot["errors"])
                    self.assertEqual("NEEDS_REVIEW", classify_pr(evidence))

    def test_irrelevant_thread_malformed_resolution_remains_excluded(self):
        head_sha = "b" * 40
        bot = "chatgpt-codex-connector[bot]"
        for author, thread_head in ((bot, "a" * 40), ("human", head_sha)):
            for resolution in ({}, {"isResolved": None}, {"isResolved": "false"}):
                with self.subTest(author=author, thread_head=thread_head, resolution=resolution):
                    snapshot = canonical({
                        "head_sha": head_sha,
                        "review_threads_graphql": [{
                            **resolution,
                            "comments": {"nodes": [{
                                "author": {"login": author},
                                "originalCommit": {"oid": thread_head},
                                "pullRequestReview": {"databaseId": 2},
                            }, {
                                "author": {"login": bot},
                                "originalCommit": {"oid": head_sha},
                            }]},
                        }],
                    })["canonical_review_evidence"]
                    self.assertTrue(snapshot["collection_complete"])
                    self.assertEqual("ABSENT", snapshot["verdict"])
                    self.assertEqual([], snapshot["errors"])

    def test_partial_raw_review_evidence_cannot_be_authoritative(self):
        evidence = {
            "repo": "owner/repo",
            "pr": 1,
            "head_sha": "1" * 40,
            "scope_status": "SATISFIED",
            "state": "open",
            "merged": False,
            "actions_ci_status": "PASS",
            "issue_comments": [
                {
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                    "body": f"Didn't find any major issues. Reviewed commit: {'1' * 40}",
                }
            ],
        }
        self.assertEqual("NEEDS_REVIEW", classify_pr(evidence))

    @patch('agent_controller.inspector.get_pr_files')
    @patch('agent_controller.inspector.get_actions_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_malformed_issue_comment_fails_closed(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_actions_runs, mock_files):
        head_sha = 'b201119ec5b82aef81630ec375d208d2c113f033'
        mock_details.return_value = {
            'head': {'sha': head_sha}, 'base': {'ref': 'main'}, 'draft': True,
            'merged': False, 'state': 'open', 'changed_files': 1,
        }
        mock_files.return_value = [{'filename': 'test.py', 'changes': 5}]
        mock_reviews.return_value = []
        mock_review_comments.return_value = []
        mock_issue_comments.return_value = ['not-an-object']
        mock_graphql.return_value = []
        mock_actions_runs.return_value = {
            'workflow_runs': [{'head_sha': head_sha, 'event': 'pull_request', 'status': 'completed', 'conclusion': 'success'}]
        }

        result = inspect_pr('owner', 'repo', 1, scope_policy={'allowed_paths': ['*']})
        self.assertEqual('NEEDS_REVIEW', result['classification'])
        self.assertEqual('UNCERTAIN', result['canonical_review_evidence']['verdict'])
        issue_surface = next(
            item for item in result['canonical_review_evidence']['surfaces']
            if item['surface'] == 'issue_comments'
        )
        self.assertEqual('UNAVAILABLE', issue_surface['status'])

    @patch('agent_controller.inspector.get_pr_files')
    @patch('agent_controller.inspector.get_actions_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_inspect_pr_end_to_end_mocked(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_actions_runs, mock_files):
        head_sha = 'b201119ec5b82aef81630ec375d208d2c113f033'
        mock_details.return_value = {
            'head': {'sha': head_sha},
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
        mock_graphql.return_value = []
        mock_actions_runs.return_value = {
            'total_count': 1,
            'workflow_runs': [{
                'id': 1,
                'head_sha': head_sha,
                'event': 'pull_request',
                'status': 'completed',
                'conclusion': 'success'
            }]
        }

        result = inspect_pr("oimus1976", "calendar-csv2ics-converter", 5, scope_policy={'allowed_paths': ['*']})
        self.assertEqual(result['classification'], "REVIEW_READY")
        self.assertEqual(result['head_sha'], head_sha)
        self.assertEqual(result['actions_ci_status'], "PASS")
        self.assertFalse(result['check_runs_error'])

    @patch('agent_controller.inspector.get_issue_comment_reactions')
    @patch('agent_controller.inspector.get_pr_files')
    @patch('agent_controller.inspector.get_actions_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_reactions_are_read_only_for_current_head_review_requests(
        self,
        mock_details,
        mock_reviews,
        mock_review_comments,
        mock_issue_comments,
        mock_graphql,
        mock_actions_runs,
        mock_files,
        mock_reactions,
    ):
        head_sha = 'b201119ec5b82aef81630ec375d208d2c113f033'
        stale_sha = 'a' * 40
        mock_details.return_value = {
            'head': {'sha': head_sha},
            'base': {'ref': 'main'},
            'draft': True,
            'merged': False,
            'state': 'open',
            'changed_files': 1,
        }
        mock_reviews.return_value = []
        mock_review_comments.return_value = []
        mock_issue_comments.return_value = [
            {'id': 1, 'user': {'login': 'user'}, 'body': 'ordinary comment'},
            {
                'id': 2,
                'user': {'login': 'user'},
                'body': f'@codex review\nhead={stale_sha}',
            },
            {
                'id': 3,
                'user': {'login': 'user'},
                'body': f'@codex review\nhead={head_sha}',
            },
        ]
        mock_graphql.return_value = []
        mock_files.return_value = [{'filename': 'test.py', 'changes': 1}]
        mock_actions_runs.return_value = {
            'total_count': 1,
            'workflow_runs': [{
                'head_sha': head_sha,
                'event': 'pull_request',
                'status': 'completed',
                'conclusion': 'success',
            }],
        }
        mock_reactions.return_value = []

        inspect_pr('owner', 'repo', 1, scope_policy={'allowed_paths': ['*']})

        mock_reactions.assert_called_once_with('owner', 'repo', 3)

    @patch('agent_controller.inspector.get_pr_files')
    @patch('agent_controller.inspector.get_actions_runs')
    @patch('agent_controller.inspector.get_pr_review_threads_graphql')
    @patch('agent_controller.inspector.get_pr_issue_comments')
    @patch('agent_controller.inspector.get_pr_review_comments')
    @patch('agent_controller.inspector.get_pr_reviews')
    @patch('agent_controller.inspector.get_pr_details')
    def test_inspect_pr_check_run_fetch_failure(self, mock_details, mock_reviews, mock_review_comments, mock_issue_comments, mock_graphql, mock_actions_runs, mock_files):
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
        mock_actions_runs.side_effect = Exception("API Error")

        result = inspect_pr("oimus1976", "calendar-csv2ics-converter", 5, scope_policy={'allowed_paths': ['*']})
        self.assertTrue(result['check_runs_error'])
        self.assertIsNone(result['check_runs'])
        self.assertEqual(result['actions_ci_status'], "UNAVAILABLE")
        self.assertEqual(result['classification'], "NEEDS_REVIEW")

if __name__ == '__main__':
    unittest.main()
