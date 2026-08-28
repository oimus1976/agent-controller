import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agent_controller.review_request import (
    ACTION,
    execute_codex_review_request,
    plan_codex_review_request,
)
from agent_controller.review_request_mutator import codex_review_request_marker


HEAD = "a" * 40
NEW_HEAD = "b" * 40
TRUSTED_AUTHOR = "oimus1976"


def _inspection(**overrides):
    values = {
        "head_sha": HEAD,
        "draft": True,
        "merged": False,
        "state": "open",
        "changed_files": 1,
        "files": [{"filename": "agent_controller/example.py", "changes": 1}],
        "actions_ci_status": "PASS",
        "graphql_error": False,
        "issue_comments": [],
        "reviews": [],
        "review_threads_graphql": [],
    }
    values.update(overrides)
    return values


def _pr_snapshot(**overrides):
    values = {
        "head": {"sha": HEAD},
        "draft": True,
        "merged": False,
        "state": "open",
    }
    values.update(overrides)
    return values


def _actions_pass():
    return {
        "total_count": 1,
        "workflow_runs": [
            {
                "head_sha": HEAD,
                "event": "pull_request",
                "status": "completed",
                "conclusion": "success",
            }
        ],
    }


class CodexReviewRequestTests(unittest.TestCase):
    def setUp(self):
        fd, self.policy_path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as handle:
            json.dump(
                {
                    "allowed_actions": [ACTION],
                    "trusted_review_request_authors": [TRUSTED_AUTHOR],
                },
                handle,
            )
        self.scope = {
            "allowed_paths": ["agent_controller/*", "tests/*"],
            "denied_paths": ["secrets/*"],
            "allow_docs_only": True,
        }

    def tearDown(self):
        if os.path.exists(self.policy_path):
            os.remove(self.policy_path)

    def _plan(self, inspection=None, policy_path=None):
        return plan_codex_review_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path if policy_path is None else policy_path,
            scope_policy=self.scope,
            inspection=_inspection() if inspection is None else inspection,
        )

    def test_eligible_exact_head_is_executable(self):
        plan = self._plan()
        self.assertEqual("EXECUTABLE", plan["decision"])
        self.assertEqual("READY_TO_REQUEST_CODEX_REVIEW", plan["reason"])
        self.assertEqual("SATISFIED", plan["scope_status"])
        self.assertEqual([TRUSTED_AUTHOR], plan["trusted_review_request_authors"])

    def test_missing_policy_blocks_before_evidence_fetch(self):
        with patch("agent_controller.review_request._inspect_review_request") as inspect:
            plan = plan_codex_review_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=109,
                policy_path=None,
                scope_policy=self.scope,
            )
        self.assertEqual("MISSING_OR_MALFORMED_POLICY", plan["reason"])
        inspect.assert_not_called()

    def test_policy_contract_gates_fail_closed(self):
        policies_and_reasons = [
            (
                {
                    "allowed_actions": ["ENSURE_DRAFT"],
                    "trusted_review_request_authors": [TRUSTED_AUTHOR],
                },
                "ACTION_NOT_ALLOWLISTED",
            ),
            ({"allowed_actions": [ACTION]}, "TRUSTED_REQUEST_AUTHORS_MISSING_OR_MALFORMED"),
            (
                {"allowed_actions": [ACTION], "trusted_review_request_authors": []},
                "TRUSTED_REQUEST_AUTHORS_MISSING_OR_MALFORMED",
            ),
            (
                {"allowed_actions": [ACTION], "trusted_review_request_authors": [""]},
                "TRUSTED_REQUEST_AUTHORS_MISSING_OR_MALFORMED",
            ),
            (
                {
                    "allowed_actions": [ACTION],
                    "trusted_review_request_authors": [TRUSTED_AUTHOR, TRUSTED_AUTHOR],
                },
                "TRUSTED_REQUEST_AUTHORS_MISSING_OR_MALFORMED",
            ),
        ]
        for policy, reason in policies_and_reasons:
            fd, path = tempfile.mkstemp()
            try:
                with os.fdopen(fd, "w") as handle:
                    json.dump(policy, handle)
                plan = self._plan(policy_path=path)
                self.assertEqual("BLOCKED", plan["decision"])
                self.assertEqual(reason, plan["reason"])
            finally:
                if os.path.exists(path):
                    os.remove(path)

    def test_pr_state_and_head_gates_fail_closed(self):
        cases = [
            (_inspection(draft=False), "PR_NOT_DRAFT"),
            (_inspection(state="closed"), "PR_CLOSED_OR_MERGED"),
            (_inspection(merged=True), "PR_CLOSED_OR_MERGED"),
            (_inspection(state="mystery"), "PR_STATE_NOT_OPEN"),
            (_inspection(head_sha="g" * 40), "HEAD_SHA_MALFORMED"),
        ]
        for evidence, reason in cases:
            with self.subTest(reason=reason):
                plan = self._plan(evidence)
                self.assertEqual("BLOCKED", plan["decision"])
                self.assertEqual(reason, plan["reason"])

    def test_scope_is_recomputed_and_rename_source_is_checked(self):
        plan = self._plan(
            _inspection(
                files=[
                    {
                        "filename": "agent_controller/new.py",
                        "previous_filename": "secrets/key.py",
                        "changes": 1,
                    }
                ],
                changed_files=1,
            )
        )
        self.assertEqual("BLOCKED", plan["decision"])
        self.assertEqual("SCOPE_NOT_SATISFIED", plan["reason"])
        self.assertEqual("VIOLATION", plan["scope_status"])

    def test_malformed_or_incomplete_changed_file_evidence_blocks(self):
        cases = [
            _inspection(files=[{}], changed_files=1),
            _inspection(
                files=[{"filename": "agent_controller/example.py", "changes": 1}],
                changed_files=2,
            ),
            _inspection(changed_files=True),
            _inspection(changed_files=-1),
        ]
        for evidence in cases:
            with self.subTest(evidence=evidence):
                plan = self._plan(evidence)
                self.assertEqual("BLOCKED", plan["decision"])
                self.assertEqual("SCOPE_EVIDENCE_MALFORMED", plan["reason"])

    def test_ci_and_review_evidence_gates(self):
        for status in ("FAIL", "PENDING", "MISSING", "UNAVAILABLE"):
            with self.subTest(status=status):
                self.assertEqual(
                    "EXACT_HEAD_CI_NOT_PASS",
                    self._plan(_inspection(actions_ci_status=status))["reason"],
                )
        self.assertEqual(
            "REVIEW_EVIDENCE_UNAVAILABLE",
            self._plan(_inspection(graphql_error=True, review_threads_graphql=None))["reason"],
        )
        self.assertEqual(
            "REVIEW_EVIDENCE_MALFORMED",
            self._plan(_inspection(reviews=[None]))["reason"],
        )

    def test_trusted_same_head_marker_dedupes_but_spoof_does_not(self):
        trusted = {
            "body": f"@codex review\n\n{codex_review_request_marker(HEAD)}",
            "user": {"login": TRUSTED_AUTHOR},
        }
        spoof = {
            "body": f"@codex review\n\n{codex_review_request_marker(HEAD)}",
            "user": {"login": "untrusted-author"},
        }
        old_head = {
            "body": f"@codex review\n\n{codex_review_request_marker(NEW_HEAD)}",
            "user": {"login": TRUSTED_AUTHOR},
        }
        self.assertEqual("NOOP", self._plan(_inspection(issue_comments=[trusted]))["decision"])
        self.assertEqual("EXECUTABLE", self._plan(_inspection(issue_comments=[spoof]))["decision"])
        self.assertEqual("EXECUTABLE", self._plan(_inspection(issue_comments=[old_head]))["decision"])

    def test_current_head_codex_evidence_suppresses_new_request(self):
        evidences = [
            _inspection(
                issue_comments=[
                    {
                        "body": f"Didn't find any major issues. Reviewed commit: {HEAD[:10]}",
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                    }
                ]
            ),
            _inspection(
                reviews=[
                    {
                        "body": "automated review",
                        "commit_id": HEAD,
                        "user": {"login": "chatgpt-codex-connector[bot]"},
                    }
                ]
            ),
            _inspection(
                review_threads_graphql=[
                    {
                        "comments": {
                            "nodes": [
                                {
                                    "author": {"login": "chatgpt-codex-connector[bot]"},
                                    "originalCommit": {"oid": HEAD},
                                    "body": "P1 finding",
                                }
                            ]
                        }
                    }
                ]
            ),
        ]
        for evidence in evidences:
            with self.subTest(evidence=evidence):
                plan = self._plan(evidence)
                self.assertEqual("NOOP", plan["decision"])
                self.assertEqual("CODEX_REVIEW_ALREADY_PRESENT_ON_HEAD", plan["reason"])

    @patch("agent_controller.inspector.get_issue_comment_reactions")
    @patch("agent_controller.review_request.get_actions_runs")
    @patch("agent_controller.review_request.get_pr_review_threads_graphql")
    @patch("agent_controller.review_request.get_pr_files")
    @patch("agent_controller.review_request.get_pr_issue_comments")
    @patch("agent_controller.review_request.get_pr_reviews")
    @patch("agent_controller.review_request.get_pr_details")
    def test_purpose_specific_planner_does_not_fetch_comment_reactions(
        self,
        get_pr,
        get_reviews,
        get_comments,
        get_files,
        get_threads,
        get_actions,
        reaction_read,
    ):
        get_pr.return_value = {**_pr_snapshot(), "changed_files": 1}
        get_reviews.return_value = []
        get_comments.return_value = [
            {"id": index, "body": "noise", "user": {"login": f"user-{index}"}}
            for index in range(50)
        ]
        get_files.return_value = [
            {"filename": "agent_controller/example.py", "changes": 1}
        ]
        get_threads.return_value = []
        get_actions.return_value = _actions_pass()

        plan = plan_codex_review_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            scope_policy=self.scope,
        )
        self.assertEqual("EXECUTABLE", plan["decision"])
        reaction_read.assert_not_called()
        get_comments.assert_called_once()

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    def test_dry_run_has_no_side_effect_or_identity_read(self, identity, post):
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=False,
        )
        self.assertEqual("DRY_RUN", result["final_outcome"])
        identity.assert_not_called()
        post.assert_not_called()

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_fresh_stale_head_blocks_before_identity_or_post(self, inspect, identity, post):
        inspect.return_value = _inspection(head_sha=NEW_HEAD)
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("STALE_HEAD_SHA", result["failure_reason"])
        identity.assert_not_called()
        post.assert_not_called()

    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request.get_pr_issue_comments")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_success_posts_once_and_verifies_trusted_marker_and_head(
        self, inspect, identity, post, get_comments, get_pr
    ):
        inspect.return_value = _inspection()
        identity.return_value = TRUSTED_AUTHOR
        get_pr.side_effect = [_pr_snapshot(), _pr_snapshot()]
        get_comments.return_value = [
            {
                "body": f"@codex review\n\n{codex_review_request_marker(HEAD)}",
                "user": {"login": TRUSTED_AUTHOR},
            }
        ]
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("SUCCESS", result["final_outcome"])
        self.assertTrue(result["postcondition_result"])
        identity.assert_called_once_with()
        post.assert_called_once_with("oimus1976", "agent-controller", 109, HEAD)
        self.assertEqual(2, get_pr.call_count)

    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_pre_post_target_reread_blocks_or_fails_on_drift(
        self, inspect, identity, post, get_pr
    ):
        inspect.return_value = _inspection()
        get_pr.return_value = _pr_snapshot(head={"sha": NEW_HEAD})
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("STALE_HEAD_SHA", result["failure_reason"])
        identity.assert_not_called()
        post.assert_not_called()

    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_policy_change_during_evidence_sweep_blocks_before_identity_and_post(
        self, inspect, identity, post, get_pr
    ):
        plan = self._plan()

        def mutate_policy_then_return(*_args, **_kwargs):
            with open(self.policy_path, "w") as handle:
                json.dump(
                    {
                        "allowed_actions": [],
                        "trusted_review_request_authors": [TRUSTED_AUTHOR],
                    },
                    handle,
                )
            return _inspection()

        inspect.side_effect = mutate_policy_then_return
        get_pr.return_value = _pr_snapshot()
        result = execute_codex_review_request(
            plan=plan,
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("POLICY_CHANGED_BEFORE_MUTATION", result["failure_reason"])
        identity.assert_not_called()
        post.assert_not_called()

    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_untrusted_or_unreadable_posting_identity_blocks_before_post(
        self, inspect, identity, post, get_pr
    ):
        inspect.return_value = _inspection()
        get_pr.return_value = _pr_snapshot()

        identity.return_value = "different-github-principal"
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("UNTRUSTED_POSTING_IDENTITY", result["failure_reason"])
        post.assert_not_called()

        identity.reset_mock()
        identity.side_effect = RuntimeError("identity unavailable")
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("POSTING_IDENTITY_READ_FAILED", result["failure_reason"])
        post.assert_not_called()

    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_mutation_failure_does_not_report_success(self, inspect, identity, post, get_pr):
        inspect.return_value = _inspection()
        identity.return_value = TRUSTED_AUTHOR
        get_pr.return_value = _pr_snapshot()
        post.side_effect = RuntimeError("api failed")
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("MUTATION_FAILED", result["failure_reason"])

    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request.get_pr_issue_comments")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_postcondition_requires_exact_head_and_trusted_marker(
        self, inspect, identity, post, get_comments, get_pr
    ):
        inspect.return_value = _inspection()
        identity.return_value = TRUSTED_AUTHOR
        get_pr.side_effect = [_pr_snapshot(), _pr_snapshot()]
        get_comments.return_value = [
            {
                "body": f"@codex review\n\n{codex_review_request_marker(HEAD)}",
                "user": {"login": "untrusted-author"},
            }
        ]
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("FAILED", result["final_outcome"])
        self.assertEqual("POSTCONDITION_FAILED", result["failure_reason"])

    @patch("agent_controller.review_request.post_codex_review_request")
    def test_target_mismatch_blocks(self, post):
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="other",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("TARGET_MISMATCH", result["failure_reason"])
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
