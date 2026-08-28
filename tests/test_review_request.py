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


def _inspection(**overrides):
    values = {
        "head_sha": HEAD,
        "draft": True,
        "merged": False,
        "state": "open",
        "scope_status": "SATISFIED",
        "actions_ci_status": "PASS",
        "graphql_error": False,
        "issue_comments": [],
        "reviews": [],
        "review_threads_graphql": [],
    }
    values.update(overrides)
    return values


class CodexReviewRequestTests(unittest.TestCase):
    def setUp(self):
        fd, self.policy_path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as handle:
            json.dump({"allowed_actions": [ACTION]}, handle)
        self.scope = {
            "allowed_paths": ["agent_controller/*", "tests/*"],
            "denied_paths": [],
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
        self.assertEqual(HEAD, plan["head_sha"])

    def test_missing_policy_blocks_before_evidence_fetch(self):
        with patch("agent_controller.review_request.inspect_pr") as inspect:
            plan = plan_codex_review_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=109,
                policy_path=None,
                scope_policy=self.scope,
            )
        self.assertEqual("BLOCKED", plan["decision"])
        self.assertEqual("MISSING_OR_MALFORMED_POLICY", plan["reason"])
        inspect.assert_not_called()

    def test_action_not_allowlisted_blocks(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump({"allowed_actions": ["ENSURE_DRAFT"]}, handle)
            plan = self._plan(policy_path=path)
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual("ACTION_NOT_ALLOWLISTED", plan["reason"])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_non_draft_blocks(self):
        plan = self._plan(_inspection(draft=False))
        self.assertEqual("BLOCKED", plan["decision"])
        self.assertEqual("PR_NOT_DRAFT", plan["reason"])

    def test_closed_or_merged_blocks(self):
        for evidence in (_inspection(state="closed"), _inspection(merged=True)):
            plan = self._plan(evidence)
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual("PR_CLOSED_OR_MERGED", plan["reason"])

    def test_scope_must_be_satisfied(self):
        plan = self._plan(_inspection(scope_status="VIOLATION"))
        self.assertEqual("BLOCKED", plan["decision"])
        self.assertEqual("SCOPE_NOT_SATISFIED", plan["reason"])

    def test_exact_head_ci_must_pass(self):
        for status in ("FAIL", "PENDING", "MISSING", "UNAVAILABLE"):
            plan = self._plan(_inspection(actions_ci_status=status))
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual("EXACT_HEAD_CI_NOT_PASS", plan["reason"])

    def test_graphql_review_evidence_failure_blocks(self):
        plan = self._plan(_inspection(graphql_error=True, review_threads_graphql=None))
        self.assertEqual("BLOCKED", plan["decision"])
        self.assertEqual("REVIEW_EVIDENCE_UNAVAILABLE", plan["reason"])

    def test_same_head_controller_request_is_noop(self):
        comment = {"body": f"@codex review\n\n{codex_review_request_marker(HEAD)}", "user": {"login": "oimus1976"}}
        plan = self._plan(_inspection(issue_comments=[comment]))
        self.assertEqual("NOOP", plan["decision"])
        self.assertEqual("REVIEW_ALREADY_REQUESTED_FOR_HEAD", plan["reason"])

    def test_old_head_request_does_not_suppress_current_head(self):
        comment = {"body": f"@codex review\n\n{codex_review_request_marker(NEW_HEAD)}", "user": {"login": "oimus1976"}}
        plan = self._plan(_inspection(issue_comments=[comment]))
        self.assertEqual("EXECUTABLE", plan["decision"])

    def test_current_head_codex_clean_comment_is_noop(self):
        comment = {
            "body": f"Codex Review: Didn't find any major issues. Reviewed commit: {HEAD[:10]}",
            "user": {"login": "chatgpt-codex-connector[bot]"},
        }
        plan = self._plan(_inspection(issue_comments=[comment]))
        self.assertEqual("NOOP", plan["decision"])
        self.assertEqual("CODEX_REVIEW_ALREADY_PRESENT_ON_HEAD", plan["reason"])

    def test_current_head_codex_review_submission_is_noop(self):
        review = {
            "body": "automated review",
            "commit_id": HEAD,
            "user": {"login": "chatgpt-codex-connector[bot]"},
        }
        plan = self._plan(_inspection(reviews=[review]))
        self.assertEqual("NOOP", plan["decision"])

    def test_current_head_codex_inline_finding_is_noop(self):
        thread = {
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
        plan = self._plan(_inspection(review_threads_graphql=[thread]))
        self.assertEqual("NOOP", plan["decision"])

    def test_old_head_codex_review_does_not_suppress(self):
        review = {
            "body": f"Reviewed commit: {NEW_HEAD[:10]}",
            "commit_id": NEW_HEAD,
            "user": {"login": "chatgpt-codex-connector[bot]"},
        }
        plan = self._plan(_inspection(reviews=[review]))
        self.assertEqual("EXECUTABLE", plan["decision"])

    def test_malformed_review_evidence_blocks(self):
        plan = self._plan(_inspection(reviews=[None]))
        self.assertEqual("BLOCKED", plan["decision"])
        self.assertEqual("REVIEW_EVIDENCE_MALFORMED", plan["reason"])

    @patch("agent_controller.review_request.post_codex_review_request")
    def test_dry_run_does_not_mutate(self, post):
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=False,
        )
        self.assertEqual("DRY_RUN", result["final_outcome"])
        post.assert_not_called()

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.inspect_pr")
    def test_stale_head_blocks_before_mutation(self, inspect, post):
        inspect.return_value = _inspection(head_sha=NEW_HEAD)
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("STALE_HEAD_SHA", result["failure_reason"])
        post.assert_not_called()

    @patch("agent_controller.review_request.get_pr_issue_comments")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.inspect_pr")
    def test_apply_posts_once_and_verifies_marker(self, inspect, post, get_comments):
        inspect.return_value = _inspection()
        get_comments.return_value = [
            {"body": f"@codex review\n\n{codex_review_request_marker(HEAD)}"}
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
        post.assert_called_once_with("oimus1976", "agent-controller", 109, HEAD)

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.inspect_pr")
    def test_fresh_same_head_request_becomes_noop_before_mutation(self, inspect, post):
        comment = {"body": f"@codex review\n\n{codex_review_request_marker(HEAD)}", "user": {"login": "oimus1976"}}
        inspect.return_value = _inspection(issue_comments=[comment])
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("NOOP", result["final_outcome"])
        self.assertEqual("REVIEW_ALREADY_REQUESTED_FOR_HEAD", result["failure_reason"])
        post.assert_not_called()

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.inspect_pr")
    def test_fresh_review_evidence_becomes_noop_before_mutation(self, inspect, post):
        review = {
            "body": "review",
            "commit_id": HEAD,
            "user": {"login": "chatgpt-codex-connector[bot]"},
        }
        inspect.return_value = _inspection(reviews=[review])
        result = execute_codex_review_request(
            plan=self._plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("NOOP", result["final_outcome"])
        self.assertEqual("CODEX_REVIEW_ALREADY_PRESENT_ON_HEAD", result["failure_reason"])
        post.assert_not_called()

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.inspect_pr")
    def test_policy_revocation_blocks_before_mutation(self, inspect, post):
        plan = self._plan()
        with open(self.policy_path, "w") as handle:
            json.dump({"allowed_actions": []}, handle)
        inspect.return_value = _inspection()
        result = execute_codex_review_request(
            plan=plan,
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("ACTION_NOT_ALLOWLISTED", result["failure_reason"])
        post.assert_not_called()

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.inspect_pr")
    def test_mutation_failure_does_not_report_success(self, inspect, post):
        inspect.return_value = _inspection()
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

    @patch("agent_controller.review_request.get_pr_issue_comments")
    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.inspect_pr")
    def test_postcondition_failure_is_explicit(self, inspect, post, get_comments):
        inspect.return_value = _inspection()
        get_comments.return_value = []
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
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("TARGET_MISMATCH", result["failure_reason"])
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
