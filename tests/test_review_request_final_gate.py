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


HEAD = "a" * 40
NEW_HEAD = "b" * 40
TRUSTED_AUTHOR = "oimus1976"


def _inspection():
    return {
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


def _pr_snapshot(head_sha=HEAD):
    return {
        "head": {"sha": head_sha},
        "draft": True,
        "merged": False,
        "state": "open",
    }


class ReviewRequestFinalMutationGateTests(unittest.TestCase):
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
            "allowed_paths": ["agent_controller/*"],
            "denied_paths": [],
            "allow_docs_only": True,
        }
        self.plan = plan_codex_review_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            scope_policy=self.scope,
            inspection=_inspection(),
        )
        self.assertEqual("EXECUTABLE", self.plan["decision"])

    def tearDown(self):
        if os.path.exists(self.policy_path):
            os.remove(self.policy_path)

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_head_drift_during_identity_lookup_is_blocked_before_post(
        self, inspect, get_pr, identity, post
    ):
        inspect.return_value = _inspection()
        get_pr.side_effect = [_pr_snapshot(), _pr_snapshot(NEW_HEAD)]
        identity.return_value = TRUSTED_AUTHOR

        result = execute_codex_review_request(
            plan=self.plan,
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )

        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("STALE_HEAD_SHA", result["failure_reason"])
        identity.assert_called_once_with()
        post.assert_not_called()

    @patch("agent_controller.review_request.post_codex_review_request")
    @patch("agent_controller.review_request.get_authenticated_github_login")
    @patch("agent_controller.review_request.get_pr_details")
    @patch("agent_controller.review_request._inspect_review_request")
    def test_policy_revocation_during_identity_lookup_is_blocked_before_post(
        self, inspect, get_pr, identity, post
    ):
        inspect.return_value = _inspection()
        get_pr.side_effect = [_pr_snapshot(), _pr_snapshot()]

        def revoke_policy_then_return_login():
            with open(self.policy_path, "w") as handle:
                json.dump(
                    {
                        "allowed_actions": [],
                        "trusted_review_request_authors": [TRUSTED_AUTHOR],
                    },
                    handle,
                )
            return TRUSTED_AUTHOR

        identity.side_effect = revoke_policy_then_return_login

        result = execute_codex_review_request(
            plan=self.plan,
            owner="oimus1976",
            repo="agent-controller",
            pr_number=109,
            policy_path=self.policy_path,
            apply=True,
        )

        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("POLICY_CHANGED_BEFORE_MUTATION", result["failure_reason"])
        identity.assert_called_once_with()
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
