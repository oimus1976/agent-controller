import unittest
from unittest.mock import patch

from agent_controller.remediation_request import ACTION, execute_codex_remediation_request
from agent_controller.remediation_request_mutator import codex_remediation_request_marker


HEAD = "a" * 40
REPO = "oimus1976/agent-controller"
POLICY = {
    "allowed_actions": [ACTION],
    "trusted_review_request_authors": ["oimus1976"],
}
REVOKED_POLICY = {
    "allowed_actions": [],
    "trusted_review_request_authors": ["oimus1976"],
}
SCOPE = {
    "allowed_paths": ["agent_controller/**", "tests/**", "CHANGELOG.md"],
    "denied_paths": [],
    "allow_docs_only": True,
}


def executable_plan():
    return {
        "repo": REPO,
        "pr": 111,
        "requested_action": ACTION,
        "decision": "EXECUTABLE",
        "reason": "READY_TO_REQUEST_CODEX_REMEDIATION",
        "source_head_sha": HEAD,
        "head_ref": "mvp-111-codex-remediation-request",
        "head_repo": REPO,
        "base_ref": "main",
        "base_repo": REPO,
        "default_branch": "main",
        "scope_policy": SCOPE,
        "policy_provenance": POLICY,
        "trusted_review_request_authors": ["oimus1976"],
    }


def safe_pr():
    return {
        "head": {
            "sha": HEAD,
            "ref": "mvp-111-codex-remediation-request",
            "repo": {"full_name": REPO},
        },
        "base": {
            "ref": "main",
            "repo": {"full_name": REPO, "default_branch": "main"},
        },
        "draft": True,
        "merged": False,
        "state": "open",
    }


def published_comment():
    return {
        "user": {"login": "oimus1976"},
        "body": "@codex address that feedback\n\n"
        + codex_remediation_request_marker(HEAD),
    }


class RemediationConcurrencyBoundaryTests(unittest.TestCase):
    """Document the intentional no-distributed-exactly-once boundary.

    Two isolated Controller instances can both pass identical pre-write evidence
    before either GitHub comment becomes visible. This test intentionally allows
    two fixed remediation POSTs and proves the effect remains the bounded
    REQUEST_CODEX_REMEDIATION capability, never Ready/merge/LEVEL 3 authority.
    """

    @patch(
        "agent_controller.remediation_request.get_pr_review_threads_graphql",
        return_value=[{
            "isResolved": False,
            "comments": {"nodes": [{
                "author": {"login": "chatgpt-codex-connector[bot]"},
                "originalCommit": {"oid": HEAD},
            }]},
        }],
    )
    @patch("agent_controller.remediation_request.get_pr_reviews", return_value=[])
    @patch("agent_controller.remediation_request.get_pr_issue_comments")
    @patch("agent_controller.remediation_request.post_codex_remediation_request")
    @patch(
        "agent_controller.remediation_request.get_authenticated_github_login",
        return_value="oimus1976",
    )
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_simultaneous_instances_can_duplicate_only_bounded_remediation_request(
        self, fresh_plan, _load, get_pr, _identity, post, comments, _reviews, _threads
    ):
        fresh_plan.return_value = executable_plan()
        get_pr.return_value = safe_pr()
        comments.return_value = [published_comment()]

        results = [
            execute_codex_remediation_request(
                plan=executable_plan(),
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                apply=True,
            )
            for _ in range(2)
        ]

        self.assertEqual(2, post.call_count)
        for result in results:
            self.assertEqual("PASS", result["final_outcome"])
            self.assertEqual("REQUEST_PUBLISHED", result["postcondition_result"])
            self.assertEqual(ACTION, result["mutation_type"])
            self.assertNotIn("READY", result["mutation_type"])
            self.assertNotIn("MERGE", result["mutation_type"])


class RemediationPolicyDriftTests(unittest.TestCase):
    @patch(
        "agent_controller.remediation_request.get_pr_review_threads_graphql",
        return_value=[{
            "isResolved": False,
            "comments": {"nodes": [{
                "author": {"login": "chatgpt-codex-connector[bot]"},
                "originalCommit": {"oid": HEAD},
            }]},
        }],
    )
    @patch("agent_controller.remediation_request.get_pr_reviews", return_value=[])
    @patch(
        "agent_controller.remediation_request.get_authenticated_github_login",
        return_value="oimus1976",
    )
    @patch("agent_controller.remediation_request.get_pr_details", return_value=safe_pr())
    @patch("agent_controller.remediation_request.load_policy")
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_policy_revocation_after_identity_lookup_blocks_before_post(
        self, fresh_plan, load_policy, _get_pr, _identity, _reviews, _threads
    ):
        fresh_plan.return_value = executable_plan()
        load_policy.side_effect = [POLICY, REVOKED_POLICY]

        with patch(
            "agent_controller.remediation_request.post_codex_remediation_request"
        ) as post:
            result = execute_codex_remediation_request(
                plan=executable_plan(),
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                apply=True,
            )

        post.assert_not_called()
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("POLICY_CHANGED_BEFORE_MUTATION", result["failure_reason"])


if __name__ == "__main__":
    unittest.main()
