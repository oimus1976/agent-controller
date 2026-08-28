import unittest
from unittest.mock import patch

from agent_controller.remediation_request import (
    ACTION,
    execute_codex_remediation_request,
    plan_codex_remediation_request,
)
from agent_controller.remediation_request_mutator import codex_remediation_request_marker


HEAD = "a" * 40
NEW_HEAD = "b" * 40
POLICY = {
    "allowed_actions": [ACTION],
    "trusted_review_request_authors": ["oimus1976"],
}
SCOPE = {
    "allowed_paths": ["agent_controller/**", "tests/**", "CHANGELOG.md"],
    "denied_paths": [],
    "allow_docs_only": True,
}


def finding_thread(head=HEAD, resolved=False):
    return {
        "isResolved": resolved,
        "comments": {
            "nodes": [
                {
                    "author": {"login": "chatgpt-codex-connector[bot]"},
                    "body": "P1 finding",
                    "originalCommit": {"oid": head},
                }
            ]
        },
    }


def inspection(**overrides):
    value = {
        "head_sha": HEAD,
        "head_ref": "mvp-111-codex-remediation-request",
        "base_ref": "main",
        "draft": True,
        "merged": False,
        "state": "open",
        "changed_files": 1,
        "files": [
            {
                "filename": "agent_controller/remediation_request.py",
                "status": "modified",
                "changes": 10,
            }
        ],
        "actions_ci_status": "PASS",
        "graphql_error": False,
        "issue_comments": [],
        "reviews": [],
        "review_threads_graphql": [finding_thread()],
    }
    value.update(overrides)
    return value


class RemediationRequestPlanTests(unittest.TestCase):
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_current_head_unresolved_codex_finding_is_executable(self, _load):
        plan = plan_codex_remediation_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            scope_policy=SCOPE,
            inspection=inspection(),
        )
        self.assertEqual("EXECUTABLE", plan["decision"])
        self.assertEqual(HEAD, plan["source_head_sha"])
        self.assertEqual("READY_TO_REQUEST_CODEX_REMEDIATION", plan["reason"])

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_resolved_or_old_head_finding_does_not_authorize(self, _load):
        for threads in (
            [finding_thread(resolved=True)],
            [finding_thread(head=NEW_HEAD)],
        ):
            plan = plan_codex_remediation_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                scope_policy=SCOPE,
                inspection=inspection(review_threads_graphql=threads),
            )
            self.assertEqual("NOOP", plan["decision"])
            self.assertEqual(
                "NO_UNRESOLVED_CURRENT_HEAD_CODEX_FINDING", plan["reason"]
            )

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_clean_current_head_review_does_not_request_remediation(self, _load):
        clean_review = {
            "user": {"login": "chatgpt-codex-connector[bot]"},
            "commit_id": HEAD,
            "state": "COMMENTED",
            "body": "No major issues",
        }
        plan = plan_codex_remediation_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            scope_policy=SCOPE,
            inspection=inspection(
                review_threads_graphql=[], reviews=[clean_review]
            ),
        )
        self.assertEqual("NOOP", plan["decision"])

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_same_source_head_trusted_marker_deduplicates(self, _load):
        comment = {
            "user": {"login": "oimus1976"},
            "body": "@codex address that feedback\n\n"
            + codex_remediation_request_marker(HEAD),
        }
        plan = plan_codex_remediation_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            scope_policy=SCOPE,
            inspection=inspection(issue_comments=[comment]),
        )
        self.assertEqual("NOOP", plan["decision"])
        self.assertEqual(
            "REMEDIATION_ALREADY_REQUESTED_FOR_SOURCE_HEAD", plan["reason"]
        )

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_untrusted_spoofed_marker_does_not_deduplicate(self, _load):
        comment = {
            "user": {"login": "attacker"},
            "body": "@codex address that feedback\n\n"
            + codex_remediation_request_marker(HEAD),
        }
        plan = plan_codex_remediation_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            scope_policy=SCOPE,
            inspection=inspection(issue_comments=[comment]),
        )
        self.assertEqual("EXECUTABLE", plan["decision"])

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_unsafe_branch_is_blocked(self, _load):
        for head_ref in ("main", "master"):
            plan = plan_codex_remediation_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                scope_policy=SCOPE,
                inspection=inspection(head_ref=head_ref),
            )
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual("UNSAFE_IMPLEMENTATION_BRANCH", plan["reason"])

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_draft_ci_scope_and_review_evidence_fail_closed(self, _load):
        cases = [
            (inspection(draft=False), "PR_NOT_DRAFT"),
            (inspection(actions_ci_status="FAIL"), "EXACT_HEAD_CI_NOT_PASS"),
            (inspection(graphql_error=True), "REVIEW_EVIDENCE_UNAVAILABLE"),
            (
                inspection(
                    changed_files=1,
                    files=[{"filename": "secrets/key.txt", "changes": 1}],
                ),
                "SCOPE_NOT_SATISFIED",
            ),
        ]
        denied_scope = {
            "allowed_paths": ["agent_controller/**", "tests/**"],
            "denied_paths": ["secrets/**"],
            "allow_docs_only": True,
        }
        for evidence, expected in cases:
            plan = plan_codex_remediation_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                scope_policy=denied_scope if expected == "SCOPE_NOT_SATISFIED" else SCOPE,
                inspection=evidence,
            )
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual(expected, plan["reason"])


class RemediationRequestExecutionTests(unittest.TestCase):
    def executable_plan(self):
        return {
            "repo": "oimus1976/agent-controller",
            "pr": 111,
            "requested_action": ACTION,
            "decision": "EXECUTABLE",
            "reason": "READY_TO_REQUEST_CODEX_REMEDIATION",
            "source_head_sha": HEAD,
            "head_ref": "mvp-111-codex-remediation-request",
            "base_ref": "main",
            "scope_policy": SCOPE,
            "policy_provenance": POLICY,
            "trusted_review_request_authors": ["oimus1976"],
        }

    def test_apply_false_is_dry_run(self):
        result = execute_codex_remediation_request(
            plan=self.executable_plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            apply=False,
        )
        self.assertEqual("DRY_RUN", result["final_outcome"])
        self.assertFalse(result["mutation_attempted"])

    @patch("agent_controller.remediation_request.get_pr_issue_comments")
    @patch("agent_controller.remediation_request.post_codex_remediation_request")
    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_apply_posts_once_and_only_claims_request_publication(
        self,
        fresh_plan,
        _load,
        get_pr,
        _identity,
        post,
        comments,
    ):
        fresh_plan.return_value = self.executable_plan()
        get_pr.return_value = {
            "head": {"sha": HEAD, "ref": "mvp-111-codex-remediation-request"},
            "base": {"ref": "main"},
            "draft": True,
            "merged": False,
            "state": "open",
        }
        comments.return_value = [
            {
                "user": {"login": "oimus1976"},
                "body": "@codex address that feedback\n\n"
                + codex_remediation_request_marker(HEAD),
            }
        ]

        result = execute_codex_remediation_request(
            plan=self.executable_plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            apply=True,
        )

        post.assert_called_once_with("oimus1976", "agent-controller", 111, HEAD)
        self.assertEqual("PASS", result["final_outcome"])
        self.assertEqual("REQUEST_PUBLISHED", result["postcondition_result"])
        self.assertTrue(result["mutation_attempted"])

    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="attacker")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_untrusted_posting_identity_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity
    ):
        fresh_plan.return_value = self.executable_plan()
        get_pr.return_value = {
            "head": {"sha": HEAD, "ref": "mvp-111-codex-remediation-request"},
            "base": {"ref": "main"},
            "draft": True,
            "merged": False,
            "state": "open",
        }
        with patch(
            "agent_controller.remediation_request.post_codex_remediation_request"
        ) as post:
            result = execute_codex_remediation_request(
                plan=self.executable_plan(),
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                apply=True,
            )
        post.assert_not_called()
        self.assertEqual("GITHUB_POSTING_IDENTITY_NOT_TRUSTED", result["failure_reason"])

    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_head_drift_after_identity_lookup_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity
    ):
        fresh_plan.return_value = self.executable_plan()
        safe = {
            "head": {"sha": HEAD, "ref": "mvp-111-codex-remediation-request"},
            "base": {"ref": "main"},
            "draft": True,
            "merged": False,
            "state": "open",
        }
        drifted = dict(safe)
        drifted["head"] = {"sha": NEW_HEAD, "ref": "mvp-111-codex-remediation-request"}
        get_pr.side_effect = [safe, drifted]
        with patch(
            "agent_controller.remediation_request.post_codex_remediation_request"
        ) as post:
            result = execute_codex_remediation_request(
                plan=self.executable_plan(),
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                apply=True,
            )
        post.assert_not_called()
        self.assertEqual("STALE_HEAD_SHA", result["failure_reason"])


if __name__ == "__main__":
    unittest.main()
