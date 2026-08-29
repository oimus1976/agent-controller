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
BASE_SHA = "c" * 40
NEW_BASE_SHA = "d" * 40
REPO = "oimus1976/agent-controller"
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
        "head_repo": REPO,
        "base_ref": "main",
        "base_sha": BASE_SHA,
        "base_repo": REPO,
        "default_branch": "main",
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


def safe_pr(head_sha=HEAD, head_ref="mvp-111-codex-remediation-request"):
    return {
        "head": {
            "sha": head_sha,
            "ref": head_ref,
            "repo": {"full_name": REPO},
        },
        "base": {
            "sha": BASE_SHA,
            "ref": "main",
            "repo": {"full_name": REPO, "default_branch": "main"},
        },
        "draft": True,
        "merged": False,
        "state": "open",
    }


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
    def test_resolved_threads_override_stale_changes_requested_review(self, _load):
        review = {
            "user": {"login": "chatgpt-codex-connector[bot]"},
            "commit_id": HEAD,
            "state": "CHANGES_REQUESTED",
        }
        plan = plan_codex_remediation_request(
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            scope_policy=SCOPE,
            inspection=inspection(
                reviews=[review], review_threads_graphql=[finding_thread(resolved=True)]
            ),
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
    def test_base_and_custom_default_branch_are_blocked(self, _load):
        cases = [
            inspection(head_ref="main"),
            inspection(head_ref="trunk", base_ref="release", default_branch="trunk"),
        ]
        for evidence in cases:
            plan = plan_codex_remediation_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                scope_policy=SCOPE,
                inspection=evidence,
            )
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual("UNSAFE_IMPLEMENTATION_BRANCH", plan["reason"])

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_fork_or_wrong_head_repository_is_blocked(self, _load):
        for head_repo in ("attacker/fork", "other/agent-controller"):
            plan = plan_codex_remediation_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                scope_policy=SCOPE,
                inspection=inspection(head_repo=head_repo),
            )
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual("UNSAFE_IMPLEMENTATION_REPOSITORY", plan["reason"])

    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    def test_missing_default_branch_or_repo_evidence_fails_closed(self, _load):
        for evidence in (
            inspection(default_branch=None),
            inspection(head_repo=None),
            inspection(base_repo=None),
        ):
            plan = plan_codex_remediation_request(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=111,
                policy_path="policy.json",
                scope_policy=SCOPE,
                inspection=evidence,
            )
            self.assertEqual("BLOCKED", plan["decision"])
            self.assertEqual("CONTRADICTORY_OR_MISSING_EVIDENCE", plan["reason"])

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
    def setUp(self):
        reviews = patch("agent_controller.remediation_request.get_pr_reviews")
        threads = patch(
            "agent_controller.remediation_request.get_pr_review_threads_graphql"
        )
        self.get_reviews = reviews.start()
        self.get_threads = threads.start()
        self.get_reviews.return_value = []
        self.get_threads.return_value = [finding_thread()]
        actions = patch("agent_controller.remediation_request.get_actions_runs")
        self.get_actions = actions.start()
        self.get_actions.return_value = {
            "total_count": 1,
            "workflow_runs": [
                {
                    "id": 1,
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": HEAD,
                    "event": "pull_request",
                }
            ],
        }
        self.addCleanup(reviews.stop)
        self.addCleanup(threads.stop)
        self.addCleanup(actions.stop)

    def executable_plan(self):
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
            "base_sha": BASE_SHA,
            "base_repo": REPO,
            "default_branch": "main",
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

    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_base_retarget_before_fresh_sweep_blocks_before_post(self, fresh_plan):
        retargeted_plan = self.executable_plan()
        retargeted_plan["base_ref"] = "release"
        fresh_plan.return_value = retargeted_plan
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
        self.assertEqual("STALE_BASE_TARGET", result["failure_reason"])

    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_resolved_finding_after_identity_lookup_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity
    ):
        fresh_plan.return_value = self.executable_plan()
        get_pr.return_value = safe_pr()
        self.get_threads.return_value = [finding_thread(resolved=True)]
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
        self.assertEqual("NOOP", result["final_outcome"])
        self.assertEqual(
            "NO_UNRESOLVED_CURRENT_HEAD_CODEX_FINDING", result["failure_reason"]
        )

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
        get_pr.return_value = safe_pr()
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

    @patch("agent_controller.remediation_request.post_codex_remediation_request")
    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_ci_rerun_pending_at_final_gate_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity, post
    ):
        fresh_plan.return_value = self.executable_plan()
        get_pr.return_value = safe_pr()
        self.get_actions.return_value = {
            "total_count": 1,
            "workflow_runs": [
                {
                    "id": 1,
                    "status": "queued",
                    "conclusion": None,
                    "head_sha": HEAD,
                    "event": "pull_request",
                }
            ],
        }

        result = execute_codex_remediation_request(
            plan=self.executable_plan(),
            owner="oimus1976",
            repo="agent-controller",
            pr_number=111,
            policy_path="policy.json",
            apply=True,
        )

        post.assert_not_called()
        self.get_actions.assert_called_once_with(
            "oimus1976", "agent-controller", HEAD
        )
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("EXACT_HEAD_CI_NOT_PASS", result["failure_reason"])

    @patch("agent_controller.remediation_request.get_pr_issue_comments")
    @patch("agent_controller.remediation_request.post_codex_remediation_request")
    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_head_drift_during_post_fails_publication_postcondition(
        self,
        fresh_plan,
        _load,
        get_pr,
        _identity,
        post,
        comments,
    ):
        fresh_plan.return_value = self.executable_plan()
        get_pr.side_effect = [safe_pr(), safe_pr(), safe_pr(head_sha=NEW_HEAD)]
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
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("STALE_HEAD_SHA", result["failure_reason"])
        self.assertEqual("FAILED", result["postcondition_result"])

    @patch("agent_controller.remediation_request.get_pr_issue_comments")
    @patch("agent_controller.remediation_request.post_codex_remediation_request")
    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_base_advance_during_post_fails_publication_postcondition(
        self,
        fresh_plan,
        _load,
        get_pr,
        _identity,
        post,
        comments,
    ):
        fresh_plan.return_value = self.executable_plan()
        advanced = safe_pr()
        advanced["base"]["sha"] = NEW_BASE_SHA
        get_pr.side_effect = [safe_pr(), safe_pr(), advanced]
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
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("STALE_BASE_TARGET", result["failure_reason"])
        self.assertEqual("FAILED", result["postcondition_result"])

    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="attacker")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_untrusted_posting_identity_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity
    ):
        fresh_plan.return_value = self.executable_plan()
        get_pr.return_value = safe_pr()
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
        get_pr.side_effect = [safe_pr(), safe_pr(head_sha=NEW_HEAD)]
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

    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_base_retarget_after_identity_lookup_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity
    ):
        fresh_plan.return_value = self.executable_plan()
        retargeted = safe_pr()
        retargeted["base"]["ref"] = "release"
        get_pr.side_effect = [safe_pr(), retargeted]
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
        self.assertEqual("STALE_BASE_TARGET", result["failure_reason"])

    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_base_advance_after_identity_lookup_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity
    ):
        fresh_plan.return_value = self.executable_plan()
        advanced = safe_pr()
        advanced["base"]["sha"] = NEW_BASE_SHA
        get_pr.side_effect = [safe_pr(), advanced]
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
        self.assertEqual("STALE_BASE_TARGET", result["failure_reason"])

    @patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976")
    @patch("agent_controller.remediation_request.get_pr_details")
    @patch("agent_controller.remediation_request.load_policy", return_value=POLICY)
    @patch("agent_controller.remediation_request.plan_codex_remediation_request")
    def test_default_branch_drift_after_identity_lookup_blocks_before_post(
        self, fresh_plan, _load, get_pr, _identity
    ):
        fresh_plan.return_value = self.executable_plan()
        final = safe_pr(head_ref="trunk")
        final["base"] = {
            "ref": "release",
            "repo": {"full_name": REPO, "default_branch": "trunk"},
        }
        get_pr.side_effect = [safe_pr(), final]
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
        self.assertEqual("UNSAFE_IMPLEMENTATION_BRANCH", result["failure_reason"])


if __name__ == "__main__":
    unittest.main()
