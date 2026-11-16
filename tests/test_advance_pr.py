import json
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from agent_controller.advance_pr import advance_pr_once
from agent_controller.inspector import build_canonical_review_evidence
from agent_controller.remediation_request_mutator import codex_remediation_request_marker
from agent_controller.review_evidence import REQUIRED_GITHUB_SURFACES, ReviewSurfaceStatus


REPO = "oimus1976/agent-controller"
HEAD = "a" * 40
NEW_HEAD = "b" * 40


def inspection(verdict="ABSENT", *, head=HEAD, ci="PASS", comments=None):
    reviews = []
    threads = []
    if verdict == "CLEAN":
        reviews = [{"id": 101, "user": {"login": "chatgpt-codex-connector[bot]"},
                    "commit_id": head, "state": "APPROVED", "body": ""}]
    elif verdict == "BLOCKING":
        reviews = [{"id": 101, "user": {"login": "chatgpt-codex-connector[bot]"},
                    "commit_id": head, "state": "COMMENTED", "body": ""}]
        threads = [{"id": "thread-1", "isResolved": False, "comments": {"nodes": [{
            "author": {"login": "chatgpt-codex-connector[bot]"},
            "body": "[P1] Narrow finding", "originalCommit": {"oid": head},
            "pullRequestReview": {"databaseId": 101}}]}}]
    comments = comments or []
    canonical = build_canonical_review_evidence(
        repo=REPO, pr_number=215, head_sha=head, reviews=reviews,
        issue_comments=comments, review_threads_graphql=threads,
        surfaces=tuple(ReviewSurfaceStatus(n, "COMPLETE", True)
                       for n in REQUIRED_GITHUB_SURFACES),
    )
    return {"repo": REPO, "pr": 215, "head_sha": head, "draft": True,
            "merged": False, "state": "open", "changed_files": 1,
            "files": [{"filename": "agent_controller/example.py", "changes": 1}],
            "actions_ci_status": ci, "graphql_error": False,
            "issue_comments": comments, "reviews": reviews,
            "review_threads_graphql": threads,
            "canonical_review_evidence": canonical.to_dict()}


def pr_snapshot(head=HEAD):
    return {"head": {"sha": head, "ref": "codex/issue-215",
                     "repo": {"full_name": REPO}},
            "base": {"sha": "c" * 40, "ref": "main",
                     "repo": {"full_name": REPO, "default_branch": "main"}},
            "draft": True, "merged": False, "state": "open"}


class AdvancePrTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.policy_path = str(Path(self.directory.name) / "policy.json")
        self.policy = {
            "allowed_actions": ["REQUEST_CODEX_REVIEW", "REQUEST_CODEX_REMEDIATION"],
            "trusted_review_request_authors": ["oimus1976"],
            "advance_pr": {"max_remediation_rounds": 3,
                           "bounded_remediation_head": HEAD,
                           "additional_paid_usage_required": False,
                           "capacity": {"availability": "AVAILABLE",
                                        "source": "OPERATOR_OBSERVED",
                                        "observed_at": datetime.now(timezone.utc).isoformat()}},
        }

    def run_advance(self, evidence=None, *, fresh_head=HEAD, apply=False, task=None):
        Path(self.policy_path).write_text(json.dumps(self.policy))
        with patch("agent_controller.advance_pr.inspect_pr", return_value=evidence or inspection()), \
             patch("agent_controller.advance_pr.get_pr_details", return_value=pr_snapshot(fresh_head)):
            return advance_pr_once(owner="oimus1976", repo="agent-controller", pr_number=215,
                                   policy_path=self.policy_path, scope_policy={"allowed_paths": ["agent_controller/*"]}, apply=apply,
                                   task_observation=task)

    def test_clean_exact_head_stops_at_human_gate(self):
        result = self.run_advance(inspection("CLEAN"))
        self.assertEqual(result["state"], "HUMAN_GATE_READY")
        self.assertEqual(result["head_sha"], HEAD)
        self.assertEqual(result["pr_url"], "https://github.com/oimus1976/agent-controller/pull/215")

    def test_pending_ci_does_not_request_review(self):
        with patch("agent_controller.advance_pr.plan_codex_review_request") as planner:
            result = self.run_advance(inspection(ci="PENDING"))
        self.assertEqual(result["state"], "WAIT_CI")
        planner.assert_not_called()

    def test_head_drift_invalidates_clean_evidence(self):
        result = self.run_advance(inspection("CLEAN"), fresh_head=NEW_HEAD)
        self.assertEqual(result["state"], "STOP_HEAD_CHANGED")

    def test_incomplete_canonical_evidence_cannot_reach_ready(self):
        evidence = inspection("CLEAN")
        evidence["canonical_review_evidence"]["collection_complete"] = False
        evidence["canonical_review_evidence"]["surfaces"][0]["status"] = "UNAVAILABLE"
        result = self.run_advance(evidence)
        self.assertEqual(result["state"], "STOP_REVIEW_EVIDENCE")

    def test_absent_review_reuses_planner(self):
        with patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
            "decision": "EXECUTABLE", "head_sha": HEAD,
            "reason": "READY_TO_REQUEST_CODEX_REVIEW"}) as planner:
            result = self.run_advance()
        self.assertEqual(result["state"], "REQUEST_REVIEW")
        planner.assert_called_once()

    def test_blocking_finding_uses_bounded_remediation(self):
        with patch("agent_controller.advance_pr.plan_codex_remediation_request", return_value={
            "decision": "EXECUTABLE", "source_head_sha": HEAD,
            "reason": "READY_TO_REQUEST_CODEX_REMEDIATION"}):
            result = self.run_advance(inspection("BLOCKING"))
        self.assertEqual(result["state"], "REMEDIATE_SCOPED")

    def test_unknown_capacity_does_not_dispatch(self):
        self.policy["advance_pr"]["capacity"]["availability"] = "UNKNOWN"
        with patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
            "decision": "EXECUTABLE", "head_sha": HEAD}), patch(
                "agent_controller.advance_pr.execute_codex_review_request") as executor:
            result = self.run_advance(apply=True)
        self.assertEqual(result["state"], "WAIT_CAPACITY")
        executor.assert_not_called()

    def test_same_source_request_needs_task_observation(self):
        comments = [{"id": 1, "user": {"login": "oimus1976"},
                     "body": "@codex address that feedback\n" + codex_remediation_request_marker(HEAD)}]
        result = self.run_advance(inspection("BLOCKING", comments=comments))
        self.assertEqual(result["state"], "STOP_TASK_OBSERVATION_REQUIRED")

    def test_completed_task_waits_for_human_apply_without_duplicate(self):
        comments = [{"id": 1, "user": {"login": "oimus1976"},
                     "body": "@codex address that feedback\n" + codex_remediation_request_marker(HEAD)}]
        task = {"repo": REPO, "pr": 215, "source_head_sha": HEAD,
                "status": "complete_pending_apply",
                "task_url": "https://chatgpt.com/codex/tasks/task_e_x"}
        with patch("agent_controller.advance_pr.execute_codex_remediation_request") as executor:
            result = self.run_advance(inspection("BLOCKING", comments=comments), apply=True, task=task)
        self.assertEqual(result["state"], "STOP_FOR_HUMAN_APPLY")
        self.assertIn("Update branch", result["next_action"])
        executor.assert_not_called()

    def test_unconfirmed_remediation_scope_stops(self):
        del self.policy["advance_pr"]["bounded_remediation_head"]
        with patch("agent_controller.advance_pr.execute_codex_remediation_request") as executor:
            result = self.run_advance(inspection("BLOCKING"), apply=True)
        self.assertEqual(result["state"], "STOP_REMEDIATION_SCOPE")
        executor.assert_not_called()

    def test_budget_exhaustion_never_dispatches(self):
        self.policy["advance_pr"]["max_remediation_rounds"] = 0
        with patch("agent_controller.advance_pr.execute_codex_remediation_request") as executor:
            result = self.run_advance(inspection("BLOCKING"), apply=True)
        self.assertEqual(result["state"], "STOP_BUDGET")
        executor.assert_not_called()

    def test_one_apply_posts_only_one_operation(self):
        with patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
            "decision": "EXECUTABLE", "head_sha": HEAD}), patch(
                "agent_controller.advance_pr.execute_codex_review_request",
                return_value={"final_outcome": "SUCCESS"}) as review, patch(
                "agent_controller.advance_pr.execute_codex_remediation_request") as remediation:
            result = self.run_advance(apply=True)
        self.assertEqual(result["state"], "WAIT_CURRENT_HEAD_REVIEW")
        review.assert_called_once()
        remediation.assert_not_called()

    def test_new_heads_repeat_ci_and_review_before_ready(self):
        """PR #214 shape: several real fix rounds do not imply final cleanliness."""
        prior_requests = []
        for index, head in enumerate((HEAD, NEW_HEAD, "c" * 40)):
            with self.subTest(round=index):
                self.policy["advance_pr"]["bounded_remediation_head"] = head
                waiting = self.run_advance(
                    inspection("CLEAN", head=head, ci="PENDING", comments=prior_requests),
                    fresh_head=head)
                self.assertEqual(waiting["state"], "WAIT_CI")
                evidence = inspection("BLOCKING", head=head, comments=prior_requests)
                evidence["review_threads_graphql"][0]["comments"]["nodes"][0]["body"] += f" round {index}"
                with patch("agent_controller.advance_pr.plan_codex_remediation_request", return_value={
                    "decision": "EXECUTABLE", "source_head_sha": head}), patch(
                        "agent_controller.advance_pr.execute_codex_remediation_request",
                        return_value={"final_outcome": "SUCCESS"}) as executor:
                    result = self.run_advance(evidence,
                                              fresh_head=head, apply=True)
                self.assertEqual(result["state"], "WAIT_REMEDIATION")
                executor.assert_called_once()
                prior_requests.append({"id": index + 1, "user": {"login": "oimus1976"},
                                       "body": "@codex address that feedback\n" +
                                       codex_remediation_request_marker(head)})
        final = "d" * 40
        result = self.run_advance(inspection("CLEAN", head=final, comments=prior_requests),
                                  fresh_head=final)
        self.assertEqual(result["state"], "HUMAN_GATE_READY")

    def test_minor_or_unknown_severity_needs_human(self):
        for body in ("[P3] Small wording change", "Unclassified finding"):
            with self.subTest(body=body):
                evidence = inspection("BLOCKING")
                evidence["review_threads_graphql"][0]["comments"]["nodes"][0]["body"] = body
                with patch("agent_controller.advance_pr.execute_codex_remediation_request") as executor:
                    result = self.run_advance(evidence, apply=True)
                self.assertEqual(result["state"], "STOP_FINDINGS")
                self.assertEqual(result["reason"], "FINDING_SEVERITY_REQUIRES_HUMAN")
                executor.assert_not_called()

    def test_reappearing_finding_stops_instead_of_spending_another_round(self):
        old_request = {"id": 1, "user": {"login": "oimus1976"},
                       "body": "@codex address that feedback\n" +
                       codex_remediation_request_marker(HEAD)}
        evidence = inspection("BLOCKING", head=NEW_HEAD, comments=[old_request])
        old_thread = inspection("BLOCKING")["review_threads_graphql"][0]
        old_thread["isResolved"] = True
        evidence["review_threads_graphql"].append(old_thread)
        self.policy["advance_pr"]["bounded_remediation_head"] = NEW_HEAD
        with patch("agent_controller.advance_pr.execute_codex_remediation_request") as executor:
            result = self.run_advance(evidence, fresh_head=NEW_HEAD, apply=True)
        self.assertEqual(result["state"], "STOP_FINDINGS")
        self.assertEqual(result["reason"], "INEFFECTIVE_REMEDIATION")
        executor.assert_not_called()

    def test_exhausted_or_elapsed_reset_never_recovers_without_observation(self):
        for state, reset in (("EXHAUSTED", None), ("AVAILABLE", datetime.now(timezone.utc).isoformat())):
            with self.subTest(availability=state):
                self.policy["advance_pr"]["capacity"] = {
                    "availability": state, "source": "OPERATOR_OBSERVED",
                    "observed_at": (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(),
                    "reset_at": reset}
                with patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
                    "decision": "EXECUTABLE", "head_sha": HEAD}), patch(
                        "agent_controller.advance_pr.execute_codex_review_request") as executor:
                    result = self.run_advance(apply=True)
                self.assertEqual(result["state"], "WAIT_CAPACITY")
                self.assertIn(result["reason"], {"CAPACITY_EXHAUSTED", "CAPACITY_REOBSERVATION_REQUIRED"})
                executor.assert_not_called()

    def test_cli_routes_one_target_to_advance_and_prints_result(self):
        from agent_controller.cli import main
        with patch("sys.argv", ["agent_controller", "advance-pr", "--repo", REPO,
                                 "--pr", "215", "--apply"]), patch(
                "agent_controller.cli.advance_pr_once", return_value={"state": "WAIT_CI"}) as advance, patch(
                "sys.stdout", new_callable=io.StringIO) as output:
            main()
        self.assertEqual(json.loads(output.getvalue()), {"state": "WAIT_CI"})
        advance.assert_called_once()
        self.assertEqual(advance.call_args.kwargs["pr_number"], 215)
        self.assertTrue(advance.call_args.kwargs["apply"])


if __name__ == "__main__":
    unittest.main()
