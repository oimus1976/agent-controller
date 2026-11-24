import json
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from agent_controller.advance_pr import advance_pr_once
from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
    ProviderCapacityObservation,
)
from agent_controller.provider_capacity_pool import ProviderCapacityPoolObservation
from agent_controller.remediation_request import remediation_findings_sha256
from agent_controller.inspector import build_canonical_review_evidence
from agent_controller.remediation_request_mutator import codex_remediation_request_marker
from agent_controller.review_evidence import REQUIRED_GITHUB_SURFACES, ReviewSurfaceStatus
from agent_controller.review_request_mutator import codex_review_request_marker


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

    def run_advance(self, evidence=None, *, fresh_head=HEAD, apply=False, task=None,
                    confirm_findings=True):
        evidence = evidence or inspection()
        if confirm_findings:
            self.policy["advance_pr"]["bounded_remediation_findings"] = remediation_findings_sha256(evidence)
        Path(self.policy_path).write_text(json.dumps(self.policy))
        with patch("agent_controller.advance_pr.inspect_pr", return_value=evidence), \
             patch("agent_controller.advance_pr.get_pr_details", return_value=pr_snapshot(fresh_head)):
            return advance_pr_once(owner="oimus1976", repo="agent-controller", pr_number=215,
                                   policy_path=self.policy_path, scope_policy={"allowed_paths": ["agent_controller/*"]}, apply=apply,
                                   task_observation=task)

    def test_clean_exact_head_stops_at_human_gate(self):
        result = self.run_advance(inspection("CLEAN"))
        self.assertEqual(result["state"], "HUMAN_GATE_READY")
        self.assertEqual(result["head_sha"], HEAD)
        self.assertEqual(result["pr_url"], "https://github.com/oimus1976/agent-controller/pull/215")

    def test_native_codex_p1_badge_can_request_bounded_remediation(self):
        evidence = inspection("BLOCKING")
        evidence["review_threads_graphql"][0]["comments"]["nodes"][0]["body"] = (
            '**<sub><sub>![P1 Badge](https://img.shields.io/badge/P1-orange?style=flat)'
            '</sub></sub> Correct this bounded defect**')
        with patch("agent_controller.advance_pr.plan_codex_remediation_request", return_value={
                "decision": "EXECUTABLE", "source_head_sha": HEAD}):
            result = self.run_advance(evidence)
        self.assertEqual(result["state"], "REMEDIATE_SCOPED")

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
                        return_value={"final_outcome": "PASS"}) as executor:
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

    def test_dismissed_review_thread_does_not_block_active_p1_remediation(self):
        evidence = inspection("BLOCKING")
        dismissed = {"id": 102, "user": {"login": "chatgpt-codex-connector[bot]"},
                     "commit_id": HEAD, "state": "DISMISSED", "body": ""}
        evidence["reviews"].append(dismissed)
        evidence["review_threads_graphql"].append({
            "id": "thread-2", "isResolved": False, "comments": {"nodes": [{
                "author": {"login": "chatgpt-codex-connector[bot]"},
                "body": "[P3] Dismissed nit", "originalCommit": {"oid": HEAD},
                "pullRequestReview": {"databaseId": 102}}]}})
        with patch("agent_controller.advance_pr.plan_codex_remediation_request", return_value={
                "decision": "EXECUTABLE", "source_head_sha": HEAD}):
            result = self.run_advance(evidence)
        self.assertEqual(result["state"], "REMEDIATE_SCOPED")

    def test_standalone_changes_requested_review_needs_human_and_changes_digest(self):
        evidence = inspection("BLOCKING")
        before = remediation_findings_sha256(evidence)
        evidence["reviews"].append({"id": 103, "user": {"login": "chatgpt-codex-connector[bot]"},
                                    "commit_id": HEAD, "state": "CHANGES_REQUESTED",
                                    "body": "Out-of-scope request"})
        self.assertNotEqual(remediation_findings_sha256(evidence), before)
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

    def test_same_head_changed_findings_invalidate_scope_confirmation(self):
        self.policy["advance_pr"]["bounded_remediation_findings"] = remediation_findings_sha256(
            inspection("BLOCKING"))
        evidence = inspection("BLOCKING")
        evidence["review_threads_graphql"][0]["comments"]["nodes"][0]["body"] = "[P1] Newly reported finding"
        with patch("agent_controller.advance_pr.execute_codex_remediation_request") as executor:
            result = self.run_advance(evidence, apply=True, confirm_findings=False)
        self.assertEqual(result["state"], "STOP_REMEDIATION_SCOPE")
        executor.assert_not_called()

    def test_real_remediation_composition_returns_wait_and_passes_finding_digest(self):
        evidence = inspection("BLOCKING")
        enriched = dict(evidence, head_ref="codex/issue-215", head_repo=REPO,
                        base_ref="main", base_sha="c" * 40, base_repo=REPO,
                        default_branch="main")
        comments = [{"id": 1, "user": {"login": "oimus1976"},
                     "body": "@codex address that feedback\n" +
                     codex_remediation_request_marker(HEAD)}]
        with patch("agent_controller.remediation_request._inspect_remediation_request", return_value=enriched), \
             patch("agent_controller.remediation_request.get_pr_details", return_value=pr_snapshot()), \
             patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976"), \
             patch("agent_controller.remediation_request.get_actions_runs", return_value={"total_count": 1, "workflow_runs": [
                 {"head_sha": HEAD, "event": "pull_request", "status": "completed", "conclusion": "success"}]}), \
             patch("agent_controller.remediation_request.get_pr_issue_comments", return_value=comments), \
             patch("agent_controller.remediation_request.post_codex_remediation_request") as post:
            result = self.run_advance(evidence, apply=True)
        self.assertEqual(result["state"], "WAIT_REMEDIATION", result)
        self.assertEqual(result["execution"]["final_outcome"], "PASS")
        post.assert_called_once()

    def test_real_remediation_rejects_same_head_minor_finding_at_final_gate(self):
        evidence = inspection("BLOCKING")
        enriched = dict(evidence, head_ref="codex/issue-215", head_repo=REPO,
                        base_ref="main", base_sha="c" * 40, base_repo=REPO,
                        default_branch="main")
        changed = inspection("BLOCKING")
        changed["review_threads_graphql"][0]["comments"]["nodes"][0]["body"] = "[P3] Minor new finding"
        changed.update(head_ref="codex/issue-215", head_repo=REPO, base_ref="main",
                       base_sha="c" * 40, base_repo=REPO, default_branch="main")
        with patch("agent_controller.remediation_request._inspect_remediation_request",
                   side_effect=[enriched, enriched, changed]), \
             patch("agent_controller.remediation_request.get_pr_details", return_value=pr_snapshot()), \
             patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976"), \
             patch("agent_controller.remediation_request.post_codex_remediation_request") as post:
            result = self.run_advance(evidence, apply=True)
        self.assertEqual(result["state"], "STOP_PROVIDER")
        self.assertEqual(result["reason"], "REMEDIATION_FINDINGS_CHANGED")
        post.assert_not_called()


def _codex_rate_limits_payload(
    *,
    now=None,
    primary_used=25,
    primary_mins=300,
    primary_reset_offset=timedelta(hours=2),
    secondary_used=40,
    secondary_mins=10080,
    secondary_reset_offset=timedelta(days=5),
    include_primary=True,
    include_secondary=True,
    limit_id="codex",
    extra_buckets=None,
    credits=None,
):
    base = now or datetime.now(timezone.utc)
    primary = (
        {
            "usedPercent": primary_used,
            "windowDurationMins": primary_mins,
            "resetsAt": int((base + primary_reset_offset).timestamp()),
        }
        if include_primary
        else None
    )
    secondary = (
        {
            "usedPercent": secondary_used,
            "windowDurationMins": secondary_mins,
            "resetsAt": int((base + secondary_reset_offset).timestamp()),
        }
        if include_secondary
        else None
    )
    bucket = {
        "limitId": limit_id,
        "limitName": None if limit_id == "codex" else limit_id,
        "planType": "pro",
        "primary": primary,
        "secondary": secondary,
        "rateLimitReachedType": None,
    }
    if credits is not None:
        bucket["credits"] = credits
    by_limit_id = {limit_id: bucket}
    if extra_buckets:
        by_limit_id.update(extra_buckets)
    return json.dumps({
        "rateLimits": bucket,
        "rateLimitsByLimitId": by_limit_id,
    })


class LiveCapacityAdvancePrTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.policy_path = Path(self.directory.name) / "policy.json"
        self.policy = {
            "allowed_actions": ["REQUEST_CODEX_REVIEW", "REQUEST_CODEX_REMEDIATION"],
            "trusted_review_request_authors": ["oimus1976"],
            "advance_pr": {
                "max_remediation_rounds": 3,
                "bounded_remediation_head": HEAD,
                "additional_paid_usage_required": False,
            },
        }

    def run_live(
        self,
        evidence=None,
        *,
        fresh_head=HEAD,
        apply=False,
        task=None,
        confirm_findings=True,
        codex_command="codex",
        codex_timeout=5.0,
    ):
        evidence = evidence or inspection()
        if confirm_findings:
            self.policy["advance_pr"]["bounded_remediation_findings"] = remediation_findings_sha256(evidence)
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        with patch("agent_controller.advance_pr.inspect_pr", return_value=evidence), \
             patch("agent_controller.advance_pr.get_pr_details", return_value=pr_snapshot(fresh_head)):
            return advance_pr_once(
                owner="oimus1976",
                repo="agent-controller",
                pr_number=215,
                policy_path=str(self.policy_path),
                scope_policy={"allowed_paths": ["agent_controller/*"]},
                apply=apply,
                task_observation=task,
                live_capacity=True,
                codex_command=codex_command,
                codex_timeout=codex_timeout,
            )

    def _write_codex_stub(self, payload_text):
        stub_path = Path(self.directory.name) / "codex_live_stub.py"
        stub_path.write_text(
            "\n".join([
                "import json, sys",
                f"RESULT = json.loads({payload_text!r})",
                "for line in sys.stdin:",
                "    line = line.strip()",
                "    if not line:",
                "        continue",
                "    msg = json.loads(line)",
                "    method = msg.get('method')",
                "    if method == 'initialize':",
                "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'userAgent': 'stub'}}) + '\\n')",
                "        sys.stdout.flush()",
                "    elif method == 'account/rateLimits/read':",
                "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': RESULT}) + '\\n')",
                "        sys.stdout.flush()",
                "        break",
            ]) + "\n",
            encoding="utf-8",
        )
        return str(stub_path)

    def test_ac1_live_review_and_remediation_without_manual_capacity_or_policy_rewrite(self):
        payload = _codex_rate_limits_payload()
        self.policy["advance_pr"]["bounded_remediation_findings"] = remediation_findings_sha256(inspection("ABSENT"))
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        before_bytes = self.policy_path.read_bytes()
        with patch("agent_controller.advance_pr.read_codex_rate_limits_result", return_value=payload) as collector, \
             patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
                 "decision": "EXECUTABLE", "head_sha": HEAD}), \
             patch("agent_controller.advance_pr.execute_codex_review_request",
                   return_value={"final_outcome": "SUCCESS"}) as executor:
            dry = self.run_live(apply=False, confirm_findings=False)
            self.assertEqual(self.policy_path.read_bytes(), before_bytes)
            applied = self.run_live(apply=True, confirm_findings=False)
            self.assertEqual(self.policy_path.read_bytes(), before_bytes)
        self.assertEqual(dry["state"], "REQUEST_REVIEW")
        self.assertEqual(dry["reason"], "DRY_RUN")
        self.assertEqual(applied["state"], "WAIT_CURRENT_HEAD_REVIEW")
        self.assertEqual(applied["reason"], "REQUEST_POSTED")
        self.assertEqual(collector.call_count, 2)
        executor.assert_called_once()

        with patch("agent_controller.advance_pr.read_codex_rate_limits_result", return_value=payload), \
             patch("agent_controller.advance_pr.plan_codex_remediation_request", return_value={
                 "decision": "EXECUTABLE", "source_head_sha": HEAD}), \
             patch("agent_controller.advance_pr.execute_codex_remediation_request",
                   return_value={"final_outcome": "PASS"}) as rem_exec:
            rem = self.run_live(inspection("BLOCKING"), apply=True)
        self.assertEqual(rem["state"], "WAIT_REMEDIATION")
        rem_exec.assert_called_once()

    def test_ac1_end_to_end_subprocess_stub_reuses_collector_parser_and_provider_capacity(self):
        stub_cmd = self._write_codex_stub(_codex_rate_limits_payload())
        evidence = inspection("ABSENT")
        enriched = dict(
            evidence,
            draft=True,
            merged=False,
            state="open",
            graphql_error=False,
        )
        posted_comments = [
            {
                "id": 1,
                "user": {"login": "oimus1976"},
                "body": "@codex review\n\n" + codex_review_request_marker(HEAD),
            }
        ]
        with patch("agent_controller.review_request._inspect_review_request", return_value=enriched), \
             patch("agent_controller.review_request.get_pr_details", return_value=pr_snapshot()), \
             patch("agent_controller.review_request.get_authenticated_github_login", return_value="oimus1976"), \
             patch("agent_controller.review_request.get_pr_issue_comments", return_value=posted_comments), \
             patch("agent_controller.review_request.post_codex_review_request") as post:
            dry = self.run_live(evidence, apply=False, codex_command=stub_cmd, codex_timeout=10.0)
            applied = self.run_live(evidence, apply=True, codex_command=stub_cmd, codex_timeout=10.0)
        self.assertEqual(dry["state"], "REQUEST_REVIEW")
        self.assertEqual(dry["reason"], "DRY_RUN")
        self.assertEqual(applied["state"], "WAIT_CURRENT_HEAD_REVIEW")
        self.assertEqual(applied["execution"]["final_outcome"], "SUCCESS")
        post.assert_called_once()

    def test_ac1_cli_routes_live_capacity_flags_and_validates_arguments(self):
        from agent_controller.cli import main

        with patch("sys.argv", [
            "agent_controller", "advance-pr", "--repo", REPO, "--pr", "215",
            "--codex-live-capacity", "--codex-command", "custom-codex", "--codex-timeout", "12",
        ]), patch("agent_controller.cli.advance_pr_once", return_value={"state": "REQUEST_REVIEW"}) as advance, \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            main()
        self.assertEqual(json.loads(output.getvalue()), {"state": "REQUEST_REVIEW"})
        self.assertEqual(advance.call_args.kwargs["live_capacity"], True)
        self.assertEqual(advance.call_args.kwargs["codex_command"], "custom-codex")
        self.assertEqual(advance.call_args.kwargs["codex_timeout"], 12.0)

        with patch("sys.argv", [
            "agent_controller", "advance-pr", "--repo", REPO, "--pr", "215",
            "--codex-live-capacity", "--codex-bin", "bin-codex",
        ]), patch("agent_controller.cli.advance_pr_once", return_value={"state": "REQUEST_REVIEW"}) as advance, \
             patch("sys.stdout", new_callable=io.StringIO):
            main()
        self.assertEqual(advance.call_args.kwargs["codex_command"], "bin-codex")

        for bad_argv in (
            ["agent_controller", "advance-pr", "--repo", REPO, "--pr", "215", "--codex-command", "codex"],
            ["agent_controller", "advance-pr", "--repo", REPO, "--pr", "215", "--codex-timeout", "10"],
            ["agent_controller", "advance-pr", "--repo", REPO, "--pr", "215", "--codex-bin", "codex"],
            ["agent_controller", "advance-pr", "--repo", REPO, "--pr", "215",
             "--codex-live-capacity", "--codex-command", "a", "--codex-bin", "b"],
            ["agent_controller", "advance-pr", "--repo", REPO, "--pr", "215",
             "--codex-live-capacity", "--codex-command", "  "],
            ["agent_controller", "advance-pr", "--repo", REPO, "--pr", "215",
             "--codex-live-capacity", "--codex-timeout", "0"],
            ["agent_controller", "advance-pr", "--repo", REPO, "--pr", "215",
             "--codex-live-capacity", "--codex-timeout", "nan"],
        ):
            with self.subTest(bad_argv=bad_argv), \
                 patch("sys.argv", bad_argv), \
                 patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as ctx:
                    main()
                self.assertEqual(ctx.exception.code, 2)

    def test_ac2_non_executable_and_policy_refusal_states_never_collect_live_capacity(self):
        pending_comment = {
            "id": 1,
            "user": {"login": "oimus1976"},
            "body": "@codex address that feedback\n" + codex_remediation_request_marker(HEAD),
        }
        minor_blocking = inspection("BLOCKING")
        minor_blocking["review_threads_graphql"][0]["comments"]["nodes"][0]["body"] = "[P3] Minor nit"
        out_of_scope = inspection("ABSENT")
        out_of_scope["files"] = [{"filename": "README.md", "changes": 1}]

        pending_review = dict(
            inspection("ABSENT"),
            canonical_review_evidence={
                **inspection("ABSENT")["canonical_review_evidence"],
                "verdict": "PENDING",
            },
        )
        uncertain_review = dict(
            inspection("ABSENT"),
            canonical_review_evidence={
                **inspection("ABSENT")["canonical_review_evidence"],
                "verdict": "UNCERTAIN",
            },
        )
        executable_plan = {"decision": "EXECUTABLE", "head_sha": HEAD}

        cases = [
            ("wait_ci", inspection(ci="PENDING"), {}, None, None, "WAIT_CI"),
            ("stop_ci", inspection(ci="FAILURE"), {}, None, None, "STOP_CI"),
            ("pending_review", pending_review, {}, None, None, "WAIT_CURRENT_HEAD_REVIEW"),
            ("uncertain_review", uncertain_review, {}, None, None, "STOP_REVIEW_EVIDENCE"),
            ("human_gate_ready", inspection("CLEAN"), {}, None, None, "HUMAN_GATE_READY"),
            ("stop_scope", out_of_scope, {}, None, None, "STOP_SCOPE"),
            ("stop_findings", minor_blocking, {}, None, None, "STOP_FINDINGS"),
            ("stop_remediation_scope", inspection("BLOCKING"), {"bounded_remediation_head": NEW_HEAD}, None, None, "STOP_REMEDIATION_SCOPE"),
            ("stop_budget", inspection("BLOCKING"), {"max_remediation_rounds": 0}, None, None, "STOP_BUDGET"),
            ("task_obs_required", inspection("BLOCKING", comments=[pending_comment]), {}, None, None, "STOP_TASK_OBSERVATION_REQUIRED"),
            ("human_apply", inspection("BLOCKING", comments=[pending_comment]), {}, {
                "repo": REPO, "pr": 215, "source_head_sha": HEAD, "status": "complete_pending_apply"
            }, None, "STOP_FOR_HUMAN_APPLY"),
            ("planner_noop", inspection("ABSENT"), {}, None, {"decision": "NOOP", "reason": "REVIEW_ALREADY_REQUESTED_FOR_HEAD"}, "WAIT_CURRENT_HEAD_REVIEW"),
            ("planner_blocked", inspection("ABSENT"), {"allowed_actions": []}, None, None, "STOP_PROVIDER"),
            ("paid_required_true", inspection("ABSENT"), {"additional_paid_usage_required": True}, None, executable_plan, "WAIT_CAPACITY"),
            ("paid_required_missing", inspection("ABSENT"), {"additional_paid_usage_required": "__DELETE__"}, None, executable_plan, "WAIT_CAPACITY"),
        ]
        for label, evidence, adv_overrides, task_obs, mocked_plan, expected_state in cases:
            with self.subTest(case=label):
                overrides = dict(adv_overrides)
                allowed_actions = overrides.pop(
                    "allowed_actions",
                    ["REQUEST_CODEX_REVIEW", "REQUEST_CODEX_REMEDIATION"],
                )
                saved_policy = {
                    "allowed_actions": allowed_actions,
                    "trusted_review_request_authors": ["oimus1976"],
                    "advance_pr": {
                        "max_remediation_rounds": 3,
                        "bounded_remediation_head": HEAD,
                        "additional_paid_usage_required": False,
                        **overrides,
                    },
                }
                if saved_policy["advance_pr"].get("additional_paid_usage_required") == "__DELETE__":
                    del saved_policy["advance_pr"]["additional_paid_usage_required"]
                saved_policy["advance_pr"]["bounded_remediation_findings"] = remediation_findings_sha256(evidence)
                self.policy_path.write_text(json.dumps(saved_policy), encoding="utf-8")
                with patch("agent_controller.advance_pr.inspect_pr", return_value=evidence), \
                     patch("agent_controller.advance_pr.get_pr_details", return_value=pr_snapshot(HEAD)), \
                     patch("agent_controller.advance_pr.read_codex_rate_limits_result") as collector:
                    if mocked_plan is not None:
                        with patch("agent_controller.advance_pr.plan_codex_review_request", return_value=mocked_plan):
                            res = advance_pr_once(
                                owner="oimus1976", repo="agent-controller", pr_number=215,
                                policy_path=str(self.policy_path),
                                scope_policy={"allowed_paths": ["agent_controller/*"]},
                                apply=True, task_observation=task_obs, live_capacity=True,
                            )
                    else:
                        res = advance_pr_once(
                            owner="oimus1976", repo="agent-controller", pr_number=215,
                            policy_path=str(self.policy_path),
                            scope_policy={"allowed_paths": ["agent_controller/*"]},
                            apply=True, task_observation=task_obs, live_capacity=True,
                        )
                self.assertEqual(res["state"], expected_state)
                collector.assert_not_called()

    def test_ac3_exhausted_missing_ambiguous_stale_fail_closed_without_manual_fallback(self):
        # Provide a valid fresh manual capacity entry in policy to prove live failure NEVER falls back to it.
        self.policy["advance_pr"]["capacity"] = {
            "availability": "AVAILABLE",
            "source": "OPERATOR_OBSERVED",
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
        future_epoch = int((datetime.now(timezone.utc) + timedelta(hours=3)).timestamp())
        null_extra_bucket = {
            "codex_other": {
                "limitId": "codex_other",
                "primary": None,
                "secondary": None,
            }
        }
        other_window_bucket = {
            "codex_other": {
                "limitId": "codex_other",
                "primary": {"usedPercent": 10, "windowDurationMins": 60, "resetsAt": future_epoch},
                "secondary": None,
            }
        }
        unclassified_slot_payload = json.dumps({
            "rateLimits": {
                "limitId": "codex",
                "primary": {"usedPercent": 10, "resetsAt": future_epoch},
                "secondary": {"usedPercent": 10, "windowDurationMins": 10080, "resetsAt": future_epoch},
            }
        })
        custom_duration_payload = json.dumps({
            "rateLimits": {
                "limitId": "codex",
                "primary": {"usedPercent": 10, "windowDurationMins": 60, "resetsAt": future_epoch},
                "secondary": {"usedPercent": 10, "windowDurationMins": 10080, "resetsAt": future_epoch},
            }
        })
        duplicate_five_hour_payload = json.dumps({
            "rateLimits": {
                "limitId": "codex",
                "primary": {"usedPercent": 10, "windowDurationMins": 300, "resetsAt": future_epoch},
                "secondary": {"usedPercent": 10, "windowDurationMins": 300, "resetsAt": future_epoch},
            }
        })

        cases = [
            ("five_hour_exhausted", _codex_rate_limits_payload(primary_used=100, secondary_used=10), "CAPACITY_EXHAUSTED"),
            ("weekly_exhausted", _codex_rate_limits_payload(primary_used=10, secondary_used=100), "CAPACITY_EXHAUSTED"),
            ("missing_weekly", _codex_rate_limits_payload(include_secondary=False), "CAPACITY_POOL_MISSING"),
            ("missing_five_hour", _codex_rate_limits_payload(include_primary=False), "CAPACITY_POOL_MISSING"),
            ("ambiguous_multi_bucket_with_windows", _codex_rate_limits_payload(extra_buckets=other_window_bucket), "CAPACITY_POOL_AMBIGUOUS"),
            ("ambiguous_multi_bucket_null_windows", _codex_rate_limits_payload(extra_buckets=null_extra_bucket), "CAPACITY_POOL_AMBIGUOUS"),
            ("ambiguous_non_codex_bucket", _codex_rate_limits_payload(limit_id="codex_other"), "CAPACITY_POOL_AMBIGUOUS"),
            ("ambiguous_missing_duration", unclassified_slot_payload, "CAPACITY_POOL_AMBIGUOUS"),
            ("ambiguous_custom_duration", custom_duration_payload, "CAPACITY_POOL_AMBIGUOUS"),
            ("ambiguous_duplicate_five_hour", duplicate_five_hour_payload, "CAPACITY_POOL_AMBIGUOUS"),
            ("malformed_json", "{not-json", "CAPACITY_COLLECTION_FAILED"),
            ("error_envelope", json.dumps({"error": {"code": -32000, "message": "not signed in"}}), "CAPACITY_COLLECTION_FAILED"),
            ("five_hour_reset_elapsed", _codex_rate_limits_payload(primary_reset_offset=timedelta(seconds=-1)), "CAPACITY_REOBSERVATION_REQUIRED"),
            ("weekly_reset_elapsed", _codex_rate_limits_payload(secondary_reset_offset=timedelta(seconds=-1)), "CAPACITY_REOBSERVATION_REQUIRED"),
        ]
        for label, payload, expected_reason in cases:
            with self.subTest(case=label), \
                 patch("agent_controller.advance_pr.read_codex_rate_limits_result", return_value=payload), \
                 patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
                     "decision": "EXECUTABLE", "head_sha": HEAD}), \
                 patch("agent_controller.advance_pr.execute_codex_review_request") as executor:
                res = self.run_live(apply=True)
                self.assertEqual(res["state"], "WAIT_CAPACITY")
                self.assertEqual(res["reason"], expected_reason)
                self.assertIn("no manual or paid fallback", res["next_action"])
                executor.assert_not_called()

        for exc in (TimeoutError("timed out"), RuntimeError("codex exited")):
            with self.subTest(exc=type(exc).__name__), \
                 patch("agent_controller.advance_pr.read_codex_rate_limits_result", side_effect=exc), \
                 patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
                     "decision": "EXECUTABLE", "head_sha": HEAD}), \
                 patch("agent_controller.advance_pr.execute_codex_review_request") as executor:
                res = self.run_live(apply=True)
                self.assertEqual(res["state"], "WAIT_CAPACITY")
                self.assertEqual(res["reason"], "CAPACITY_COLLECTION_FAILED")
                executor.assert_not_called()

        unknown_pools = (
            ProviderCapacityPoolObservation(
                capacity_pool="codex-five-hour",
                observation=ProviderCapacityObservation(
                    controller_task_id="t", workstream_id="w", operation_id="o",
                    operation_version="1", provider="codex",
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    availability=ProviderAvailability.UNKNOWN,
                    source=CapacityObservationSource.PROVIDER_TELEMETRY,
                ),
                provenance="codex-app-server/account/rateLimits/read",
            ),
            ProviderCapacityPoolObservation(
                capacity_pool="codex-weekly",
                observation=ProviderCapacityObservation(
                    controller_task_id="t", workstream_id="w", operation_id="o",
                    operation_version="1", provider="codex",
                    observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    availability=ProviderAvailability.AVAILABLE,
                    source=CapacityObservationSource.PROVIDER_TELEMETRY,
                ),
                provenance="codex-app-server/account/rateLimits/read",
            ),
        )
        with patch("agent_controller.advance_pr.read_codex_rate_limits_result", return_value=_codex_rate_limits_payload()), \
             patch("agent_controller.advance_pr.parse_codex_rate_limits_capacity", return_value=unknown_pools), \
             patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
                 "decision": "EXECUTABLE", "head_sha": HEAD}), \
             patch("agent_controller.advance_pr.execute_codex_review_request") as executor:
            res = self.run_live(apply=True)
        self.assertEqual(res["state"], "WAIT_CAPACITY")
        self.assertEqual(res["reason"], "CAPACITY_REOBSERVATION_REQUIRED")
        executor.assert_not_called()

        # Static fixture stub has past resetsAt dates relative to current UTC and must fail closed.
        fixture_stub = Path(__file__).parent / "fixtures" / "codex_app_server_stub.py"
        with patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
            "decision": "EXECUTABLE", "head_sha": HEAD}), \
             patch("agent_controller.advance_pr.execute_codex_review_request") as executor:
            res = self.run_live(apply=True, codex_command=str(fixture_stub), codex_timeout=5.0)
        self.assertEqual(res["state"], "WAIT_CAPACITY")
        self.assertEqual(res["reason"], "CAPACITY_REOBSERVATION_REQUIRED")
        executor.assert_not_called()

    def test_ac4_dry_run_and_apply_observe_independently_across_delay(self):
        t0 = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
        clock = {"now": t0, "mono": 100.0}

        class FakeDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock["now"]

        p_first = _codex_rate_limits_payload(now=t0)
        p_second = _codex_rate_limits_payload(now=t0 + timedelta(seconds=600))
        with patch("agent_controller.advance_pr.datetime", FakeDatetime), \
             patch("agent_controller.advance_pr.time.monotonic", side_effect=lambda: clock["mono"]), \
             patch("agent_controller.advance_pr.read_codex_rate_limits_result", side_effect=[p_first, p_second]) as collector, \
             patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
                 "decision": "EXECUTABLE", "head_sha": HEAD}), \
             patch("agent_controller.advance_pr.execute_codex_review_request",
                   return_value={"final_outcome": "SUCCESS"}) as executor:
            dry = self.run_live(apply=False)
            clock["now"] = t0 + timedelta(seconds=600)
            clock["mono"] = 700.0
            applied = self.run_live(apply=True)
        self.assertEqual(dry["state"], "REQUEST_REVIEW")
        self.assertEqual(applied["state"], "WAIT_CURRENT_HEAD_REVIEW")
        self.assertEqual(collector.call_count, 2)
        executor.assert_called_once()

        # Re-observation at --apply sees newly exhausted quota and refuses to post.
        p_exhausted = _codex_rate_limits_payload(now=t0 + timedelta(seconds=1200), primary_used=100)
        with patch("agent_controller.advance_pr.datetime", FakeDatetime), \
             patch("agent_controller.advance_pr.time.monotonic", side_effect=lambda: clock["mono"]), \
             patch("agent_controller.advance_pr.read_codex_rate_limits_result", side_effect=[p_second, p_exhausted]), \
             patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
                 "decision": "EXECUTABLE", "head_sha": HEAD}), \
             patch("agent_controller.advance_pr.execute_codex_review_request") as executor:
            dry2 = self.run_live(apply=False)
            clock["now"] = t0 + timedelta(seconds=1200)
            clock["mono"] = 1300.0
            applied2 = self.run_live(apply=True)
        self.assertEqual(dry2["state"], "REQUEST_REVIEW")
        self.assertEqual(applied2["state"], "WAIT_CAPACITY")
        self.assertEqual(applied2["reason"], "CAPACITY_EXHAUSTED")
        executor.assert_not_called()

    def test_ac4_final_pre_post_gate_aborts_if_300s_ttl_or_reset_expires_before_post(self):
        for scenario in ("ttl_300s", "reset_elapsed"):
            with self.subTest(scenario=scenario):
                t0 = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
                clock = {"now": t0, "mono": 100.0}

                class FakeDatetime(datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return clock["now"]

                reset_offset = timedelta(seconds=10) if scenario == "reset_elapsed" else timedelta(hours=2)
                payload = _codex_rate_limits_payload(now=t0, primary_reset_offset=reset_offset)

                def slow_identity():
                    if scenario == "ttl_300s":
                        clock["now"] = t0 + timedelta(seconds=300)
                        clock["mono"] = 400.0
                    else:
                        clock["now"] = t0 + timedelta(seconds=20)
                        clock["mono"] = 120.0
                    return "oimus1976"

                review_evidence = dict(inspection("ABSENT"), draft=True, merged=False, state="open", graphql_error=False)
                with patch("agent_controller.advance_pr.datetime", FakeDatetime), \
                     patch("agent_controller.advance_pr.time.monotonic", side_effect=lambda: clock["mono"]), \
                     patch("agent_controller.advance_pr.read_codex_rate_limits_result", return_value=payload), \
                     patch("agent_controller.review_request._inspect_review_request", return_value=review_evidence), \
                     patch("agent_controller.review_request.get_pr_details", return_value=pr_snapshot()), \
                     patch("agent_controller.review_request.get_authenticated_github_login", side_effect=slow_identity), \
                     patch("agent_controller.review_request.post_codex_review_request") as post_review:
                    res = self.run_live(review_evidence, apply=True)
                self.assertEqual(res["state"], "WAIT_CAPACITY")
                self.assertEqual(res["reason"], "CAPACITY_REOBSERVATION_REQUIRED")
                self.assertFalse(res["execution"]["mutation_attempted"])
                post_review.assert_not_called()

        # Also verify the real remediation executor pre-mutation capacity gate.
        t0 = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
        clock = {"now": t0, "mono": 50.0}

        class FakeDatetimeRem(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock["now"]

        rem_evidence = dict(
            inspection("BLOCKING"),
            head_ref="codex/issue-215",
            head_repo=REPO,
            base_ref="main",
            base_sha="c" * 40,
            base_repo=REPO,
            default_branch="main",
        )

        def slow_ci(*_args, **_kwargs):
            clock["now"] = t0 + timedelta(seconds=301)
            clock["mono"] = 351.0
            return {
                "total_count": 1,
                "workflow_runs": [
                    {"head_sha": HEAD, "event": "pull_request", "status": "completed", "conclusion": "success"}
                ],
            }

        with patch("agent_controller.advance_pr.datetime", FakeDatetimeRem), \
             patch("agent_controller.advance_pr.time.monotonic", side_effect=lambda: clock["mono"]), \
             patch("agent_controller.advance_pr.read_codex_rate_limits_result",
                   return_value=_codex_rate_limits_payload(now=t0)), \
             patch("agent_controller.remediation_request._inspect_remediation_request", return_value=rem_evidence), \
             patch("agent_controller.remediation_request.get_pr_details", return_value=pr_snapshot()), \
             patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976"), \
             patch("agent_controller.remediation_request.get_actions_runs", side_effect=slow_ci), \
             patch("agent_controller.remediation_request.post_codex_remediation_request") as post_rem:
            res = self.run_live(rem_evidence, apply=True)
        self.assertEqual(res["state"], "WAIT_CAPACITY")
        self.assertEqual(res["reason"], "CAPACITY_REOBSERVATION_REQUIRED")
        self.assertFalse(res["execution"]["mutation_attempted"])
        post_rem.assert_not_called()

    def test_ac5_existing_paid_finding_head_and_dedup_invariants_preserved_in_live_mode(self):
        # Paid-usage prohibition holds even when credits exist in Codex telemetry.
        self.policy["advance_pr"]["additional_paid_usage_required"] = True
        with patch("agent_controller.advance_pr.plan_codex_review_request", return_value={
            "decision": "EXECUTABLE", "head_sha": HEAD}), \
             patch("agent_controller.advance_pr.read_codex_rate_limits_result") as collector:
            paid_res = self.run_live(apply=True)
        self.assertEqual(paid_res["state"], "WAIT_CAPACITY")
        self.assertEqual(paid_res["reason"], "PAID_USAGE_NOT_AUTHORIZED")
        collector.assert_not_called()

        # Reset to unpaid-only policy and verify finding-set, head-drift, and dedup boundaries.
        self.policy["advance_pr"]["additional_paid_usage_required"] = False
        payload = _codex_rate_limits_payload(credits={"hasCredits": True, "unlimited": False, "balance": "10.00"})
        rem_evidence = dict(
            inspection("BLOCKING"),
            head_ref="codex/issue-215",
            head_repo=REPO,
            base_ref="main",
            base_sha="c" * 40,
            base_repo=REPO,
            default_branch="main",
        )
        changed = dict(rem_evidence)
        changed["review_threads_graphql"] = [
            {
                "id": "thread-1",
                "isResolved": False,
                "comments": {
                    "nodes": [
                        {
                            "author": {"login": "chatgpt-codex-connector[bot]"},
                            "body": "[P3] Minor new finding",
                            "originalCommit": {"oid": HEAD},
                            "pullRequestReview": {"databaseId": 101},
                        }
                    ]
                },
            }
        ]
        with patch("agent_controller.advance_pr.read_codex_rate_limits_result", return_value=payload), \
             patch("agent_controller.remediation_request._inspect_remediation_request",
                   side_effect=[rem_evidence, rem_evidence, changed]), \
             patch("agent_controller.remediation_request.get_pr_details", return_value=pr_snapshot()), \
             patch("agent_controller.remediation_request.get_authenticated_github_login", return_value="oimus1976"), \
             patch("agent_controller.remediation_request.post_codex_remediation_request") as post_rem:
            finding_res = self.run_live(rem_evidence, apply=True)
        self.assertEqual(finding_res["state"], "STOP_PROVIDER")
        self.assertEqual(finding_res["reason"], "REMEDIATION_FINDINGS_CHANGED")
        post_rem.assert_not_called()

        # Head drift during executor aborts cleanly without posting.
        review_evidence = dict(inspection("ABSENT"), draft=True, merged=False, state="open", graphql_error=False)
        drifted_evidence = dict(inspection("ABSENT", head=NEW_HEAD), draft=True, merged=False, state="open", graphql_error=False)
        with patch("agent_controller.advance_pr.read_codex_rate_limits_result", return_value=payload), \
             patch("agent_controller.review_request._inspect_review_request",
                   side_effect=[review_evidence, drifted_evidence]), \
             patch("agent_controller.review_request.post_codex_review_request") as post_review:
            head_res = self.run_live(review_evidence, apply=True)
        self.assertEqual(head_res["state"], "STOP_PROVIDER")
        self.assertEqual(head_res["reason"], "STALE_HEAD_SHA")
        post_review.assert_not_called()

        # Existing same-head review request deduplicates via planner NOOP without collecting.
        dup_comment = {
            "id": 2,
            "user": {"login": "oimus1976"},
            "body": "@codex review\n\n" + codex_review_request_marker(HEAD),
        }
        dup_evidence = inspection("ABSENT", comments=[dup_comment])
        with patch("agent_controller.review_request._inspect_review_request", return_value=dup_evidence), \
             patch("agent_controller.advance_pr.read_codex_rate_limits_result") as collector:
            dup_res = self.run_live(dup_evidence, apply=True)
        self.assertEqual(dup_res["state"], "WAIT_CURRENT_HEAD_REVIEW")
        self.assertEqual(dup_res["reason"], "REVIEW_ALREADY_REQUESTED_FOR_HEAD")
        collector.assert_not_called()


if __name__ == "__main__":
    unittest.main()
