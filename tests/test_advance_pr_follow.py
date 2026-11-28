import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from agent_controller import advance_pr, cli, inspector, remediation_request, review_request
from agent_controller.advance_pr_follow import _run_step, follow_pr
from agent_controller.reconciler import ReconcilerLock, pr_lock_path, reconcile_pr_once
from agent_controller.remediation_request import _inspect_remediation_request as inspect_remediation
from agent_controller.review_evidence import REQUIRED_GITHUB_SURFACES, ReviewSurfaceStatus
from tests.test_advance_pr import HEAD, NEW_HEAD, REPO, inspection, pr_snapshot


def pending_review():
    reviews = [{"id": 9, "user": {"login": "chatgpt-codex-connector[bot]"},
                "commit_id": HEAD, "state": "COMMENTED", "body": ""}]
    canonical = inspector.build_canonical_review_evidence(
        repo=REPO, pr_number=215, head_sha=HEAD, reviews=reviews,
        issue_comments=[], review_threads_graphql=[],
        surfaces=tuple(ReviewSurfaceStatus(name, "COMPLETE", True) for name in REQUIRED_GITHUB_SURFACES),
    )
    return dict(inspection(), reviews=reviews, canonical_review_evidence=canonical.to_dict())


class AdvancePrFollowTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.result = self.directory / "result.json"
        self.policy = self.directory / "policy.json"
        self.now = 10.0
        self.sleeps = []
        self.target = dict(owner="oimus1976", repo="agent-controller", pr_number=215)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("tempfile.gettempdir", return_value=tmp.name))
        self.workflow_pass = {"total_count": 1, "workflow_runs": [
            {"head_sha": HEAD, "event": "pull_request", "status": "completed", "conclusion": "success"},
        ]}
        self.rem_evidence = dict(
            inspection("BLOCKING"), head_ref="codex/issue-215", head_repo=REPO,
            base_ref="main", base_sha="c" * 40, base_repo=REPO, default_branch="main",
        )
        self.policy.write_text(json.dumps({
            "allowed_actions": ["REQUEST_CODEX_REVIEW", "REQUEST_CODEX_REMEDIATION"],
            "trusted_review_request_authors": ["oimus1976"],
            "advance_pr": {
                "additional_paid_usage_required": False, "max_remediation_rounds": 2,
                "bounded_remediation_head": HEAD,
                "bounded_remediation_findings": remediation_request.remediation_findings_sha256(self.rem_evidence),
                "capacity": {"availability": "AVAILABLE", "source": "OPERATOR_OBSERVED",
                             "observed_at": datetime.now(timezone.utc).isoformat()},
            },
        }), encoding="utf-8")
        reset = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        self.capacity = {"ordinaryUsageAllowed": True, "rateLimits": {
            "limitId": "codex",
            "primary": {"windowDurationMins": 300, "resetsAt": reset, "usedPercent": 30},
            "secondary": {"windowDurationMins": 10080, "resetsAt": reset, "usedPercent": 10},
        }}
        self.inspect = stack.enter_context(patch.object(advance_pr, "inspect_pr", return_value=inspection()))
        self.pr = stack.enter_context(patch.object(advance_pr, "get_pr_details", return_value=pr_snapshot()))
        self.collect = stack.enter_context(patch.object(advance_pr, "read_codex_rate_limits_result",
                                                     side_effect=lambda *_: json.dumps(self.capacity)))
        self.post_review = self.configure_executor(stack, review_request, "review", inspection())
        self.post_rem = self.configure_executor(stack, remediation_request, "remediation", self.rem_evidence)
        self.actions = stack.enter_context(patch.object(remediation_request, "get_actions_runs",
                                                       return_value=self.workflow_pass))

    def configure_executor(self, stack, module, kind, evidence):
        stack.enter_context(patch.object(module, f"_inspect_{kind}_request", return_value=evidence))
        stack.enter_context(patch.object(module, "get_pr_details", return_value=pr_snapshot()))
        stack.enter_context(patch.object(module, "get_authenticated_github_login", return_value="oimus1976"))
        body = getattr(module, f"codex_{kind}_request_marker")(HEAD)
        message = "@codex review" if kind == "review" else "@codex address that feedback"
        stack.enter_context(patch.object(module, "get_pr_issue_comments", return_value=[
            {"id": 1, "user": {"login": "oimus1976"}, "body": f"{message}\n\n{body}"},
        ]))
        return stack.enter_context(patch.object(module, f"post_codex_{kind}_request"))

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def run_follow(self, **options):
        kwargs = dict(
            **self.target, policy_path=str(self.policy), scope_policy={"allowed_paths": ["agent_controller/*"]},
            apply=True, live_capacity=True, result_file=self.result, interval=1, max_elapsed_seconds=60,
            clock=lambda: self.now, sleep_fn=self.sleep,
            run_step=lambda kwargs, timeout: advance_pr._advance_pr_step(
                **kwargs, step_deadline=time.monotonic() + timeout,
            ),
        )
        return follow_pr(**(kwargs | options))

    def test_ci_wait_posts_one_review_waits_for_clean_and_keeps_capacity_lazy(self):
        seen = []

        def inspect(*args, **kwargs):
            seen.append(self.collect.call_count)
            return [inspection(ci="PENDING"), inspection(), pending_review(),
                    inspection(), inspection("CLEAN")][len(seen) - 1]

        self.inspect.side_effect = inspect
        result = self.run_follow()
        self.assertEqual(result["state"], "HUMAN_GATE_READY")
        self.assertEqual(seen, [0, 0, 1, 1, 1])
        self.assertEqual(result["initial_head_sha"], HEAD)
        self.assertEqual(result["observation_count"], 5)
        self.assertEqual([item["state"] for item in result["transitions"]],
                         ["WAIT_CI", "WAIT_CURRENT_HEAD_REVIEW", "WAIT_CURRENT_HEAD_REVIEW",
                          "WAIT_CURRENT_HEAD_REVIEW", "HUMAN_GATE_READY"])
        self.post_review.assert_called_once_with("oimus1976", "agent-controller", 215, HEAD)
        self.post_rem.assert_not_called()
        self.assertEqual(json.loads(self.result.read_text()), result)

    def test_remediation_stops_at_task_handoff_after_one_request(self):
        self.inspect.side_effect = [pending_review(), self.rem_evidence]
        result = self.run_follow()
        self.assertEqual(result["state"], "WAIT_REMEDIATION")
        self.assertIn("View Task", result["next_action"])
        self.assertEqual(self.sleeps, [1])
        self.collect.assert_called_once()
        self.post_rem.assert_called_once()
        self.post_review.assert_not_called()

    def test_drift_before_planning_does_not_collect_or_post(self):
        result = self.run_follow(expected_head=NEW_HEAD)
        self.assertEqual((result["initial_head_sha"], result["head_sha"]), (NEW_HEAD, HEAD))
        self.assertEqual(result["state"], "STOP_HEAD_CHANGED")
        self.collect.assert_not_called()
        self.post_review.assert_not_called()

        self.inspect.side_effect = [inspection(ci="PENDING"), inspection(head=NEW_HEAD)]
        result = self.run_follow()
        self.assertEqual(result["state"], "STOP_HEAD_CHANGED")
        self.assertEqual((result["initial_head_sha"], result["head_sha"]), (HEAD, NEW_HEAD))
        self.collect.assert_not_called()
        self.post_review.assert_not_called()

    def test_drift_in_first_canonical_collection_preserves_both_heads(self):
        self.inspect.return_value = dict(inspection(), head_after_collection=NEW_HEAD)
        result = self.run_follow()
        self.assertEqual((result["initial_head_sha"], result["head_sha"]), (HEAD, NEW_HEAD))
        self.assertEqual(result["state"], "STOP_HEAD_CHANGED")
        self.collect.assert_not_called()
        self.post_review.assert_not_called()

    def test_same_head_base_retarget_invalidates_scope_for_ready_and_review(self):
        changed = pr_snapshot()
        changed["base"].update(ref="release", sha="d" * 40)
        self.inspect.return_value = inspection("CLEAN")
        self.pr.return_value = changed
        result = self.run_follow()
        self.assertEqual((result["state"], result["reason"]), ("STOP_SCOPE", "STALE_BASE_TARGET"))
        self.collect.assert_not_called()

        self.inspect.return_value = inspection()
        self.pr.return_value = pr_snapshot()
        target = pr_snapshot()

        def identity():
            nonlocal target
            target = changed
            return "oimus1976"

        with patch.object(review_request, "get_pr_details", side_effect=lambda *args: target), \
             patch.object(review_request, "get_authenticated_github_login", side_effect=identity):
            result = self.run_follow()
        self.assertEqual((result["state"], result["reason"]), ("STOP_SCOPE", "STALE_BASE_TARGET"))
        self.post_review.assert_not_called()

    def test_drift_at_each_executors_final_target_check_blocks_post(self):
        review_actual = pr_snapshot()
        rem_actual = pr_snapshot()

        def identity():
            nonlocal review_actual
            review_actual = pr_snapshot(NEW_HEAD)
            return "oimus1976"

        def actions(*args):
            nonlocal rem_actual
            rem_actual = pr_snapshot(NEW_HEAD)
            return self.workflow_pass

        with patch.object(review_request, "get_pr_details", side_effect=lambda *args: review_actual), \
             patch.object(review_request, "get_authenticated_github_login", side_effect=identity):
            review = self.run_follow()
        self.inspect.return_value = self.rem_evidence
        with patch.object(remediation_request, "get_pr_details", side_effect=lambda *args: rem_actual):
            self.actions.side_effect = actions
            rem = self.run_follow()
        for result in (review, rem):
            self.assertEqual(result["state"], "STOP_HEAD_CHANGED")
            self.assertEqual((result["initial_head_sha"], result["head_sha"]), (HEAD, NEW_HEAD))
            self.assertFalse(result["execution"]["mutation_attempted"])
        self.post_review.assert_not_called()
        self.post_rem.assert_not_called()

    def test_review_replans_after_identity_before_the_final_target_check(self):
        marker = review_request.codex_review_request_marker(HEAD)
        comments = [{"id": 1, "user": {"login": "oimus1976"}, "body": f"@codex review\n\n{marker}"}]
        for evidence, expected in (
            (inspection(ci="FAIL"), "EXACT_HEAD_CI_NOT_PASS"),
            (inspection(comments=comments), "REVIEW_ALREADY_REQUESTED_FOR_HEAD"),
        ):
            with self.subTest(expected=expected):
                current = inspection()

                def identity():
                    nonlocal current
                    current = evidence
                    return "oimus1976"

                with patch.object(review_request, "_inspect_review_request", side_effect=lambda *args: current), \
                     patch.object(review_request, "get_authenticated_github_login", side_effect=identity):
                    result = self.run_follow(max_polls=1)
                self.assertEqual(result["transitions"][-1]["reason"], expected)
                self.assertFalse(result["execution"]["mutation_attempted"])
                self.post_review.assert_not_called()

    def test_target_ci_capacity_and_evidence_boundaries(self):
        for snapshot in (dict(pr_snapshot(), state="closed"), dict(pr_snapshot(), merged=True),
                         dict(pr_snapshot(), draft=False)):
            with self.subTest(snapshot=snapshot):
                self.pr.return_value = snapshot
                self.assertEqual(self.run_follow()["state"], "STOP_TARGET")
        self.pr.return_value = pr_snapshot()
        for ci in ("FAIL", "UNAVAILABLE"):
            self.inspect.return_value = inspection(ci=ci)
            self.assertEqual(self.run_follow()["state"], "STOP_CI")
        self.inspect.return_value = dict(inspection(), canonical_review_evidence=None)
        self.assertEqual(self.run_follow()["state"], "STOP_REVIEW_EVIDENCE")
        with patch.object(advance_pr, "inspect_pr", side_effect=OSError):
            self.assertEqual(self.run_follow()["state"], "STOP_EVIDENCE")
        self.collect.assert_not_called()

        self.inspect.return_value = inspection()
        with patch.object(advance_pr, "read_codex_rate_limits_result", side_effect=OSError):
            self.assertEqual(self.run_follow()["reason"], "CAPACITY_COLLECTION_FAILED")
        self.capacity["rateLimits"]["secondary"]["usedPercent"] = 100
        self.assertEqual(self.run_follow()["reason"], "CAPACITY_EXHAUSTED")
        self.collect.reset_mock()
        policy = json.loads(self.policy.read_text())
        policy["advance_pr"]["additional_paid_usage_required"] = True
        self.policy.write_text(json.dumps(policy))
        result = self.run_follow()
        self.assertEqual((result["state"], result["reason"]), ("WAIT_CAPACITY", "PAID_USAGE_NOT_AUTHORIZED"))
        self.collect.assert_not_called()
        self.post_review.assert_not_called()

    def test_review_marker_noop_keeps_polling_without_posting_or_collecting(self):
        marker = review_request.codex_review_request_marker(HEAD)
        comments = [{"id": 1, "user": {"login": "oimus1976"}, "body": f"@codex review\n\n{marker}"}]
        with patch.object(review_request, "_inspect_review_request", return_value=inspection(comments=comments)):
            result = self.run_follow(max_polls=3)
        self.assertEqual(result["reason"], "MAX_OBSERVATIONS")
        self.assertEqual(result["observation_count"], 3)
        self.assertEqual(len(result["transitions"]), 1)
        self.collect.assert_not_called()
        self.post_review.assert_not_called()

    def test_existing_remediation_marker_stops_with_task_action(self):
        marker = remediation_request.codex_remediation_request_marker(HEAD)
        comments = [{"id": 1, "user": {"login": "oimus1976"}, "body": f"@codex address that feedback\n\n{marker}"}]
        self.inspect.return_value = dict(self.rem_evidence, issue_comments=comments)
        result = self.run_follow()
        self.assertEqual(result["state"], "STOP_TASK_OBSERVATION_REQUIRED")
        self.assertIn("View Task", result["next_action"])
        self.post_rem.assert_not_called()
        self.collect.assert_not_called()

    def test_remediation_marker_arriving_during_identity_stops_before_post(self):
        self.inspect.return_value = self.rem_evidence
        marker = remediation_request.codex_remediation_request_marker(HEAD)
        comments = [{"id": 1, "user": {"login": "oimus1976"}, "body": f"@codex address that feedback\n\n{marker}"}]
        current = self.rem_evidence

        def identity():
            nonlocal current
            current = dict(self.rem_evidence, issue_comments=comments)
            return "oimus1976"

        with patch.object(remediation_request, "_inspect_remediation_request", side_effect=lambda *args: current), \
             patch.object(remediation_request, "get_authenticated_github_login", side_effect=identity):
            result = self.run_follow()
        self.assertEqual((result["state"], result["reason"]),
                         ("STOP_TASK_OBSERVATION_REQUIRED", "REMEDIATION_ALREADY_REQUESTED_FOR_SOURCE_HEAD"))
        self.assertIn("View Task", result["next_action"])
        self.assertFalse(result["execution"]["mutation_attempted"])
        self.post_rem.assert_not_called()

    def test_remediation_supplemental_target_read_reports_drift(self):
        self.inspect.return_value = self.rem_evidence
        for drift_phase in ("plan", "after identity"):
            with self.subTest(drift_phase=drift_phase):
                actual = pr_snapshot(NEW_HEAD if drift_phase == "plan" else HEAD)

                def identity():
                    nonlocal actual
                    actual = pr_snapshot(NEW_HEAD)
                    return "oimus1976"

                with patch.object(remediation_request, "_inspect_remediation_request", inspect_remediation), \
                     patch.object(remediation_request, "inspect_pr", return_value=self.rem_evidence), \
                     patch.object(remediation_request, "get_pr_details", side_effect=lambda *args: actual), \
                     patch.object(remediation_request, "get_authenticated_github_login", side_effect=identity):
                    result = self.run_follow()
                self.assertEqual(result["state"], "STOP_HEAD_CHANGED")
                self.assertEqual((result["initial_head_sha"], result["head_sha"]), (HEAD, NEW_HEAD))
                self.post_rem.assert_not_called()

    def test_dry_run_stops_at_first_executable_action(self):
        result = self.run_follow(apply=False)
        self.assertEqual((result["state"], result["reason"]), ("REQUEST_REVIEW", "DRY_RUN"))
        self.assertEqual(result["observation_count"], 1)
        self.post_review.assert_not_called()

    def test_bounds_sleep_and_clock(self):
        self.inspect.return_value = inspection(ci="PENDING")
        result = self.run_follow(max_elapsed_seconds=1.25)
        self.assertEqual(result["reason"], "MAX_ELAPSED")
        self.assertEqual(self.sleeps, [1, 0.25])
        for limits in ({"max_polls": 0}, {"interval": float("inf")}, {"max_elapsed_seconds": float("nan")}):
            with self.subTest(limits=limits):
                self.assertEqual(self.run_follow(**limits)["reason"], "INVALID_FOLLOW_BOUNDS")
        with patch.object(self, "sleep", side_effect=OSError):
            self.assertEqual(self.run_follow()["reason"], "FOLLOW_SLEEP_FAILED")
        self.inspect.reset_mock()
        samples = iter([0, 2, 1])
        self.assertEqual(self.run_follow(clock=lambda: next(samples))["reason"], "MONOTONIC_CLOCK_REVERSED")
        self.assertEqual(self.inspect.call_count, 1)

    def test_conflicts_preserve_active_results_and_allow_single_dry_run(self):
        old = b'{"state":"winner"}'
        self.result.write_bytes(old)
        observed = {}

        def notify(mode, command, path, result):
            observed["notification"] = (path, json.loads(path.read_text()))

        def hold_step(kwargs, timeout):
            observed["conflict"] = self.run_follow(notify_mode="bell", notify=notify)
            observed["winner_during_conflict"] = self.result.read_bytes()
            observed["single"] = advance_pr.advance_pr_once(**self.target, apply=True)
            observed["reconciled"] = reconcile_pr_once(**self.target)
            observed["dry"] = advance_pr.advance_pr_once(**self.target)
            raise OSError("injected worker failure")

        result = self.run_follow(run_step=hold_step)
        self.assertEqual(result["reason"], "FOLLOW_STEP_FAILED")
        conflict = observed["conflict"]
        self.assertEqual(conflict["state"], "STOP_CONFLICT")
        self.assertEqual(conflict["lock_path"], pr_lock_path(**self.target))
        self.assertEqual(observed["winner_during_conflict"], old)
        self.assertEqual(conflict["shared_result_file"], str(self.result.resolve()))
        conflict_path = Path(conflict["result_file"])
        self.assertNotEqual(conflict_path, self.result.resolve())
        self.assertEqual(conflict["notification"], {"status": "SENT"})
        self.assertEqual(json.loads(conflict_path.read_text()), conflict)
        self.assertEqual(observed["notification"][0], conflict_path)
        self.assertEqual(observed["notification"][1]["state"], "STOP_CONFLICT")
        self.assertEqual(observed["notification"][1]["notification"]["status"], "PENDING")
        self.assertEqual(observed["single"]["state"], "STOP_CONFLICT")
        self.assertEqual(observed["reconciled"]["state"], "STOP_CONFLICT")
        self.assertEqual(observed["reconciled"]["action_plan"]["reason"], "CONCURRENT_RECONCILIATION")
        self.assertNotEqual(observed["dry"]["state"], "STOP_CONFLICT")
        lock = ReconcilerLock(pr_lock_path(**self.target))
        self.assertTrue(lock.acquire())
        lock.release()
        self.assertFalse(Path(lock.lock_file).exists())

    def test_reconcile_lock_blocks_follow_even_under_different_repo_case(self):
        lock = ReconcilerLock(pr_lock_path(**self.target))
        self.assertTrue(lock.acquire())
        try:
            result = self.run_follow(owner="OIMUS1976")
            self.assertEqual(result["state"], "STOP_CONFLICT")
            self.assertFalse(self.result.exists())
            self.assertTrue(Path(result["result_file"]).is_file())
        finally:
            lock.release()

    def test_notification_runs_after_persist_and_failure_is_sanitized(self):
        self.inspect.return_value = inspection("CLEAN")
        calls = []

        def notifier(mode, command, path, result):
            calls.append((path, json.loads(path.read_text())))
            raise RuntimeError("private notifier output")

        result = self.run_follow(notify_mode="bell", notify=notifier)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], self.result.resolve())
        self.assertEqual(calls[0][1]["state"], "HUMAN_GATE_READY")
        self.assertEqual(calls[0][1]["notification"]["status"], "PENDING")
        self.assertEqual(result["notification"], {"status": "FAILED", "error": "NOTIFICATION_FAILED"})
        self.assertEqual(json.loads(self.result.read_text()), result)
        self.assertNotIn("private notifier output", self.result.read_text())

    def test_step_and_notification_receive_distinct_finite_timeouts(self):
        budgets = []

        def step(_kwargs, timeout):
            budgets.append(timeout)
            raise subprocess.TimeoutExpired("worker", timeout)

        def notify(*args):
            raise subprocess.TimeoutExpired("notifier", 10)

        result = self.run_follow(max_elapsed_seconds=.25, run_step=step, notify_mode="bell", notify=notify)
        self.assertEqual(budgets, [.25])
        self.assertEqual(result["reason"], "MAX_ELAPSED")
        self.assertEqual(result["notification"], {"status": "FAILED", "error": "NOTIFICATION_TIMED_OUT"})
        self.assertEqual(json.loads(self.result.read_text()), result)
        self.assertEqual(self.sleeps, [])

    def test_real_notification_command_timeout_leaves_terminal_result(self):
        self.inspect.return_value = inspection("CLEAN")
        script = self.directory / "notify.py"
        script.write_text("import time; time.sleep(30)\n", encoding="utf-8")
        with patch("agent_controller.advance_pr_follow.NOTIFY_TIMEOUT", .15):
            result = self.run_follow(notify_mode="command", notify_command=str(script))
        self.assertEqual(result["state"], "HUMAN_GATE_READY")
        self.assertEqual(result["notification"], {"status": "FAILED", "error": "NOTIFICATION_TIMED_OUT"})
        self.assertEqual(json.loads(self.result.read_text()), result)

    def test_cli_routes_follow_options_without_altering_single_shot(self):
        args = ["controller", "advance-pr", "--repo", REPO, "--pr", "215"]
        with patch.object(sys, "argv", args + ["--follow", "--max-polls", "2", "--expected-head", HEAD]), \
             patch.object(cli, "follow_pr", return_value={"state": "WAIT_CI"}) as follow, patch("sys.stdout"):
            cli.main()
        self.assertEqual(follow.call_args.kwargs["expected_head"], HEAD)
        self.assertEqual(follow.call_args.kwargs["max_polls"], 2)
        self.assertFalse(follow.call_args.kwargs["apply"])


class FollowProcessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        # sitecustomize runs inside the real subprocess. No GitHub/agent calls
        # are made, and this is deliberately not a production test switch.
        self.directory.joinpath("sitecustomize.py").write_text(
            "import os, time\n"
            "from agent_controller import advance_pr\n"
            "from tests.test_advance_pr import HEAD, inspection, pr_snapshot\n"
            "advance_pr.inspect_pr = lambda *a, **k: inspection('CLEAN')\n"
            "def snapshot(*a, **k):\n"
            "    time.sleep(float(os.environ['FOLLOW_TEST_DELAY']))\n"
            "    return pr_snapshot()\n"
            "advance_pr.get_pr_details = snapshot\n",
            encoding="utf-8",
        )
        self.env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(self.directory), os.getcwd()]),
                        TEMP=str(self.directory), TMP=str(self.directory), TMPDIR=str(self.directory))

    def test_worker_timeout_cancels_in_flight_call_and_preserves_first_head(self):
        result_path = self.directory / "timeout.json"
        with patch.dict(os.environ, self.env | {"FOLLOW_TEST_DELAY": "30"}):
            started = time.monotonic()
            result = follow_pr(owner="fixture", repo="project", pr_number=215, result_file=result_path,
                               max_elapsed_seconds=2, run_step=_run_step)
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual((result["state"], result["reason"]), ("STOP_WAIT_LIMIT", "MAX_ELAPSED"))
        self.assertEqual(result["observation_count"], 1)
        self.assertEqual(result["initial_head_sha"], HEAD)
        self.assertEqual(json.loads(result_path.read_text()), result)

    def test_detached_follow_finishes_after_its_launcher_exits(self):
        result_path = self.directory / "detached.json"
        cli_args = [
            sys.executable, "-B", "-m", "agent_controller.cli", "advance-pr", "--follow",
            "--repo", REPO, "--pr", "215", "--allowed-paths", "agent_controller/*",
            "--max-polls", "1", "--max-elapsed-seconds", "15", "--expected-head", HEAD,
            "--result-file", str(result_path),
        ]
        launcher = (
            "import os, subprocess, sys\n"
            "opts = {'creationflags': subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP} "
            "if os.name == 'nt' else {'start_new_session': True}\n"
            "subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL, **opts)\n"
        )
        subprocess.run([sys.executable, "-B", "-c", launcher, *cli_args],
                       env=self.env | {"FOLLOW_TEST_DELAY": "1.5"}, check=True, timeout=10)
        self.assertFalse(result_path.exists())
        deadline = time.monotonic() + 12
        while (not result_path.exists() or any(self.directory.glob("agent_controller_pr_*.lock"))) and time.monotonic() < deadline:
            time.sleep(.05)
        result = json.loads(result_path.read_text())
        self.assertEqual(result["state"], "HUMAN_GATE_READY")
        self.assertEqual(result["head_sha"], HEAD)
