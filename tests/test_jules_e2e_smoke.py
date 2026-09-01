import inspect
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock

from agent_controller.jules_draft_publication import DraftPublicationResult
from agent_controller.jules_e2e_smoke import (
    SMOKE_DOC_PATH,
    build_live_smoke,
    run_operator_assisted_smoke,
)
from agent_controller.jules_live import JulesApiClient
from agent_controller.operation_follow import FollowResult, FollowStopReason
from agent_controller.provider_contract import (
    AgentObservation,
    AwaitingInput,
    ControllerState,
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
)
from agent_controller.provider_plan_gate_flow import (
    HumanPlanAction,
    PlanGateCheckpoint,
    PlanGateFlowResult,
    PlanGateFlowStatus,
)
from agent_controller.published_draft_inspection import PublishedDraftInspectionResult
from agent_controller.workstream import WorkstreamBinding
from scripts import run_jules_e2e_smoke as smoke_script


SHA = "a" * 40
HEAD = "b" * 40


def _task():
    return TaskBinding(
        controller_task_id="task-smoke",
        operation_id="op-smoke",
        provider="jules",
        repo="oimus1976/agent-controller",
        expected_start_ref="main",
        expected_start_sha=SHA,
        objective_scope=ObjectiveScope(allowed_paths=(SMOKE_DOC_PATH,)),
        requested_capability="LIVE_JULES_E2E_SMOKE_DOC_ONLY",
        allowed_effects=("SESSION_CREATE", "DRAFT_PR_CREATE"),
        forbidden_effects=("AUTO_CREATE_PR", "PLAN_APPROVAL", "READY", "MERGE"),
        approval_policy_id="adr-90-human-final",
        created_at="2026-09-01T00:00:00Z",
    )


def _workstream():
    return WorkstreamBinding(
        workstream_id="ws-smoke",
        repo="oimus1976/agent-controller",
        root_work_item_ref="github:issue:139",
        task_ids=("task-smoke",),
        github_issues=(139,),
        branch_refs=("controller/live-smoke",),
    )


def _operation():
    return ProviderOperationRef(
        provider="jules",
        provider_operation_id="session-1",
        provider_url="https://jules.example/session-1",
        controller_task_id="task-smoke",
        operation_id="op-smoke",
    )


def _observation(*, state, awaiting=AwaitingInput.NONE, terminal=TerminalClaim.NONE):
    return AgentObservation(
        provider="jules",
        provider_operation_id="session-1",
        observed_at="2026-09-01T00:00:01Z",
        provider_updated_at=None,
        provider_raw_state={},
        mapped_state=state,
        awaiting_input=awaiting,
        terminal_claim=terminal,
    )


def _follow(*, stop, final):
    return FollowResult(
        controller_task_id="task-smoke",
        operation_id="op-smoke",
        provider="jules",
        provider_operation_id="session-1",
        workstream_id="ws-smoke",
        stop_reason=stop,
        outcome_state=final.mapped_state,
        observation_count=1,
        elapsed_seconds=0.1,
        first_observation=final,
        final_observation=final,
    )


def _gate_result(task, workstream, operation):
    gate_obs = _observation(
        state=ControllerState.PLAN_REVIEW_REQUIRED,
        awaiting=AwaitingInput.PLAN_APPROVAL,
    )
    follow = _follow(stop=FollowStopReason.ATTENTION_REQUIRED, final=gate_obs)
    checkpoint = PlanGateCheckpoint(
        task=task,
        operation=operation,
        workstream_binding=workstream,
        expected_provider="jules",
        expected_provider_operation_id="session-1",
        expected_workstream_id="ws-smoke",
        gate_mapped_state=ControllerState.PLAN_REVIEW_REQUIRED,
        gate_awaiting_input=AwaitingInput.PLAN_APPROVAL,
    )
    action = HumanPlanAction(
        workstream_id="ws-smoke",
        controller_task_id="task-smoke",
        operation_id="op-smoke",
        provider="jules",
        provider_operation_id="session-1",
        provider_url=operation.provider_url,
        mapped_state=ControllerState.PLAN_REVIEW_REQUIRED,
        awaiting_input=AwaitingInput.PLAN_APPROVAL,
    )
    return PlanGateFlowResult(
        status=PlanGateFlowStatus.HUMAN_PLAN_ACTION_REQUIRED,
        operation=operation,
        follow_result=follow,
        checkpoint=checkpoint,
        human_action=action,
    )


def _success_resume(operation):
    final = _observation(
        state=ControllerState.ARTIFACT_READY,
        terminal=TerminalClaim.SUCCESS,
    )
    return PlanGateFlowResult(
        status=PlanGateFlowStatus.FOLLOW_STOPPED,
        operation=operation,
        follow_result=_follow(stop=FollowStopReason.TERMINAL_CLAIM, final=final),
    )


class JulesE2ESmokeTests(unittest.TestCase):
    def setUp(self):
        self.task = _task()
        self.workstream = _workstream()
        self.operation = _operation()
        self.gate = _gate_result(self.task, self.workstream, self.operation)
        self.adapter = Mock()
        self.change_reader = Mock()
        self.github = Mock()

    def _run(self, *, resume_result=None, publication=None, inspection=None, waiter=None):
        start_flow = Mock(return_value=self.gate)
        resume_flow = Mock(return_value=resume_result or _success_resume(self.operation))
        publish = Mock(
            return_value=publication
            or DraftPublicationResult(
                "PASS",
                branch="controller/live-smoke",
                commit_sha=HEAD,
                pr_number=140,
                patch_sha256="c" * 64,
                activity_id="activity-1",
            )
        )
        inspect_fn = Mock(
            return_value=inspection
            or PublishedDraftInspectionResult(
                "PASS",
                pr_number=140,
                head_sha=HEAD,
                classification="NEEDS_REVIEW",
                actions_ci_status="PENDING",
                scope_status="SATISFIED",
            )
        )
        waited = []
        waiter = waiter or (lambda action: waited.append(action))
        result = run_operator_assisted_smoke(
            task=self.task,
            workstream=self.workstream,
            destination_branch="controller/live-smoke",
            adapter=self.adapter,
            change_reader=self.change_reader,
            github=self.github,
            wait_for_human=waiter,
            start_flow=start_flow,
            resume_flow=resume_flow,
            publish=publish,
            inspect=inspect_fn,
        )
        return result, start_flow, resume_flow, publish, inspect_fn, waited

    def test_happy_path_uses_one_gate_same_checkpoint_publication_and_inspection(self):
        result, start, resume, publish, inspect_fn, waited = self._run()
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.provider_operation_id, "session-1")
        self.assertEqual(len(waited), 1)
        start.assert_called_once()
        resume.assert_called_once()
        self.assertIs(resume.call_args.kwargs["checkpoint"], self.gate.checkpoint)
        publish.assert_called_once()
        self.assertIs(publish.call_args.kwargs["operation"], self.operation)
        inspect_fn.assert_called_once()

    def test_wait_callback_return_alone_cannot_approve_plan(self):
        still_waiting = self.gate
        result, _, resume, publish, inspect_fn, _ = self._run(
            resume_result=still_waiting,
            waiter=lambda action: None,
        )
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.reason, "PROVIDER_STILL_REQUIRES_PLAN_ACTION")
        resume.assert_called_once()
        publish.assert_not_called()
        inspect_fn.assert_not_called()

    def test_terminal_failure_never_reaches_publication(self):
        final = _observation(
            state=ControllerState.BLOCKED,
            terminal=TerminalClaim.FAILURE,
        )
        failed = PlanGateFlowResult(
            status=PlanGateFlowStatus.FOLLOW_STOPPED,
            operation=self.operation,
            follow_result=_follow(stop=FollowStopReason.TERMINAL_CLAIM, final=final),
        )
        result, _, _, publish, inspect_fn, _ = self._run(resume_result=failed)
        self.assertEqual(result.status, "BLOCKED")
        publish.assert_not_called()
        inspect_fn.assert_not_called()

    def test_publication_uncertainty_stops_before_inspection(self):
        result, _, _, _, inspect_fn, _ = self._run(
            publication=DraftPublicationResult("UNCERTAIN", "PUBLICATION_EXTERNAL_UNCERTAINTY")
        )
        self.assertEqual(result.status, "UNCERTAIN")
        self.assertEqual(result.stage, "PUBLICATION")
        inspect_fn.assert_not_called()

    def test_inspection_uncertainty_never_becomes_e2e_pass(self):
        result, _, _, _, inspect_fn, _ = self._run(
            inspection=PublishedDraftInspectionResult(
                "UNCERTAIN", "INSPECTION_EXTERNAL_UNCERTAINTY"
            )
        )
        self.assertEqual(result.status, "UNCERTAIN")
        self.assertEqual(result.stage, "INSPECTION")
        inspect_fn.assert_called_once()

    def test_build_live_smoke_freezes_exact_doc_only_scope(self):
        class FakeGitHub:
            def get_ref_sha(self, repo, ref):
                self.last = (repo, ref)
                return SHA

            def get_file_text(self, repo, commit_sha, path):
                self.file = (repo, commit_sha, path)
                return None

        github = FakeGitHub()
        api = JulesApiClient(api_key="test-key", transport=lambda req: (200, {}, b"{}"))
        task, workstream, branch, _, _, returned_github = build_live_smoke(
            github=github, api_client=api
        )
        self.assertIs(returned_github, github)
        self.assertEqual(task.expected_start_sha, SHA)
        self.assertEqual(task.objective_scope.allowed_paths, (SMOKE_DOC_PATH,))
        self.assertIn("SESSION_CREATE", task.allowed_effects)
        self.assertIn("DRAFT_PR_CREATE", task.allowed_effects)
        self.assertIn("PLAN_APPROVAL", task.forbidden_effects)
        self.assertIn(branch, workstream.branch_refs)
        self.assertEqual(github.file, (task.repo, SHA, SMOKE_DOC_PATH))

    def test_local_checkout_preflight_requires_root_main_exact_head_and_clean_tree(self):
        cwd = Path.cwd().resolve()

        def make_runner(*, branch="main", head=SHA, status=""):
            def runner(command, **kwargs):
                args = tuple(command[1:])
                outputs = {
                    ("rev-parse", "--show-toplevel"): str(cwd),
                    ("branch", "--show-current"): branch,
                    ("rev-parse", "HEAD"): head,
                    ("status", "--porcelain"): status,
                }
                return subprocess.CompletedProcess(command, 0, stdout=outputs[args] + "\n", stderr="")

            return runner

        smoke_script._verify_local_checkout(expected_sha=SHA, cwd=cwd, runner=make_runner())
        with self.assertRaisesRegex(RuntimeError, "BRANCH_NOT_MAIN"):
            smoke_script._verify_local_checkout(
                expected_sha=SHA, cwd=cwd, runner=make_runner(branch="topic")
            )
        with self.assertRaisesRegex(RuntimeError, "HEAD_NOT_ACCEPTED_MAIN"):
            smoke_script._verify_local_checkout(
                expected_sha=SHA, cwd=cwd, runner=make_runner(head=HEAD)
            )
        with self.assertRaisesRegex(RuntimeError, "CHECKOUT_DIRTY"):
            smoke_script._verify_local_checkout(
                expected_sha=SHA, cwd=cwd, runner=make_runner(status=" M file.txt")
            )

    def test_public_surface_has_no_approval_ready_merge_or_redispatch_argument(self):
        params = set(inspect.signature(run_operator_assisted_smoke).parameters)
        for forbidden in ("approved", "approve", "ready", "merge", "redispatch", "session_id"):
            self.assertNotIn(forbidden, params)

        script = Path("scripts/run_jules_e2e_smoke.py").read_text(encoding="utf-8")
        self.assertIn("Pressing Enter here does NOT approve anything", script)
        self.assertIn("do not retry", script.lower())
        self.assertIn('STATE_FILE = Path(".jules_e2e_smoke_state.json")', script)
        self.assertNotIn("--state-file", script)
        self.assertIn('"provider_operation_id": action.get("provider_operation_id")', script)
        self.assertNotIn("approvePlan", script)
        self.assertNotIn("mark_pull_request_ready", script)
        self.assertNotIn("merge_pull_request", script)


if __name__ == "__main__":
    unittest.main()
