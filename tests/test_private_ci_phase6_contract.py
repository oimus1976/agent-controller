import hashlib
import inspect
import unittest
from pathlib import PureWindowsPath

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_SCHEMA,
    PHASE5_RESULT_STATUS,
    Phase5ResultEvidence,
    phase5_result_bytes,
)


def binding():
    generation = "ac-pilot-0123456789abcdef"
    return PrivateCiPilotBinding(
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-230",
        workflow_sha="2" * 40,
        workflow_path=".github/workflows/private-ci-windows-pilot.yml",
        runner_id=23,
        runner_name="ac-ci-0123456789abcdef",
        runner_label="private-ci-windows-pilot",
        environment_generation=generation,
        runner_root=(
            r"C:\ProgramData\agent-controller\private-ci"
            rf"\{generation}\runner"
        ),
        work_folder="_work",
        host="WOBBUFFET",
        broker_identity=r"WOBBUFFET\c-admin",
        target_identity="ac-runner",
    )


def phase5_evidence():
    b = binding()
    return Phase5ResultEvidence(
        schema=PHASE5_RESULT_SCHEMA,
        binding=b,
        phase5_plan_sha256="1" * 64,
        phase4_result_sha256="2" * 64,
        human_approval_sha256="3" * 64,
        phase5_consumption_sha256="4" * 64,
        candidate_sha256="5" * 64,
        workflow_run_id=9001,
        workflow_run_attempt=1,
        job_id=7001,
        runner_id=b.runner_id,
        runner_name=b.runner_name,
        runner_label=b.runner_label,
        runner_process_id=8123,
        runner_process_owner=r"WOBBUFFET\ac-runner",
        runner_child_exit_code=0,
        security_probe_sha256="6" * 64,
        security_probe_result_sha256="7" * 64,
        security_probe_stdout_sha256="8" * 64,
        security_probe_stderr_sha256="9" * 64,
        runner_stdout_sha256="a" * 64,
        runner_stderr_sha256="b" * 64,
        status=PHASE5_RESULT_STATUS,
        completed_at="2026-09-22T12:00:00+00:00",
    )


class PrivateCiPhase6ContractRedTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_phase6_contract
        return private_ci_phase6_contract

    def plan(self):
        raw = phase5_result_bytes(phase5_evidence())
        return self.module().build_phase6_cleanup_plan(raw)

    def test_cleanup_plan_is_derived_only_from_exact_phase5_evidence(self):
        m = self.module()
        raw = phase5_result_bytes(phase5_evidence())
        digest = hashlib.sha256(raw).hexdigest()

        signature = inspect.signature(m.build_phase6_cleanup_plan)
        self.assertEqual(tuple(signature.parameters), ("phase5_result_bytes",))

        plan = m.build_phase6_cleanup_plan(raw)
        self.assertEqual(plan.schema, m.PHASE6_CLEANUP_PLAN_SCHEMA)
        self.assertEqual(plan.phase5_result_sha256, digest)
        self.assertEqual(plan.binding, binding())
        self.assertEqual(plan.runner_id, binding().runner_id)
        self.assertEqual(plan.runner_name, binding().runner_name)
        self.assertEqual(plan.runner_label, binding().runner_label)
        self.assertEqual(plan.runner_process_id, phase5_evidence().runner_process_id)
        self.assertEqual(
            plan.environment_generation,
            binding().environment_generation,
        )
        self.assertEqual(plan.runner_root, binding().runner_root)

        generation_root = str(PureWindowsPath(binding().runner_root).parent)
        workspace_root = str(
            PureWindowsPath(binding().runner_root) / binding().work_folder
        )
        self.assertEqual(plan.generation_root, generation_root)
        self.assertEqual(plan.workspace_root, workspace_root)
        self.assertTrue(plan.require_zero_services)
        self.assertTrue(plan.require_zero_tasks)

        encoded = m.phase6_cleanup_plan_bytes(plan)
        self.assertEqual(m.parse_phase6_cleanup_plan_bytes(encoded), plan)

    def test_cleanup_plan_exposes_no_arbitrary_delete_target_parameters(self):
        m = self.module()
        parameters = set(inspect.signature(m.build_phase6_cleanup_plan).parameters)
        forbidden = {
            "runner_id",
            "runner_name",
            "runner_label",
            "generation",
            "generation_path",
            "runner_root",
            "work_folder",
            "workspace_root",
            "process_id",
            "service_name",
            "task_name",
            "delete_path",
            "evidence_root",
        }
        self.assertTrue(parameters.isdisjoint(forbidden))

    def test_cleanup_plan_requires_canonical_generation_relationship(self):
        m = self.module()
        plan = self.plan()
        expected_generation_root = (
            "C:\\ProgramData\\agent-controller\\private-ci\\"
            + binding().environment_generation
        )
        self.assertEqual(plan.generation_root, expected_generation_root)
        self.assertEqual(
            plan.runner_root,
            expected_generation_root + r"\runner",
        )
        self.assertEqual(
            plan.workspace_root,
            expected_generation_root + r"\runner\_work",
        )

    def test_cleanup_operator_spec_matches_attestable_direct_effects(self):
        m = self.module()
        plan = self.plan()
        plan_raw = m.phase6_cleanup_plan_bytes(plan)

        spec = m.build_phase6_cleanup_operator_spec(
            plan,
            phase6_plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        )
        self.assertEqual(spec.operation_id, "issue230-phase6-cleanup")
        self.assertEqual(spec.step_id, "cleanup-fresh-pilot")
        self.assertEqual(spec.required_identity, "c-admin")
        self.assertEqual(
            spec.allowed_effect_families,
            (
                "ACL_MUTATION",
                "GENERATION_RETIREMENT",
                "HTTP_API_ACCESS",
                "PROCESS_CONTROL",
                "RUNNER_DEREGISTRATION",
            ),
        )
        self.assertTrue(spec.require_parser_attestation)
        self.assertFalse(spec.require_heartbeat_or_progress)
        self.assertFalse(spec.require_child_exit_code)
        self.assertTrue(spec.require_fail_fast)
        self.assertNotEqual(
            spec.expected_success_marker,
            "SELF_HOSTED_PRIVATE_CI_PASS",
        )

    def test_cleanup_candidate_is_canonical_exact_and_no_broad_sweep(self):
        m = self.module()
        plan = self.plan()
        candidate = m.render_phase6_cleanup_candidate(plan)

        self.assertEqual(candidate, m.render_phase6_cleanup_candidate(plan))
        required = (
            binding().repository,
            binding().runner_name,
            binding().runner_label,
            binding().environment_generation,
            plan.generation_root,
            plan.runner_root,
            plan.workspace_root,
            "actions/runners?per_page=100",
            "actions/runners/23",
            "gh.exe api --method DELETE",
            "Get-CimInstance Win32_Process",
            "Get-CimInstance Win32_Service",
            "Get-ScheduledTask",
            "Stop-Process -Id $BridgeRunnerProcessId",
            "icacls.exe $BridgeRunnerRoot /inheritance:r /grant:r",
            "Invoke-PrivateCiGenerationRetirement",
            "PHASE6_GENERATION_RETIREMENT_IDENTITY_BOUND",
            "Phase 6 runner absent without exact prior cleanup evidence",
            "Phase 6 target PR binding drift",
            "Phase 6 trusted workflow SHA drift",
            "Phase 6 active workflow readback failed",
            "Phase 6 unexpected generation-bound process",
            "Phase 6 unexpected generation-bound service",
            "Phase 6 unexpected generation-bound scheduled task",
            "Phase 6 generation root reparse point blocked",
            "progress phase=phase6",
            "PHASE6_CLEANUP_PASS",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, candidate)

        self.assertEqual(candidate.count("gh.exe api --method DELETE"), 1)
        self.assertNotIn(
            "Remove-Item -LiteralPath $BridgeGenerationRoot",
            candidate,
        )
        self.assertNotIn("Remove-Item -Recurse", candidate)
        self.assertNotIn("SELF_HOSTED_PRIVATE_CI_PASS", candidate)
        self.assertNotIn("Get-ChildItem C:\\", candidate)
        self.assertNotIn("Stop-Process -Name", candidate)
        self.assertNotIn("Remove-Item -Path", candidate)
        self.assertNotIn("-ErrorAction SilentlyContinue", candidate)


if __name__ == "__main__":
    unittest.main()
