import hashlib
import inspect
import unittest

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
        self.assertEqual(
            plan.environment_generation,
            binding().environment_generation,
        )
        self.assertEqual(plan.runner_root, binding().runner_root)
        self.assertEqual(plan.work_folder, binding().work_folder)

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
            "process_id",
            "service_name",
            "task_name",
            "delete_path",
            "evidence_root",
        }
        self.assertTrue(parameters.isdisjoint(forbidden))

    def test_cleanup_operator_spec_is_bounded_and_cannot_publish_final_pass(self):
        m = self.module()
        raw = phase5_result_bytes(phase5_evidence())
        plan = m.build_phase6_cleanup_plan(raw)
        plan_raw = m.phase6_cleanup_plan_bytes(plan)

        spec = m.build_phase6_cleanup_operator_spec(
            plan,
            phase6_plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        )
        self.assertEqual(spec.operation_id, "issue230-phase6-cleanup")
        self.assertEqual(spec.step_id, "cleanup-fresh-pilot")
        self.assertEqual(spec.required_identity, "c-admin")
        self.assertTrue(spec.require_parser_attestation)
        self.assertTrue(spec.require_heartbeat_or_progress)
        self.assertTrue(spec.require_child_exit_code)
        self.assertTrue(spec.require_fail_fast)
        self.assertNotEqual(
            spec.expected_success_marker,
            "SELF_HOSTED_PRIVATE_CI_PASS",
        )


if __name__ == "__main__":
    unittest.main()
