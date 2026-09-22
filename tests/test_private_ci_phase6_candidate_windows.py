import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_controller.operator_step_gate import operator_step_spec_sha256
from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_SCHEMA,
    PHASE5_RESULT_STATUS,
    Phase5ResultEvidence,
    phase5_result_bytes,
)


@unittest.skipUnless(
    os.name == "nt",
    "Windows PowerShell 5.1 Phase 6 candidate regression",
)
class PrivateCiPhase6CandidateWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.producer = (
            cls.repo_root / "scripts" / "Invoke-PrivateCiAstAttestation.ps1"
        )

    def binding(self):
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

    def phase5_result(self):
        b = self.binding()
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

    def test_rendered_phase6_candidate_passes_real_ast_shape_requirements(self):
        from agent_controller.private_ci_phase6_contract import (
            build_phase6_cleanup_operator_spec,
            build_phase6_cleanup_plan,
            phase6_cleanup_plan_bytes,
            render_phase6_cleanup_candidate,
        )

        phase5_raw = phase5_result_bytes(self.phase5_result())
        plan = build_phase6_cleanup_plan(phase5_raw)
        plan_raw = phase6_cleanup_plan_bytes(plan)
        spec = build_phase6_cleanup_operator_spec(
            plan,
            phase6_plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        )
        candidate = render_phase6_cleanup_candidate(plan)

        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate_path = Path(temporary_directory) / "phase6-candidate.ps1"
            candidate_path.write_bytes(candidate.encode("utf-8"))
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(self.producer),
                    "-CandidatePath",
                    str(candidate_path),
                    "-SpecSha256",
                    operator_step_spec_sha256(spec),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["parsed"], report)
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(
            set(report["observed_effect_families"]),
            {
                "ACL_MUTATION",
                "GENERATION_RETIREMENT",
                "HTTP_API_ACCESS",
                "PROCESS_CONTROL",
                "RUNNER_DEREGISTRATION",
            },
        )
        self.assertNotIn(
            "DYNAMIC_OR_UNKNOWN_COMMAND",
            report["observed_effect_families"],
        )
        self.assertEqual(report["automatic_variable_collisions"], [])
        self.assertEqual(report["unresolved_placeholders"], [])
        self.assertEqual(report["forbidden_convenience_paths"], [])
        self.assertTrue(report["fail_fast_proven"])
        self.assertFalse(report["heartbeat_or_progress_proven"])
        self.assertFalse(report["child_exit_code_proven"])


    def test_generation_retirement_bindings_cannot_be_reassigned_after_render(self):
        from agent_controller.private_ci_phase6_contract import (
            build_phase6_cleanup_operator_spec,
            build_phase6_cleanup_plan,
            phase6_cleanup_plan_bytes,
            render_phase6_cleanup_candidate,
        )

        phase5_raw = phase5_result_bytes(self.phase5_result())
        plan = build_phase6_cleanup_plan(phase5_raw)
        plan_raw = phase6_cleanup_plan_bytes(plan)
        spec = build_phase6_cleanup_operator_spec(
            plan,
            phase6_plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        )
        candidate = render_phase6_cleanup_candidate(plan)
        forged_generation = "ac-pilot-fedcba9876543210"
        forged_root = (
            r"C:\ProgramData\agent-controller\private-ci\"
            + forged_generation
        )
        call = "Invoke-PrivateCiGenerationRetirement"
        prefix, separator, suffix = candidate.rpartition(call)
        self.assertEqual(separator, call)
        forged = (
            prefix
            + "$BridgeGenerationRoot = '"
            + forged_root
            + "'\n"
            + "$BridgeEnvironmentGeneration = '"
            + forged_generation
            + "'\n"
            + call
            + suffix
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate_path = Path(temporary_directory) / "phase6-forged.ps1"
            candidate_path.write_bytes(forged.encode("utf-8"))
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(self.producer),
                    "-CandidatePath",
                    str(candidate_path),
                    "-SpecSha256",
                    operator_step_spec_sha256(spec),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        problems = set(report["unresolved_placeholders"])
        self.assertTrue(
            "NONCANONICAL_BINDING:BridgeGenerationRoot" in problems
            or "BINDING_COUNT_INVALID:BridgeGenerationRoot" in problems,
            report,
        )
        self.assertTrue(
            "NONCANONICAL_BINDING:BridgeEnvironmentGeneration" in problems
            or "BINDING_COUNT_INVALID:BridgeEnvironmentGeneration" in problems,
            report,
        )
        self.assertFalse(report["parsed"], report)


if __name__ == "__main__":
    unittest.main()
