import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_controller.operator_step_gate import operator_step_spec_sha256
from agent_controller.private_ci_phase4_contract import (
    REGISTRATION_HANDOFF_SCHEMA,
    PrivateCiPilotBinding,
    RegistrationHandoffEvidence,
    build_phase4_target_environment_spec,
    registration_handoff_bytes,
    render_phase4_target_environment_candidate,
)


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 Phase 4 candidate regression")
class PrivateCiPhase4CandidateWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.producer = cls.repo_root / "scripts" / "Invoke-PrivateCiAstAttestation.ps1"

    def binding(self):
        generation = "ac-pilot-0123456789abcdef"
        return PrivateCiPilotBinding(
            repository="oimus1976/example-private",
            pull_request_number=4,
            target_sha="1" * 40,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
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

    def handoff(self, binding):
        return RegistrationHandoffEvidence(
            schema=REGISTRATION_HANDOFF_SCHEMA,
            binding=binding,
            phase0_evidence_sha256="3" * 64,
            registration_plan_sha256="4" * 64,
            human_approval_sha256="5" * 64,
            registration_consumption_sha256="6" * 64,
            registration_result_sha256="7" * 64,
            local_runner_settings_sha256="8" * 64,
            registration_status="REGISTERED",
        )

    def test_rendered_candidate_passes_real_ast_shape_requirements(self):
        binding = self.binding()
        handoff = self.handoff(binding)
        handoff_sha = hashlib.sha256(
            registration_handoff_bytes(handoff)
        ).hexdigest()
        spec = build_phase4_target_environment_spec(
            binding,
            registration_handoff_sha256=handoff_sha,
        )
        candidate = render_phase4_target_environment_candidate(
            binding,
            handoff,
            target_probe_sha256="b" * 64,
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate_path = Path(temporary_directory) / "phase4-candidate.ps1"
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
                "FILESYSTEM_WRITE_MUTATION",
                "PROCESS_CONTROL",
                "PROCESS_LAUNCH",
            },
        )
        self.assertNotIn(
            "DYNAMIC_OR_UNKNOWN_COMMAND",
            report["observed_effect_families"],
        )
        self.assertEqual(report["automatic_variable_collisions"], [])
        self.assertEqual(report["unresolved_placeholders"], [])
        self.assertEqual(report["forbidden_convenience_paths"], [])
        self.assertTrue(report["heartbeat_or_progress_proven"])
        self.assertTrue(report["child_exit_code_proven"])
        self.assertTrue(report["fail_fast_proven"])


if __name__ == "__main__":
    unittest.main()
