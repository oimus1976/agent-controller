import hashlib
import importlib
import unittest

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase4_result import (
    PHASE4_RESULT_SCHEMA,
    PHASE4_RESULT_STATUS,
    Phase4ResultEvidence,
    phase4_result_bytes,
)


MODULE = "agent_controller.private_ci_phase5_contract"


def module():
    return importlib.import_module(MODULE)


def binding():
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


def phase4_evidence():
    return Phase4ResultEvidence(
        schema=PHASE4_RESULT_SCHEMA,
        binding=binding(),
        phase4_plan_sha256="1" * 64,
        registration_handoff_sha256="2" * 64,
        human_approval_sha256="3" * 64,
        phase4_consumption_sha256="4" * 64,
        candidate_sha256="5" * 64,
        target_probe_sha256="6" * 64,
        target_probe_result_sha256="7" * 64,
        target_probe_stdout_sha256="8" * 64,
        target_probe_stderr_sha256="9" * 64,
        runner_generation_snapshot_sha256="a" * 64,
        status=PHASE4_RESULT_STATUS,
        completed_at="2026-09-19T13:00:00+00:00",
    )


class PrivateCiPhase5ContractRedTests(unittest.TestCase):
    def test_phase5_spec_requires_exact_phase4_result(self):
        m = module()
        raw = phase4_result_bytes(phase4_evidence())
        digest = hashlib.sha256(raw).hexdigest()

        spec = m.build_phase5_exactly_one_job_spec(
            binding(),
            phase4_result_sha256=digest,
        )

        self.assertEqual(spec.operation_id, "issue225-phase5-exactly-one-job")
        self.assertEqual(spec.step_id, "run-exactly-one-job")
        self.assertEqual(spec.required_identity, "c-admin")
        self.assertEqual(
            spec.allowed_effect_families,
            (
                "HTTP_API_ACCESS",
                "PROCESS_CONTROL",
                "PROCESS_LAUNCH",
                "WORKFLOW_DISPATCH",
            ),
        )
        self.assertTrue(spec.require_parser_attestation)
        self.assertTrue(spec.require_heartbeat_or_progress)
        self.assertTrue(spec.require_child_exit_code)
        self.assertTrue(spec.require_fail_fast)
        self.assertEqual(
            spec.prior_evidence_requirement.evidence_sha256,
            digest,
        )

    def test_candidate_is_canonical_and_contains_exactly_one_dispatch(self):
        m = module()
        evidence = phase4_evidence()
        raw = phase4_result_bytes(evidence)
        digest = hashlib.sha256(raw).hexdigest()

        candidate = m.render_phase5_exactly_one_job_candidate(
            evidence.binding,
            phase4_result_sha256=digest,
            target_probe_sha256=evidence.target_probe_sha256,
        )
        self.assertEqual(
            candidate,
            m.render_phase5_exactly_one_job_candidate(
                evidence.binding,
                phase4_result_sha256=digest,
            ),
        )
        required = (
            evidence.binding.repository,
            evidence.binding.target_sha,
            evidence.binding.workflow_sha,
            evidence.binding.workflow_path,
            evidence.binding.runner_name,
            evidence.binding.runner_label,
            evidence.binding.environment_generation,
            evidence.binding.runner_root,
            evidence.binding.target_identity,
            "run.cmd",
            "Start-Process",
            "-Credential",
            "-LoadUserProfile",
            "-PassThru",
            "gh.exe api ",
            "event=workflow_dispatch&branch=main&status=queued&per_page=100",
            "event=workflow_dispatch&branch=main&status=in_progress&per_page=100",
            "event=workflow_dispatch&branch=main&status=requested&per_page=100",
            "event=workflow_dispatch&branch=main&status=waiting&per_page=100",
            "event=workflow_dispatch&branch=main&status=pending&per_page=100",
            "queued trusted workflow exists before runner start",
            "requested trusted workflow exists before runner start",
            "waiting trusted workflow exists before dispatch",
            "pending trusted workflow exists before dispatch",
            "in-progress trusted workflow exists before dispatch",
            "actions/runners?per_page=100",
            "Phase 5 pre-dispatch eligible runner cardinality invalid",
            "Phase 5 pre-dispatch runner is not online",
            "Phase 5 pre-dispatch runner is busy",
            "gh.exe api --method POST",
            "inputs[pr_number]=4",
            f"inputs[expected_sha]={evidence.binding.target_sha}",
            (
                "inputs[expected_workflow_sha]="
                + evidence.binding.workflow_sha
            ),
            (
                "inputs[expected_runner_name]="
                + evidence.binding.runner_name
            ),
            "PHASE5_RUNNER_PROCESS_ID=",
            "PHASE5_RUNNER_PROCESS_OWNER=",
            "Invoke-CimMethod",
            "-MethodName GetOwner",
            "PHASE5_WORKFLOW_RUN_ID=",
            "heartbeat phase=phase5",
            "$BridgeChild.ExitCode",
            "PHASE5_EXACTLY_ONE_JOB_ATTEMPT_COMPLETE",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, candidate)

        self.assertEqual(candidate.count("gh.exe api --method POST"), 1)
        self.assertNotIn("return_run_details", candidate)
        self.assertNotIn("SELF_HOSTED_PRIVATE_CI_PASS", candidate)
        self.assertNotIn("-UseNewEnvironment", candidate)


    def test_candidate_revalidates_target_security_context_before_listener(self):
        m = module()
        evidence = phase4_evidence()
        raw = phase4_result_bytes(evidence)
        digest = hashlib.sha256(raw).hexdigest()
        candidate = m.render_phase5_exactly_one_job_candidate(
            evidence.binding,
            phase4_result_sha256=digest,
            target_probe_sha256=evidence.target_probe_sha256,
        )
        probe = candidate.index("$BridgeSecurityProbeChild = Start-Process")
        probe_pass = candidate.index(
            "PHASE5_SECURITY_CONTEXT_REVALIDATED",
            probe,
        )
        listener = candidate.index(
            "$BridgeChild = Start-Process -FilePath 'cmd.exe'",
            probe_pass,
        )
        self.assertLess(probe, probe_pass)
        self.assertLess(probe_pass, listener)
        self.assertIn(
            "issue225-phase5-result-" + digest + ".consumed.json",
            candidate,
        )
        self.assertIn("Phase 5 target gh authentication isolation failed", candidate)
        self.assertIn("Phase 5 broker credential isolation failed", candidate)
        self.assertIn("Phase 5 security probe admin status unsafe", candidate)
        self.assertIn("Phase 5 durable authority isolation failed", candidate)

    def test_candidate_rejects_invalid_security_probe_digest(self):
        m = module()
        with self.assertRaisesRegex(ValueError, "target probe SHA-256"):
            m.render_phase5_exactly_one_job_candidate(
                binding(),
                phase4_result_sha256="a" * 64,
                target_probe_sha256="short",
            )

    def test_candidate_requires_dispatch_response_with_positive_run_id(self):
        m = module()
        candidate = m.render_phase5_exactly_one_job_candidate(
            binding(),
            phase4_result_sha256="a" * 64,
            target_probe_sha256="b" * 64,
        )
        self.assertIn("ConvertFrom-Json", candidate)
        self.assertIn("workflow_run_id", candidate)
        self.assertIn("throw 'Phase 5 dispatch response", candidate)

    def test_invalid_binding_or_phase4_digest_is_rejected(self):
        m = module()
        with self.assertRaisesRegex(ValueError, "pilot binding"):
            m.build_phase5_exactly_one_job_spec(
                binding().__class__(
                    **{
                        **{
                            field: getattr(binding(), field)
                            for field in binding().__dataclass_fields__
                        },
                        "runner_id": 0,
                    }
                ),
                phase4_result_sha256="a" * 64,
            )
        with self.assertRaisesRegex(ValueError, "Phase 4 result SHA-256"):
            m.render_phase5_exactly_one_job_candidate(
                binding(),
                phase4_result_sha256="short",
                target_probe_sha256="b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
