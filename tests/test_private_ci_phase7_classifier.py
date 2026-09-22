import inspect
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_SCHEMA,
    PHASE5_RESULT_STATUS,
    Phase5ResultEvidence,
    phase5_result_bytes,
)


def binding(*, runner_name="ac-ci-0123456789abcdef"):
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
        runner_name=runner_name,
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


def phase5_evidence(*, pilot_binding=None):
    b = pilot_binding or binding()
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


class PrivateCiPhase7ClassifierRedTests(unittest.TestCase):
    def result_module(self):
        from agent_controller import private_ci_phase7_result
        return private_ci_phase7_result

    def phase6_module(self):
        from agent_controller import private_ci_phase6_result
        return private_ci_phase6_result

    def classifier_module(self):
        from agent_controller import private_ci_final_classifier
        return private_ci_final_classifier

    def clean_observation(self):
        m = self.result_module()
        return m.ZeroResidualObservation(
            runner_match_count=0,
            active_targetable_run_count=0,
            generation_exists=False,
            workspace_exists=False,
            process_count=0,
            service_count=0,
            task_count=0,
            credential_lifecycle_proven=True,
            target_binding_exact=True,
            github_readback_complete=True,
            local_readback_complete=True,
        )

    def phase6_evidence(
        self,
        *,
        pilot_binding=None,
        phase5_result_sha256="d" * 64,
    ):
        m = self.phase6_module()
        b = pilot_binding or binding()
        return m.Phase6CleanupResultEvidence(
            schema=m.PHASE6_RESULT_SCHEMA,
            binding=b,
            phase6_plan_sha256="c" * 64,
            phase5_result_sha256=phase5_result_sha256,
            human_approval_sha256="e" * 64,
            phase6_consumption_sha256="f" * 64,
            runner_deregistered=True,
            generation_removed=True,
            status=m.PHASE6_RESULT_STATUS,
            completed_at="2026-09-22T12:30:00+00:00",
        )

    def phase7_evidence(
        self,
        *,
        pilot_binding=None,
        phase6_result_sha256="3" * 64,
    ):
        m = self.result_module()
        return m.build_phase7_zero_residual_result(
            binding=pilot_binding or binding(),
            phase6_result_sha256=phase6_result_sha256,
            observation=self.clean_observation(),
        )

    def test_zero_residual_result_requires_every_postcondition(self):
        m = self.result_module()
        evidence = self.phase7_evidence()
        self.assertEqual(evidence.status, m.PHASE7_ZERO_RESIDUAL_STATUS)

        failures = (
            ("runner_match_count", 1, "RUNNER_RESIDUAL"),
            ("active_targetable_run_count", 1, "ACTIVE_JOB_RESIDUAL"),
            ("generation_exists", True, "GENERATION_RESIDUAL"),
            ("workspace_exists", True, "WORKSPACE_RESIDUAL"),
            ("process_count", 1, "PROCESS_RESIDUAL"),
            ("service_count", 1, "SERVICE_RESIDUAL"),
            ("task_count", 1, "TASK_RESIDUAL"),
            ("credential_lifecycle_proven", False, "CREDENTIAL_LIFECYCLE"),
            ("target_binding_exact", False, "TARGET_BINDING_DRIFT"),
            ("github_readback_complete", False, "GITHUB_READBACK"),
            ("local_readback_complete", False, "LOCAL_READBACK"),
        )
        for field, value, reason in failures:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, reason):
                    m.build_phase7_zero_residual_result(
                        binding=binding(),
                        phase6_result_sha256="3" * 64,
                        observation=replace(
                            self.clean_observation(),
                            **{field: value},
                        ),
                    )

    def test_zero_residual_evidence_roundtrips_canonically(self):
        m = self.result_module()
        evidence = self.phase7_evidence()
        raw = m.phase7_result_bytes(evidence)
        self.assertEqual(m.parse_phase7_result_bytes(raw), evidence)

    def test_phase6_result_roundtrips_and_requires_cleanup_pass(self):
        m = self.phase6_module()
        evidence = self.phase6_evidence()
        raw = m.phase6_result_bytes(evidence)
        self.assertEqual(m.parse_phase6_result_bytes(raw), evidence)

        with self.assertRaisesRegex(ValueError, "RUNNER_DEREGISTRATION"):
            m.phase6_result_bytes(
                replace(evidence, runner_deregistered=False)
            )
        with self.assertRaisesRegex(ValueError, "GENERATION_REMOVAL"):
            m.phase6_result_bytes(
                replace(evidence, generation_removed=False)
            )

    def test_final_classifier_owns_durable_single_use_publication(self):
        classifier = self.classifier_module()
        function = classifier.classify_final_private_ci_pilot
        self.assertEqual(
            tuple(inspect.signature(function).parameters),
            (
                "phase5_result_bytes",
                "phase6_result_bytes",
                "phase7_result_bytes",
            ),
        )
        source = inspect.getsource(function)
        self.assertNotIn("already_published", source)
        self.assertIn("consume_final_pass_publication", source)

    def test_final_classifier_requires_authoritative_phase6_phase7_provenance(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()

        self.assertTrue(hasattr(phase6, "validate_phase6_result_authority"))
        self.assertTrue(hasattr(phase7, "validate_phase7_result_authority"))

        source = inspect.getsource(
            classifier.classify_final_private_ci_pilot
        )
        self.assertIn("validate_phase6_result_authority", source)
        self.assertIn("validate_phase7_result_authority", source)

    def test_final_pass_requires_exact_phase5_phase6_phase7_success_chain(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()

        import hashlib

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = phase6.phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase7_raw = phase7.phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            from agent_controller import private_ci_final_publication

            with patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                Path(temporary_directory),
            ):
                result = classifier.classify_final_private_ci_pilot(
                    phase5_result_bytes=phase5_raw,
                    phase6_result_bytes=phase6_raw,
                    phase7_result_bytes=phase7_raw,
                )
                self.assertEqual(result, "SELF_HOSTED_PRIVATE_CI_PASS")

                with self.assertRaisesRegex(
                    ValueError,
                    "already published",
                ):
                    classifier.classify_final_private_ci_pilot(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=phase7_raw,
                    )

    def test_final_classifier_rejects_cross_pilot_evidence(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()
        other = binding(runner_name="ac-ci-fedcba9876543210")

        import hashlib

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = phase6.phase6_result_bytes(
            self.phase6_evidence(
                pilot_binding=other,
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest(),
            )
        )
        phase7_raw = phase7.phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            classifier.classify_final_private_ci_pilot(
                phase5_result_bytes=phase5_raw,
                phase6_result_bytes=phase6_raw,
                phase7_result_bytes=phase7_raw,
            )


if __name__ == "__main__":
    unittest.main()
