import unittest
from dataclasses import replace

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding


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


class PrivateCiPhase7ClassifierRedTests(unittest.TestCase):
    def result_module(self):
        from agent_controller import private_ci_phase7_result
        return private_ci_phase7_result

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

    def test_zero_residual_result_requires_every_postcondition(self):
        m = self.result_module()
        evidence = m.build_phase7_zero_residual_result(
            binding=binding(),
            phase6_result_sha256="1" * 64,
            observation=self.clean_observation(),
        )
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
                        phase6_result_sha256="1" * 64,
                        observation=replace(
                            self.clean_observation(),
                            **{field: value},
                        ),
                    )

    def test_zero_residual_evidence_roundtrips_canonically(self):
        m = self.result_module()
        evidence = m.build_phase7_zero_residual_result(
            binding=binding(),
            phase6_result_sha256="1" * 64,
            observation=self.clean_observation(),
        )
        raw = m.phase7_result_bytes(evidence)
        self.assertEqual(m.parse_phase7_result_bytes(raw), evidence)

    def test_final_pass_requires_exact_phase5_phase6_phase7_success_chain(self):
        result_module = self.result_module()
        classifier = self.classifier_module()

        result = classifier.classify_final_private_ci_pilot(
            binding=binding(),
            phase5_result_sha256="1" * 64,
            phase5_status="PHASE5_EXACTLY_ONE_JOB_PASS",
            phase6_result_sha256="2" * 64,
            phase6_status="PHASE6_CLEANUP_PASS",
            phase7_result_sha256="3" * 64,
            phase7_status=result_module.PHASE7_ZERO_RESIDUAL_STATUS,
            already_published=False,
        )
        self.assertEqual(result, "SELF_HOSTED_PRIVATE_CI_PASS")

        with self.assertRaisesRegex(ValueError, "PHASE7"):
            classifier.classify_final_private_ci_pilot(
                binding=binding(),
                phase5_result_sha256="1" * 64,
                phase5_status="PHASE5_EXACTLY_ONE_JOB_PASS",
                phase6_result_sha256="2" * 64,
                phase6_status="PHASE6_CLEANUP_PASS",
                phase7_result_sha256="3" * 64,
                phase7_status="BLOCKED",
                already_published=False,
            )

        with self.assertRaisesRegex(ValueError, "already published"):
            classifier.classify_final_private_ci_pilot(
                binding=binding(),
                phase5_result_sha256="1" * 64,
                phase5_status="PHASE5_EXACTLY_ONE_JOB_PASS",
                phase6_result_sha256="2" * 64,
                phase6_status="PHASE6_CLEANUP_PASS",
                phase7_result_sha256="3" * 64,
                phase7_status=result_module.PHASE7_ZERO_RESIDUAL_STATUS,
                already_published=True,
            )


if __name__ == "__main__":
    unittest.main()
