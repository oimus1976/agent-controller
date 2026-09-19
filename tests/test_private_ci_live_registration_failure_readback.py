import unittest
from types import SimpleNamespace
from unittest import mock

import agent_controller.private_ci_live_registration as live
from agent_controller.operator_step_gate import OperatorGateStatus
from agent_controller.private_ci_live_registration import (
    LiveRegistrationStatus,
    RegistrationExecution,
    RunnerReadback,
    execute_live_registration,
    frozen_live_registration_binding,
)


class PostFailureReadbackTests(unittest.TestCase):
    def _execute(self, read_runners):
        binding = frozen_live_registration_binding()
        passed = SimpleNamespace(
            status=OperatorGateStatus.PASS_TO_OPERATOR,
            reason_codes=(),
            candidate_sha256="c" * 64,
        )
        with (
            mock.patch.object(live, "plan_live_registration", return_value=passed),
            mock.patch.object(live, "validate_operator_step", return_value=passed),
            mock.patch.object(live, "_require_frozen_target_still_exact"),
        ):
            return execute_live_registration(
                binding,
                phase0_evidence_bytes=b"phase0\n",
                candidate="candidate",
                ast_attestation=object(),
                prior_evidence_capability=object(),
                prepare_runner=lambda observed: None,
                acquire_registration_token=lambda repository: "one-time-token",
                run_registration=lambda observed, token: RegistrationExecution(
                    37, "partial", "failed"
                ),
                credential_handoff_cleared=lambda observed, token: True,
                read_runners=read_runners,
            )

    def test_decode_uncertainty_preserves_exit_and_records_observed_mutation_without_retry(self):
        binding = frozen_live_registration_binding()
        runner = RunnerReadback(
            runner_id=21,
            name=binding.runner_name,
            status="offline",
            busy=False,
            labels=(binding.runner_label,),
            ephemeral=True,
        )
        passed = SimpleNamespace(
            status=OperatorGateStatus.PASS_TO_OPERATOR,
            reason_codes=(),
            candidate_sha256="c" * 64,
        )
        registration_calls = []
        readback_calls = []

        def run_registration(observed, token):
            registration_calls.append((observed, token))
            return RegistrationExecution(
                0,
                "\\x81",
                "",
                output_decoding_uncertain=True,
            )

        def read_runners(repository):
            readback_calls.append(repository)
            return (runner,)

        with (
            mock.patch.object(live, "plan_live_registration", return_value=passed),
            mock.patch.object(live, "validate_operator_step", return_value=passed),
            mock.patch.object(live, "_require_frozen_target_still_exact"),
        ):
            result = execute_live_registration(
                binding,
                phase0_evidence_bytes=b"phase0\n",
                candidate="candidate",
                ast_attestation=object(),
                prior_evidence_capability=object(),
                prepare_runner=lambda observed: None,
                acquire_registration_token=lambda repository: "one-time-token",
                run_registration=run_registration,
                credential_handoff_cleared=lambda observed, token: True,
                read_runners=read_runners,
            )

        self.assertEqual(len(registration_calls), 1)
        self.assertEqual(readback_calls, [binding.repository])
        self.assertEqual(result.status, LiveRegistrationStatus.FAILED)
        self.assertEqual(result.child_exit_code, 0)
        self.assertEqual(result.runner_id, 21)
        self.assertIn("REGISTRATION_NATIVE_OUTPUT_DECODE_FAILED", result.reason_codes)
        self.assertIn(
            "REGISTRATION_MUTATION_OBSERVED_AFTER_DECODE_FAILURE",
            result.reason_codes,
        )

    def test_nonzero_exit_with_matching_remote_runner_records_observed_mutation(self):
        binding = frozen_live_registration_binding()
        runner = RunnerReadback(
            runner_id=17,
            name=binding.runner_name,
            status="offline",
            busy=False,
            labels=(binding.runner_label,),
            ephemeral=True,
        )
        result = self._execute(lambda repository: (runner,))
        self.assertEqual(result.status, LiveRegistrationStatus.FAILED)
        self.assertEqual(result.child_exit_code, 37)
        self.assertEqual(result.runner_id, 17)
        self.assertIn("REGISTRATION_CHILD_EXIT_NONZERO", result.reason_codes)
        self.assertIn(
            "REGISTRATION_MUTATION_OBSERVED_AFTER_CHILD_FAILURE",
            result.reason_codes,
        )

    def test_nonzero_exit_with_no_remote_runner_records_no_observed_mutation(self):
        result = self._execute(lambda repository: ())
        self.assertEqual(result.status, LiveRegistrationStatus.FAILED)
        self.assertEqual(result.child_exit_code, 37)
        self.assertIsNone(result.runner_id)
        self.assertIn("REGISTRATION_CHILD_EXIT_NONZERO", result.reason_codes)
        self.assertNotIn(
            "REGISTRATION_MUTATION_OBSERVED_AFTER_CHILD_FAILURE",
            result.reason_codes,
        )

    def test_nonzero_exit_with_readback_failure_records_uncertainty(self):
        def fail_readback(repository):
            raise RuntimeError("readback unavailable")

        result = self._execute(fail_readback)
        self.assertEqual(result.status, LiveRegistrationStatus.FAILED)
        self.assertEqual(result.child_exit_code, 37)
        self.assertIsNone(result.runner_id)
        self.assertIn("REGISTRATION_CHILD_EXIT_NONZERO", result.reason_codes)
        self.assertIn(
            "RUNNER_READBACK_UNCERTAIN_AFTER_CHILD_FAILURE",
            result.reason_codes,
        )


if __name__ == "__main__":
    unittest.main()
