import hashlib
import hmac
import unittest
from dataclasses import replace

import agent_controller.operator_step_gate as gate
from agent_controller.operator_step_gate import (
    WINDOWS_POWERSHELL_51,
    WINDOWS_POWERSHELL_PARSER,
    PowerShellAstAttestation,
    ast_attestation_auth_message,
    authenticate_ast_attestation,
    authenticate_prior_evidence,
    configure_controller_authority,
    operator_step_spec_sha256,
    prior_evidence_auth_message,
)
from agent_controller.private_ci_live_registration import (
    FROZEN_ENVIRONMENT_GENERATION,
    FROZEN_PR_NUMBER,
    FROZEN_REPOSITORY,
    FROZEN_RUNNER_LABEL,
    FROZEN_RUNNER_NAME,
    FROZEN_RUNNER_ROOT,
    FROZEN_TARGET_SHA,
    FROZEN_WORKFLOW_SHA,
    LIVE_REGISTRATION_SUCCESS_MARKER,
    LIVE_REGISTRATION_TRANSCRIPT,
    PHASE0_OPERATION_ID,
    PHASE0_STEP_ID,
    LiveRegistrationStatus,
    RegistrationExecution,
    RunnerReadback,
    build_live_registration_spec,
    execute_live_registration,
    frozen_live_registration_binding,
    phase0_evidence_sha256,
    plan_live_registration,
    render_live_registration_candidate,
)


AST_KEY = b"A" * 32
EVIDENCE_KEY = b"E" * 32
PHASE0_EVIDENCE = b"canonical phase0 evidence\nPHASE0_PASS\n"
REGISTRATION_TOKEN = "runner-registration-token-secret"


def authenticated_ast(binding, candidate, evidence_bytes=PHASE0_EVIDENCE):
    spec = build_live_registration_spec(
        binding,
        phase0_evidence_sha256=phase0_evidence_sha256(evidence_bytes),
    )
    report = PowerShellAstAttestation(
        runtime=WINDOWS_POWERSHELL_51,
        parser=WINDOWS_POWERSHELL_PARSER,
        candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        spec_sha256=operator_step_spec_sha256(spec),
        parsed=True,
        error_count=0,
        repository=spec.repository,
        pull_request_number=spec.pull_request_number,
        target_sha=spec.target_sha,
        target_host_role=spec.target_host_role,
        required_identity=spec.required_identity,
        evidence_root=spec.evidence_root,
        transcript_filename=spec.transcript_filename,
        expected_success_marker=spec.expected_success_marker,
        observed_effect_families=spec.allowed_effect_families,
        automatic_variable_collisions=(),
        unresolved_placeholders=(),
        forbidden_convenience_paths=(),
        self_declared_gate_authority=False,
        heartbeat_or_progress_proven=False,
        child_exit_code_proven=False,
        fail_fast_proven=False,
    )
    tag = hmac.new(AST_KEY, ast_attestation_auth_message(report), hashlib.sha256).hexdigest()
    return authenticate_ast_attestation(report, auth_tag=tag)


def authenticated_phase0_evidence(binding, evidence_bytes=PHASE0_EVIDENCE):
    evidence_sha = phase0_evidence_sha256(evidence_bytes)
    message = prior_evidence_auth_message(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        producer_operation_id=PHASE0_OPERATION_ID,
        producer_step_id=PHASE0_STEP_ID,
        evidence_sha256=evidence_sha,
    )
    tag = hmac.new(EVIDENCE_KEY, message, hashlib.sha256).hexdigest()
    return authenticate_prior_evidence(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        producer_operation_id=PHASE0_OPERATION_ID,
        producer_step_id=PHASE0_STEP_ID,
        evidence_bytes=evidence_bytes,
        auth_tag=tag,
    )


class PrivateCiLiveRegistrationTests(unittest.TestCase):
    def setUp(self):
        gate._ACTIVE_CONTROLLER_AUTHORITY = None
        configure_controller_authority(ast_hmac_key=AST_KEY, evidence_hmac_key=EVIDENCE_KEY)
        self.binding = frozen_live_registration_binding()
        self.candidate = render_live_registration_candidate(self.binding)
        self.ast = authenticated_ast(self.binding, self.candidate)

    def tearDown(self):
        gate._ACTIVE_CONTROLLER_AUTHORITY = None

    def test_frozen_binding_matches_issue_216_identity(self):
        self.assertEqual(self.binding.repository, FROZEN_REPOSITORY)
        self.assertEqual(self.binding.pull_request_number, FROZEN_PR_NUMBER)
        self.assertEqual(self.binding.target_sha, FROZEN_TARGET_SHA)
        self.assertEqual(self.binding.workflow_sha, FROZEN_WORKFLOW_SHA)
        self.assertEqual(self.binding.runner_name, FROZEN_RUNNER_NAME)
        self.assertEqual(self.binding.runner_label, FROZEN_RUNNER_LABEL)
        self.assertEqual(self.binding.environment_generation, FROZEN_ENVIRONMENT_GENERATION)
        self.assertEqual(self.binding.runner_root, FROZEN_RUNNER_ROOT)

    def test_candidate_is_token_free_and_ephemeral(self):
        self.assertNotIn(REGISTRATION_TOKEN, self.candidate)
        self.assertNotIn("--token", self.candidate.lower())
        self.assertIn("--ephemeral", self.candidate)
        self.assertIn("--no-default-labels", self.candidate)
        self.assertIn(FROZEN_RUNNER_NAME, self.candidate)
        self.assertIn(FROZEN_RUNNER_LABEL, self.candidate)
        self.assertIn(LIVE_REGISTRATION_TRANSCRIPT, self.candidate)
        self.assertIn(LIVE_REGISTRATION_SUCCESS_MARKER, self.candidate)

    def test_valid_plan_reaches_pass_without_live_callbacks(self):
        result = plan_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=self.candidate,
            ast_attestation=self.ast,
        )
        self.assertTrue(result.passed)

    def test_frozen_binding_drift_is_blocked(self):
        cases = (
            {"repository": "attacker/repo"},
            {"pull_request_number": 999},
            {"target_sha": "b" * 40},
            {"workflow_sha": "c" * 40},
            {"runner_name": "ac-ci-0000000000000000"},
            {"runner_label": "other-label"},
            {"environment_generation": "other-generation"},
            {"runner_root": r"C:\other"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                binding = replace(self.binding, **changes)
                candidate = render_live_registration_candidate(binding)
                ast = authenticated_ast(binding, candidate)
                result = plan_live_registration(
                    binding,
                    phase0_evidence_bytes=PHASE0_EVIDENCE,
                    candidate=candidate,
                    ast_attestation=ast,
                )
                self.assertFalse(result.passed)
                self.assertEqual(result.status.value, "BLOCKED")

    def test_noncanonical_candidate_and_token_literal_are_blocked(self):
        candidate = self.candidate + "Write-Output 'extra'\n"
        ast = authenticated_ast(self.binding, candidate)
        result = plan_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=candidate,
            ast_attestation=ast,
        )
        self.assertFalse(result.passed)
        self.assertIn("LIVE_REGISTRATION_CANDIDATE_NOT_CANONICAL", result.reason_codes)

        candidate_with_token = self.candidate.replace(
            ".\\config.cmd ",
            f".\\config.cmd --token '{REGISTRATION_TOKEN}' ",
        )
        ast_with_token = authenticated_ast(self.binding, candidate_with_token)
        result_with_token = plan_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=candidate_with_token,
            ast_attestation=ast_with_token,
        )
        self.assertFalse(result_with_token.passed)
        self.assertIn("LIVE_REGISTRATION_CANDIDATE_NOT_CANONICAL", result_with_token.reason_codes)

    def test_missing_prior_evidence_blocks_before_any_live_callback(self):
        called = []
        result = execute_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=self.candidate,
            ast_attestation=self.ast,
            prior_evidence_capability=None,
            prepare_runner=lambda binding: called.append("prepare"),
            acquire_registration_token=lambda repo: called.append("token") or REGISTRATION_TOKEN,
            run_registration=lambda binding, token: RegistrationExecution(0, "ok", ""),
            credential_handoff_cleared=lambda binding, token: True,
            read_runners=lambda repo: (),
        )
        self.assertEqual(result.status, LiveRegistrationStatus.BLOCKED)
        self.assertIn("LIVE_GATE_PRIOR_EVIDENCE_CAPABILITY_TYPE_INVALID", result.reason_codes)
        self.assertEqual(called, [])

    def test_prior_evidence_is_consumed_at_live_boundary(self):
        evidence = authenticated_phase0_evidence(self.binding)
        called = []
        runners = (
            RunnerReadback(
                runner_id=17,
                name=self.binding.runner_name,
                status="offline",
                busy=False,
                labels=(self.binding.runner_label,),
                ephemeral=True,
            ),
        )
        first = execute_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=self.candidate,
            ast_attestation=self.ast,
            prior_evidence_capability=evidence,
            prepare_runner=lambda binding: called.append("prepare"),
            acquire_registration_token=lambda repo: called.append("token") or REGISTRATION_TOKEN,
            run_registration=lambda binding, token: called.append("run") or RegistrationExecution(0, "ok", ""),
            credential_handoff_cleared=lambda binding, token: called.append("clear") or True,
            read_runners=lambda repo: called.append("readback") or runners,
        )
        self.assertTrue(first.registered)
        self.assertEqual(called, ["prepare", "token", "run", "clear", "readback"])

        called.clear()
        second = execute_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=self.candidate,
            ast_attestation=self.ast,
            prior_evidence_capability=evidence,
            prepare_runner=lambda binding: called.append("prepare"),
            acquire_registration_token=lambda repo: called.append("token") or REGISTRATION_TOKEN,
            run_registration=lambda binding, token: RegistrationExecution(0, "ok", ""),
            credential_handoff_cleared=lambda binding, token: True,
            read_runners=lambda repo: runners,
        )
        self.assertEqual(second.status, LiveRegistrationStatus.BLOCKED)
        self.assertIn("LIVE_GATE_PRIOR_EVIDENCE_ALREADY_CONSUMED", second.reason_codes)
        self.assertEqual(called, [])

    def test_nonzero_child_exit_stops_before_readback(self):
        evidence = authenticated_phase0_evidence(self.binding)
        readback_called = []
        result = execute_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=self.candidate,
            ast_attestation=self.ast,
            prior_evidence_capability=evidence,
            prepare_runner=lambda binding: None,
            acquire_registration_token=lambda repo: REGISTRATION_TOKEN,
            run_registration=lambda binding, token: RegistrationExecution(37, "partial", "failed"),
            credential_handoff_cleared=lambda binding, token: True,
            read_runners=lambda repo: readback_called.append(True) or (),
        )
        self.assertEqual(result.status, LiveRegistrationStatus.FAILED)
        self.assertEqual(result.reason_codes, ("REGISTRATION_CHILD_EXIT_NONZERO",))
        self.assertEqual(result.child_exit_code, 37)
        self.assertEqual(readback_called, [])

    def test_handoff_not_cleared_stops_before_readback(self):
        evidence = authenticated_phase0_evidence(self.binding)
        readback_called = []
        result = execute_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=self.candidate,
            ast_attestation=self.ast,
            prior_evidence_capability=evidence,
            prepare_runner=lambda binding: None,
            acquire_registration_token=lambda repo: REGISTRATION_TOKEN,
            run_registration=lambda binding, token: RegistrationExecution(0, "ok", ""),
            credential_handoff_cleared=lambda binding, token: False,
            read_runners=lambda repo: readback_called.append(True) or (),
        )
        self.assertEqual(result.status, LiveRegistrationStatus.FAILED)
        self.assertEqual(result.reason_codes, ("REGISTRATION_TOKEN_HANDOFF_NOT_CLEARED",))
        self.assertEqual(readback_called, [])

    def test_token_leak_is_redacted_and_fails_closed(self):
        evidence = authenticated_phase0_evidence(self.binding)
        result = execute_live_registration(
            self.binding,
            phase0_evidence_bytes=PHASE0_EVIDENCE,
            candidate=self.candidate,
            ast_attestation=self.ast,
            prior_evidence_capability=evidence,
            prepare_runner=lambda binding: None,
            acquire_registration_token=lambda repo: REGISTRATION_TOKEN,
            run_registration=lambda binding, token: RegistrationExecution(
                0,
                f"token={REGISTRATION_TOKEN}",
                "",
            ),
            credential_handoff_cleared=lambda binding, token: True,
            read_runners=lambda repo: (),
        )
        self.assertEqual(result.status, LiveRegistrationStatus.FAILED)
        self.assertEqual(result.reason_codes, ("REGISTRATION_TOKEN_LEAKED_TO_CHILD_OUTPUT",))
        self.assertNotIn(REGISTRATION_TOKEN, result.stdout)
        self.assertIn("***", result.stdout)

    def test_duplicate_wrong_or_non_ephemeral_runner_readback_blocks(self):
        cases = (
            (
                RunnerReadback(1, self.binding.runner_name, "online", False, (self.binding.runner_label,), True),
                RunnerReadback(2, "other", "online", False, (self.binding.runner_label,), True),
            ),
            (
                RunnerReadback(1, "wrong", "online", False, (self.binding.runner_label,), True),
            ),
            (
                RunnerReadback(1, self.binding.runner_name, "online", False, (self.binding.runner_label,), False),
            ),
        )
        for runners in cases:
            with self.subTest(runners=runners):
                gate._ACTIVE_CONTROLLER_AUTHORITY = None
                configure_controller_authority(ast_hmac_key=AST_KEY, evidence_hmac_key=EVIDENCE_KEY)
                ast = authenticated_ast(self.binding, self.candidate)
                evidence = authenticated_phase0_evidence(self.binding)
                result = execute_live_registration(
                    self.binding,
                    phase0_evidence_bytes=PHASE0_EVIDENCE,
                    candidate=self.candidate,
                    ast_attestation=ast,
                    prior_evidence_capability=evidence,
                    prepare_runner=lambda binding: None,
                    acquire_registration_token=lambda repo: REGISTRATION_TOKEN,
                    run_registration=lambda binding, token: RegistrationExecution(0, "ok", ""),
                    credential_handoff_cleared=lambda binding, token: True,
                    read_runners=lambda repo, runners=runners: runners,
                )
                self.assertEqual(result.status, LiveRegistrationStatus.FAILED)

    def test_execute_surface_has_no_dispatch_callback(self):
        import inspect
        parameters = inspect.signature(execute_live_registration).parameters
        self.assertNotIn("dispatch", parameters)
        self.assertNotIn("workflow_dispatch", parameters)


if __name__ == "__main__":
    unittest.main()
