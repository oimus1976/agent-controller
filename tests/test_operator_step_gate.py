import hashlib
import hmac
import unittest
from dataclasses import replace

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    WINDOWS_POWERSHELL_PARSER,
    AuthenticatedAstAttestation,
    OperatorEffectClass,
    OperatorGateStatus,
    OperatorStepSpec,
    PowerShellAstAttestation,
    PriorEvidenceCapability,
    PriorEvidenceRequirement,
    ast_attestation_auth_message,
    authenticate_ast_attestation,
    authenticate_prior_evidence,
    configure_controller_authority,
    operator_step_spec_sha256,
    prior_evidence_auth_message,
    validate_operator_step,
)


REPOSITORY = "owner/private-repo"
PR_NUMBER = 42
TARGET_SHA = "a" * 40
HOST_ROLE = "owner-machine-broker"
IDENTITY = "c-admin"
TRANSCRIPT = "issue211-readonly.log"
SUCCESS_MARKER = "ISSUE211_READ_ONLY_PASS"
AST_KEY = b"A" * 32
EVIDENCE_KEY = b"E" * 32
EVIDENCE_BYTES = b"trusted prior operator evidence\n"
EVIDENCE_SHA = hashlib.sha256(EVIDENCE_BYTES).hexdigest()


def setUpModule():
    configure_controller_authority(ast_hmac_key=AST_KEY, evidence_hmac_key=EVIDENCE_KEY)


def make_spec(**changes):
    spec = OperatorStepSpec(
        operation_id="issue211-operator-gate",
        step_id="readonly-preflight",
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=REPOSITORY,
        pull_request_number=PR_NUMBER,
        target_sha=TARGET_SHA,
        target_host_role=HOST_ROLE,
        required_identity=IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.READ_ONLY,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=TRANSCRIPT,
        expected_success_marker=SUCCESS_MARKER,
        allowed_effect_families=(),
        prior_evidence_requirement=None,
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=False,
        require_fail_fast=False,
    )
    return replace(spec, **changes)


def make_candidate(extra=""):
    return f"Write-Output 'bounded candidate'\n{extra}\n"


def make_report(spec, candidate, **changes):
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
        observed_effect_families=(),
        automatic_variable_collisions=(),
        unresolved_placeholders=(),
        forbidden_convenience_paths=(),
        self_declared_gate_authority=False,
        heartbeat_or_progress_proven=False,
        child_exit_code_proven=False,
        fail_fast_proven=False,
    )
    return replace(report, **changes)


def authenticate_report(report, *, key=AST_KEY):
    tag = hmac.new(key, ast_attestation_auth_message(report), hashlib.sha256).hexdigest()
    return authenticate_ast_attestation(report, auth_tag=tag)


def make_mutation_spec(**changes):
    requirement = PriorEvidenceRequirement(
        producer_operation_id="issue211-preflight",
        producer_step_id="readonly-preflight",
        evidence_sha256=EVIDENCE_SHA,
    )
    base = make_spec(
        operation_id="issue211-runner-registration",
        step_id="register-runner",
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        allowed_effect_families=("RUNNER_REGISTRATION",),
        prior_evidence_requirement=requirement,
    )
    return replace(base, **changes)


def authenticate_evidence_for(spec, *, repository=None, evidence_bytes=EVIDENCE_BYTES, key=EVIDENCE_KEY):
    requirement = spec.prior_evidence_requirement
    assert requirement is not None
    bound_repository = spec.repository if repository is None else repository
    digest = hashlib.sha256(evidence_bytes).hexdigest()
    message = prior_evidence_auth_message(
        repository=bound_repository,
        pull_request_number=spec.pull_request_number,
        target_sha=spec.target_sha,
        producer_operation_id=requirement.producer_operation_id,
        producer_step_id=requirement.producer_step_id,
        evidence_sha256=digest,
    )
    tag = hmac.new(key, message, hashlib.sha256).hexdigest()
    return authenticate_prior_evidence(
        repository=bound_repository,
        pull_request_number=spec.pull_request_number,
        target_sha=spec.target_sha,
        producer_operation_id=requirement.producer_operation_id,
        producer_step_id=requirement.producer_step_id,
        evidence_bytes=evidence_bytes,
        auth_tag=tag,
    )


class EqualitySpoofString(str):
    def __eq__(self, _other):
        return True

    def __ne__(self, _other):
        return False


class OperatorStepGateTests(unittest.TestCase):
    def test_valid_read_only_candidate_passes_with_authenticated_ast_capability(self):
        spec = make_spec()
        candidate = make_candidate()
        capability = authenticate_report(make_report(spec, candidate))
        result = validate_operator_step(spec, candidate, ast_attestation=capability)
        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)
        self.assertEqual(result.reason_codes, ())

    def test_raw_caller_constructed_ast_report_is_not_authority(self):
        spec = make_spec()
        candidate = make_candidate()
        forged = make_report(spec, candidate)
        result = validate_operator_step(spec, candidate, ast_attestation=forged)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("AST_ATTESTATION_UNAUTHENTICATED",))

    def test_forged_ast_capability_is_rejected(self):
        spec = make_spec()
        candidate = make_candidate()
        forged = AuthenticatedAstAttestation(token="0" * 64)
        result = validate_operator_step(spec, candidate, ast_attestation=forged)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("AST_ATTESTATION_UNAUTHENTICATED",))

    def test_ast_report_requires_configured_producer_authentication(self):
        spec = make_spec()
        candidate = make_candidate()
        report = make_report(spec, candidate)
        bad_tag = hmac.new(b"Z" * 32, ast_attestation_auth_message(report), hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(ValueError, "AST authentication failed"):
            authenticate_ast_attestation(report, auth_tag=bad_tag)

    def test_comment_literals_cannot_substitute_for_authenticated_executable_binding(self):
        spec = make_spec()
        candidate = make_candidate(
            f"# {REPOSITORY} PR {PR_NUMBER} {TARGET_SHA} {HOST_ROLE} {IDENTITY}\n"
            "Set-Location 'C:\\unrelated-checkout'"
        )
        capability = authenticate_report(make_report(spec, candidate, repository="owner/other-repo"))
        result = validate_operator_step(spec, candidate, ast_attestation=capability)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_REPOSITORY_BINDING_MISMATCH", result.reason_codes)

    def test_dynamic_mutation_is_blocked_when_authenticated_ast_reports_effect(self):
        spec = make_spec()
        candidate = make_candidate("& ('Remove' + '-Item') -LiteralPath C:\\target")
        capability = authenticate_report(
            make_report(
                spec,
                candidate,
                observed_effect_families=("FILESYSTEM_DESTRUCTIVE_MUTATION",),
            )
        )
        result = validate_operator_step(spec, candidate, ast_attestation=capability)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_READ_ONLY_EFFECT_PRESENT", result.reason_codes)

    def test_automatic_variable_collision_is_driven_by_authenticated_ast(self):
        spec = make_spec()
        for spelling in ("$global:args = 1", "${args} = 1", "Write-Output x; $Args = 1", "param(${args})"):
            with self.subTest(spelling=spelling):
                candidate = make_candidate(spelling)
                capability = authenticate_report(
                    make_report(spec, candidate, automatic_variable_collisions=("args",))
                )
                result = validate_operator_step(spec, candidate, ast_attestation=capability)
                self.assertIs(result.status, OperatorGateStatus.BLOCKED)
                self.assertIn("AST_AUTOMATIC_VARIABLE_COLLISION", result.reason_codes)

    def test_requested_execution_controls_require_authenticated_ast_proof(self):
        cases = (
            ("require_heartbeat_or_progress", "AST_PROGRESS_PROOF_MISSING"),
            ("require_child_exit_code", "AST_CHILD_EXIT_CODE_PROOF_MISSING"),
            ("require_fail_fast", "AST_FAIL_FAST_PROOF_MISSING"),
        )
        for field, reason in cases:
            with self.subTest(field=field):
                spec = make_spec(**{field: True})
                candidate = make_candidate()
                capability = authenticate_report(make_report(spec, candidate))
                result = validate_operator_step(spec, candidate, ast_attestation=capability)
                self.assertIs(result.status, OperatorGateStatus.BLOCKED)
                self.assertIn(reason, result.reason_codes)

    def test_execution_controls_pass_when_authenticated_ast_proves_them(self):
        spec = make_spec(
            require_heartbeat_or_progress=True,
            require_child_exit_code=True,
            require_fail_fast=True,
        )
        candidate = make_candidate()
        capability = authenticate_report(
            make_report(
                spec,
                candidate,
                heartbeat_or_progress_proven=True,
                child_exit_code_proven=True,
                fail_fast_proven=True,
            )
        )
        result = validate_operator_step(spec, candidate, ast_attestation=capability)
        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)

    def test_evidence_root_string_subclass_cannot_spoof_authoritative_root(self):
        evil = EqualitySpoofString(r"C:\evil")
        spec = make_spec(evidence_root=evil)
        result = validate_operator_step(spec, make_candidate())
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("EVIDENCE_ROOT_INVALID", result.reason_codes)

    def test_mutation_effect_must_be_in_allowlist_before_evidence_consumption(self):
        spec = make_mutation_spec()
        candidate = make_candidate("Remove-Item C:\\target")
        ast_capability = authenticate_report(
            make_report(
                spec,
                candidate,
                observed_effect_families=("FILESYSTEM_DESTRUCTIVE_MUTATION",),
            )
        )
        evidence_capability = authenticate_evidence_for(spec)
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=ast_capability,
            prior_evidence_capability=evidence_capability,
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_EFFECT_NOT_ALLOWED", result.reason_codes)

    def test_authenticated_prior_evidence_is_bound_and_consumed_once(self):
        spec = make_mutation_spec()
        candidate = make_candidate("# authenticated AST reports runner registration")
        ast_capability = authenticate_report(
            make_report(spec, candidate, observed_effect_families=("RUNNER_REGISTRATION",))
        )
        evidence_capability = authenticate_evidence_for(spec)
        first = validate_operator_step(
            spec,
            candidate,
            ast_attestation=ast_capability,
            prior_evidence_capability=evidence_capability,
        )
        second = validate_operator_step(
            spec,
            candidate,
            ast_attestation=ast_capability,
            prior_evidence_capability=evidence_capability,
        )
        self.assertIs(first.status, OperatorGateStatus.PASS_TO_OPERATOR)
        self.assertIs(second.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(second.reason_codes, ("PRIOR_EVIDENCE_ALREADY_CONSUMED",))

    def test_prior_evidence_requires_producer_authentication(self):
        spec = make_mutation_spec()
        requirement = spec.prior_evidence_requirement
        assert requirement is not None
        digest = hashlib.sha256(EVIDENCE_BYTES).hexdigest()
        message = prior_evidence_auth_message(
            repository=spec.repository,
            pull_request_number=spec.pull_request_number,
            target_sha=spec.target_sha,
            producer_operation_id=requirement.producer_operation_id,
            producer_step_id=requirement.producer_step_id,
            evidence_sha256=digest,
        )
        bad_tag = hmac.new(b"Z" * 32, message, hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(ValueError, "evidence authentication failed"):
            authenticate_prior_evidence(
                repository=spec.repository,
                pull_request_number=spec.pull_request_number,
                target_sha=spec.target_sha,
                producer_operation_id=requirement.producer_operation_id,
                producer_step_id=requirement.producer_step_id,
                evidence_bytes=EVIDENCE_BYTES,
                auth_tag=bad_tag,
            )

    def test_prior_evidence_digest_is_derived_from_authenticated_bytes(self):
        spec = make_mutation_spec()
        candidate = make_candidate()
        ast_capability = authenticate_report(
            make_report(spec, candidate, observed_effect_families=("RUNNER_REGISTRATION",))
        )
        other_bytes = b"different evidence\n"
        other_capability = authenticate_evidence_for(spec, evidence_bytes=other_bytes)
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=ast_capability,
            prior_evidence_capability=other_capability,
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIOR_EVIDENCE_BINDING_MISMATCH",))

    def test_prior_evidence_cannot_cross_repository_binding(self):
        spec = make_mutation_spec()
        candidate = make_candidate()
        ast_capability = authenticate_report(
            make_report(spec, candidate, observed_effect_families=("RUNNER_REGISTRATION",))
        )
        capability = authenticate_evidence_for(spec, repository="owner/other-private-repo")
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=ast_capability,
            prior_evidence_capability=capability,
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIOR_EVIDENCE_BINDING_MISMATCH",))

    def test_forged_prior_evidence_capability_is_rejected(self):
        spec = make_mutation_spec()
        candidate = make_candidate()
        ast_capability = authenticate_report(
            make_report(spec, candidate, observed_effect_families=("RUNNER_REGISTRATION",))
        )
        forged = PriorEvidenceCapability(token="0" * 64)
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=ast_capability,
            prior_evidence_capability=forged,
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIOR_EVIDENCE_UNKNOWN",))

    def test_candidate_self_declared_gate_authority_is_blocked(self):
        spec = make_spec()
        candidate = make_candidate("Write-Output 'PASS_TO_OPERATOR'")
        capability = authenticate_report(
            make_report(spec, candidate, self_declared_gate_authority=True)
        )
        result = validate_operator_step(spec, candidate, ast_attestation=capability)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_SELF_DECLARED_GATE_AUTHORITY", result.reason_codes)

    def test_candidate_is_not_executed_by_portable_validator(self):
        spec = make_spec()
        candidate = make_candidate("throw 'this would fail if executed'")
        capability = authenticate_report(make_report(spec, candidate))
        result = validate_operator_step(spec, candidate, ast_attestation=capability)
        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)

    def test_same_authenticated_read_only_inputs_are_deterministic(self):
        spec = make_spec()
        candidate = make_candidate()
        capability = authenticate_report(make_report(spec, candidate))
        first = validate_operator_step(spec, candidate, ast_attestation=capability)
        second = validate_operator_step(spec, candidate, ast_attestation=capability)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
