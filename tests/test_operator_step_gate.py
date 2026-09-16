import hashlib
import unittest
from dataclasses import replace

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    WINDOWS_POWERSHELL_PARSER,
    OperatorEffectClass,
    OperatorEvidenceAuthority,
    OperatorGateStatus,
    OperatorStepSpec,
    PowerShellAstAttestation,
    PriorEvidenceCapability,
    PriorEvidenceRequirement,
    operator_step_spec_sha256,
    validate_operator_step,
)


REPOSITORY = "owner/private-repo"
PR_NUMBER = 42
TARGET_SHA = "a" * 40
HOST_ROLE = "owner-machine-broker"
IDENTITY = "c-admin"
TRANSCRIPT = "issue211-readonly.log"
SUCCESS_MARKER = "ISSUE211_READ_ONLY_PASS"
EVIDENCE_SHA = "e" * 64


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


def make_attestation(spec, candidate, **changes):
    attestation = PowerShellAstAttestation(
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
    return replace(attestation, **changes)


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


def issue_prior(authority, spec):
    requirement = spec.prior_evidence_requirement
    assert requirement is not None
    return authority.issue(
        repository=spec.repository,
        pull_request_number=spec.pull_request_number,
        target_sha=spec.target_sha,
        producer_operation_id=requirement.producer_operation_id,
        producer_step_id=requirement.producer_step_id,
        evidence_sha256=requirement.evidence_sha256,
    )


class EqualitySpoof:
    def __eq__(self, _other):
        return True

    def __ne__(self, _other):
        return False


class StringSubclass(str):
    pass


class OperatorStepGateTests(unittest.TestCase):
    def test_valid_read_only_candidate_passes_with_matching_ast_attestation(self):
        spec = make_spec()
        candidate = make_candidate()
        result = validate_operator_step(spec, candidate, ast_attestation=make_attestation(spec, candidate))
        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)
        self.assertEqual(result.reason_codes, ())

    def test_missing_ast_attestation_is_uncertain_never_pass(self):
        result = validate_operator_step(make_spec(), make_candidate())
        self.assertIs(result.status, OperatorGateStatus.UNCERTAIN)
        self.assertEqual(result.reason_codes, ("AST_ATTESTATION_MISSING",))

    def test_attestation_is_bound_to_exact_candidate_hash(self):
        spec = make_spec()
        candidate = make_candidate()
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(spec, candidate, candidate_sha256="0" * 64),
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_CANDIDATE_HASH_MISMATCH", result.reason_codes)

    def test_attestation_is_bound_to_entire_frozen_spec(self):
        spec = make_spec()
        candidate = make_candidate()
        changed_spec = replace(spec, step_id="other-step")
        result = validate_operator_step(
            changed_spec,
            candidate,
            ast_attestation=make_attestation(spec, candidate),
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_SPEC_HASH_MISMATCH", result.reason_codes)

    def test_comment_literals_cannot_substitute_for_executable_binding_attestation(self):
        spec = make_spec()
        candidate = make_candidate(
            f"# {REPOSITORY} PR {PR_NUMBER} {TARGET_SHA} {HOST_ROLE} {IDENTITY}\n"
            "Set-Location 'C:\\unrelated-checkout'"
        )
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(spec, candidate, repository="owner/other-repo"),
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_REPOSITORY_BINDING_MISMATCH", result.reason_codes)

    def test_wrong_authoritative_evidence_root_is_blocked_at_spec_boundary(self):
        spec = make_spec(evidence_root=r"C:\Temp\agent-controller-handoff")
        candidate = make_candidate()
        result = validate_operator_step(spec, candidate, ast_attestation=None)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("EVIDENCE_ROOT_INVALID", result.reason_codes)

    def test_ast_reported_convenience_path_is_blocked(self):
        spec = make_spec()
        candidate = make_candidate("$Scratch = $env:TEMP")
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(
                spec,
                candidate,
                forbidden_convenience_paths=("$env:TEMP",),
            ),
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_FORBIDDEN_CONVENIENCE_PATH", result.reason_codes)

    def test_ast_reported_placeholder_is_blocked(self):
        spec = make_spec()
        candidate = make_candidate("$RunnerNonce = '<RUNNER_NONCE>'")
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(
                spec,
                candidate,
                unresolved_placeholders=("<RUNNER_NONCE>",),
            ),
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_UNRESOLVED_PLACEHOLDER", result.reason_codes)

    def test_dynamic_invocation_cannot_escape_read_only_effect_attestation(self):
        spec = make_spec()
        candidate = make_candidate("& ('Remove' + '-Item') -LiteralPath C:\\target")
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(
                spec,
                candidate,
                observed_effect_families=("FILESYSTEM_DESTRUCTIVE_MUTATION",),
            ),
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_READ_ONLY_EFFECT_PRESENT", result.reason_codes)

    def test_mutation_effect_must_be_in_spec_allowlist(self):
        spec = make_mutation_spec()
        candidate = make_candidate("Remove-Item C:\\target")
        authority = OperatorEvidenceAuthority()
        capability = issue_prior(authority, spec)
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(
                spec,
                candidate,
                observed_effect_families=("FILESYSTEM_DESTRUCTIVE_MUTATION",),
            ),
            prior_evidence_authority=authority,
            prior_evidence_capability=capability,
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_EFFECT_NOT_ALLOWED", result.reason_codes)

    def test_allowed_mutation_requires_and_consumes_authority_owned_prior_evidence(self):
        spec = make_mutation_spec()
        candidate = make_candidate("# trusted AST reports repository-scoped runner registration")
        authority = OperatorEvidenceAuthority()
        capability = issue_prior(authority, spec)
        attestation = make_attestation(
            spec,
            candidate,
            observed_effect_families=("RUNNER_REGISTRATION",),
        )
        first = validate_operator_step(
            spec,
            candidate,
            ast_attestation=attestation,
            prior_evidence_authority=authority,
            prior_evidence_capability=capability,
        )
        second = validate_operator_step(
            spec,
            candidate,
            ast_attestation=attestation,
            prior_evidence_authority=authority,
            prior_evidence_capability=capability,
        )
        self.assertIs(first.status, OperatorGateStatus.PASS_TO_OPERATOR)
        self.assertIs(second.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(second.reason_codes, ("PRIOR_EVIDENCE_ALREADY_CONSUMED",))

    def test_prior_evidence_cannot_cross_repository_binding(self):
        spec = make_mutation_spec()
        candidate = make_candidate()
        authority = OperatorEvidenceAuthority()
        requirement = spec.prior_evidence_requirement
        assert requirement is not None
        capability = authority.issue(
            repository="owner/other-private-repo",
            pull_request_number=spec.pull_request_number,
            target_sha=spec.target_sha,
            producer_operation_id=requirement.producer_operation_id,
            producer_step_id=requirement.producer_step_id,
            evidence_sha256=requirement.evidence_sha256,
        )
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(
                spec,
                candidate,
                observed_effect_families=("RUNNER_REGISTRATION",),
            ),
            prior_evidence_authority=authority,
            prior_evidence_capability=capability,
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIOR_EVIDENCE_BINDING_MISMATCH",))

    def test_forged_prior_evidence_capability_is_rejected(self):
        spec = make_mutation_spec()
        candidate = make_candidate()
        authority = OperatorEvidenceAuthority()
        forged = PriorEvidenceCapability(token="0" * 64)
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(
                spec,
                candidate,
                observed_effect_families=("RUNNER_REGISTRATION",),
            ),
            prior_evidence_authority=authority,
            prior_evidence_capability=forged,
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIOR_EVIDENCE_UNKNOWN",))

    def test_execution_control_requirements_fail_closed_without_ast_proof(self):
        cases = (
            ("require_heartbeat_or_progress", "AST_PROGRESS_PROOF_MISSING"),
            ("require_child_exit_code", "AST_CHILD_EXIT_CODE_PROOF_MISSING"),
            ("require_fail_fast", "AST_FAIL_FAST_PROOF_MISSING"),
        )
        for field, reason in cases:
            with self.subTest(field=field):
                spec = make_spec(**{field: True})
                candidate = make_candidate()
                result = validate_operator_step(
                    spec,
                    candidate,
                    ast_attestation=make_attestation(spec, candidate),
                )
                self.assertIs(result.status, OperatorGateStatus.BLOCKED)
                self.assertIn(reason, result.reason_codes)

    def test_execution_control_requirements_pass_only_with_ast_proof(self):
        spec = make_spec(
            require_heartbeat_or_progress=True,
            require_child_exit_code=True,
            require_fail_fast=True,
        )
        candidate = make_candidate()
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(
                spec,
                candidate,
                heartbeat_or_progress_proven=True,
                child_exit_code_proven=True,
                fail_fast_proven=True,
            ),
        )
        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)

    def test_attestation_equality_spoof_objects_are_rejected_before_comparison(self):
        spec = make_spec()
        candidate = make_candidate()
        spoof = make_attestation(spec, candidate)
        object.__setattr__(spoof, "candidate_sha256", EqualitySpoof())
        result = validate_operator_step(spec, candidate, ast_attestation=spoof)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("AST_ATTESTATION_FIELD_TYPE_INVALID",))

    def test_attestation_string_subclasses_are_rejected(self):
        spec = make_spec()
        candidate = make_candidate()
        attestation = make_attestation(spec, candidate, runtime=StringSubclass(WINDOWS_POWERSHELL_51))
        result = validate_operator_step(spec, candidate, ast_attestation=attestation)
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("AST_ATTESTATION_FIELD_TYPE_INVALID",))

    def test_scoped_braced_and_parameter_automatic_variable_collisions_are_authoritative_ast_findings(self):
        spellings = (
            "$global:args = @('changed')",
            "${args} = @('changed')",
            "Write-Output x; $Args = @('changed')",
            "param([string]${args})",
        )
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                spec = make_spec()
                candidate = make_candidate(spelling)
                result = validate_operator_step(
                    spec,
                    candidate,
                    ast_attestation=make_attestation(
                        spec,
                        candidate,
                        automatic_variable_collisions=("args",),
                    ),
                )
                self.assertIs(result.status, OperatorGateStatus.BLOCKED)
                self.assertIn("AST_AUTOMATIC_VARIABLE_COLLISION", result.reason_codes)

    def test_candidate_self_declared_gate_authority_is_blocked_by_ast_attestation(self):
        spec = make_spec()
        candidate = make_candidate("Write-Output 'PASS_TO_OPERATOR'")
        result = validate_operator_step(
            spec,
            candidate,
            ast_attestation=make_attestation(spec, candidate, self_declared_gate_authority=True),
        )
        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("AST_SELF_DECLARED_GATE_AUTHORITY", result.reason_codes)

    def test_candidate_is_not_executed_by_portable_validator(self):
        spec = make_spec()
        candidate = make_candidate("throw 'this would fail if executed'")
        result = validate_operator_step(spec, candidate, ast_attestation=make_attestation(spec, candidate))
        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)

    def test_same_frozen_read_only_inputs_produce_identical_result(self):
        spec = make_spec()
        candidate = make_candidate()
        attestation = make_attestation(spec, candidate)
        first = validate_operator_step(spec, candidate, ast_attestation=attestation)
        second = validate_operator_step(spec, candidate, ast_attestation=attestation)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
