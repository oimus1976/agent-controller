import hashlib
import unittest
from dataclasses import replace

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    WINDOWS_POWERSHELL_PARSER,
    OperatorEffectClass,
    OperatorGateStatus,
    OperatorStepSpec,
    PowerShellParserAttestation,
    validate_operator_step,
)


REPOSITORY = "owner/private-repo"
PR_NUMBER = 42
TARGET_SHA = "a" * 40
HOST_ROLE = "owner-machine-broker"
IDENTITY = "c-admin"
TRANSCRIPT = "issue211-readonly.log"
SUCCESS_MARKER = "ISSUE211_READ_ONLY_PASS"


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
        required_prior_evidence_marker=None,
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=False,
        require_fail_fast=True,
    )
    return replace(spec, **changes)


def make_candidate(extra=""):
    return f'''# repository: {REPOSITORY}
# PR: {PR_NUMBER}
# exact SHA: {TARGET_SHA}
# host role: {HOST_ROLE}
# required identity: {IDENTITY}
$EvidenceRoot = '{AUTHORITATIVE_EVIDENCE_ROOT}'
$Transcript = Join-Path $EvidenceRoot '{TRANSCRIPT}'
$SuccessMarker = '{SUCCESS_MARKER}'
Write-Output $SuccessMarker
{extra}
'''


def make_attestation(candidate, **changes):
    attestation = PowerShellParserAttestation(
        runtime=WINDOWS_POWERSHELL_51,
        parser=WINDOWS_POWERSHELL_PARSER,
        candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        parsed=True,
        error_count=0,
    )
    return replace(attestation, **changes)


class OperatorStepGateTests(unittest.TestCase):
    def test_valid_read_only_candidate_passes_with_matching_parser_attestation(self):
        spec = make_spec()
        candidate = make_candidate()

        result = validate_operator_step(
            spec,
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)
        self.assertEqual(result.reason_codes, ())

    def test_missing_parser_attestation_is_uncertain_never_pass(self):
        result = validate_operator_step(make_spec(), make_candidate())

        self.assertIs(result.status, OperatorGateStatus.UNCERTAIN)
        self.assertEqual(result.reason_codes, ("PARSER_ATTESTATION_MISSING",))

    def test_parser_attestation_is_bound_to_exact_candidate_hash(self):
        candidate = make_candidate()
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate, candidate_sha256="0" * 64),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("PARSER_CANDIDATE_HASH_MISMATCH", result.reason_codes)

    def test_wrong_authoritative_evidence_root_is_blocked(self):
        spec = make_spec(evidence_root=r"C:\Temp\agent-controller-handoff")
        candidate = make_candidate()

        result = validate_operator_step(
            spec,
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("EVIDENCE_ROOT_INVALID", result.reason_codes)

    def test_temp_convenience_path_is_blocked(self):
        candidate = make_candidate("$Scratch = $env:TEMP")
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("FORBIDDEN_CONVENIENCE_PATH", result.reason_codes)

    def test_unresolved_placeholder_is_blocked(self):
        candidate = make_candidate("$RunnerNonce = '<RUNNER_NONCE>'")
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("UNRESOLVED_PLACEHOLDER", result.reason_codes)

    def test_exact_sha_drift_is_blocked(self):
        spec = make_spec(target_sha="b" * 40)
        candidate = make_candidate()
        result = validate_operator_step(
            spec,
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("SHA_BINDING_MISSING", result.reason_codes)

    def test_read_only_account_mutation_is_blocked(self):
        candidate = make_candidate("New-LocalUser -Name 'act-target'")
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("ACCOUNT_MUTATION", result.reason_codes)

    def test_read_only_acl_mutation_is_blocked(self):
        candidate = make_candidate("icacls.exe C:\\Runner /grant 'act-target:(RX)'")
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("ACL_MUTATION", result.reason_codes)

    def test_read_only_workflow_dispatch_is_blocked(self):
        candidate = make_candidate("gh workflow run private-ci.yml")
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("WORKFLOW_MUTATION", result.reason_codes)

    def test_mutation_spec_requires_prior_evidence_in_contract(self):
        spec = make_spec(effect_class=OperatorEffectClass.BOUNDED_MUTATION)
        candidate = make_candidate()
        result = validate_operator_step(
            spec,
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("MUTATION_PRIOR_EVIDENCE_REQUIRED", result.reason_codes)

    def test_mutation_step_blocks_missing_prior_evidence(self):
        spec = make_spec(
            effect_class=OperatorEffectClass.BOUNDED_MUTATION,
            required_prior_evidence_marker="ISSUE211_PREFLIGHT_PASS",
        )
        candidate = make_candidate()
        result = validate_operator_step(
            spec,
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIOR_EVIDENCE_MISSING",))

    def test_mutation_step_blocks_mismatched_prior_evidence(self):
        spec = make_spec(
            effect_class=OperatorEffectClass.BOUNDED_MUTATION,
            required_prior_evidence_marker="ISSUE211_PREFLIGHT_PASS",
        )
        candidate = make_candidate()
        result = validate_operator_step(
            spec,
            candidate,
            parser_attestation=make_attestation(candidate),
            prior_evidence_marker="OTHER_PASS",
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIOR_EVIDENCE_MISMATCH",))

    def test_args_assignment_is_blocked_case_insensitively(self):
        for spelling in ("$args = @('x')", "$Args = @('x')"):
            with self.subTest(spelling=spelling):
                candidate = make_candidate(spelling)
                result = validate_operator_step(
                    make_spec(),
                    candidate,
                    parser_attestation=make_attestation(candidate),
                )
                self.assertIs(result.status, OperatorGateStatus.BLOCKED)
                self.assertIn("POWERSHELL_AUTOMATIC_VARIABLE_ASSIGNMENT", result.reason_codes)

    def test_args_parameter_is_blocked_case_insensitively(self):
        for spelling in ("param([string]$args)", "param([string]$Args)"):
            with self.subTest(spelling=spelling):
                candidate = make_candidate(spelling)
                result = validate_operator_step(
                    make_spec(),
                    candidate,
                    parser_attestation=make_attestation(candidate),
                )
                self.assertIs(result.status, OperatorGateStatus.BLOCKED)
                self.assertIn("POWERSHELL_AUTOMATIC_VARIABLE_PARAMETER", result.reason_codes)

    def test_candidate_cannot_self_declare_gate_pass(self):
        candidate = make_candidate("Write-Output 'PASS_TO_OPERATOR'")
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.BLOCKED)
        self.assertIn("SELF_DECLARED_GATE_AUTHORITY", result.reason_codes)

    def test_candidate_is_not_executed_by_validator(self):
        candidate = make_candidate("throw 'this would fail if executed'")
        result = validate_operator_step(
            make_spec(),
            candidate,
            parser_attestation=make_attestation(candidate),
        )

        self.assertIs(result.status, OperatorGateStatus.PASS_TO_OPERATOR)

    def test_same_inputs_produce_identical_result(self):
        spec = make_spec()
        candidate = make_candidate("$Scratch = $env:TEMP")
        attestation = make_attestation(candidate)

        first = validate_operator_step(spec, candidate, parser_attestation=attestation)
        second = validate_operator_step(spec, candidate, parser_attestation=attestation)

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
