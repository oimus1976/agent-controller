import hashlib
import hmac
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import agent_controller.operator_step_gate as gate
from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    WINDOWS_POWERSHELL_PARSER,
    OperatorEffectClass,
    OperatorStepSpec,
    PowerShellAstAttestation,
    PriorEvidenceRequirement,
    ast_attestation_auth_message,
    authenticate_ast_attestation,
    authenticate_prior_evidence,
    operator_step_spec_sha256,
    prior_evidence_auth_message,
)
from agent_controller.owner_machine_jit_bridge import (
    OWNER_MACHINE_HOST_ROLE,
    TARGET_EXECUTION_IDENTITY,
    TRUSTED_BROKER_IDENTITY,
    OwnerMachineBridgePhase,
    OwnerMachineBridgeRequest,
    OwnerMachineBridgeStatus,
    build_owner_machine_jit_bridge_plan,
)
from agent_controller.private_ci_contract import PrivateCiRequest, PrivateCiTargetOs
from agent_controller.private_ci_durable_authority import (
    DurablePrivateCiAuthority,
    DurablePrivateCiBinding,
)


REPOSITORY = "owner/private-repo"
PR_NUMBER = 42
TARGET_SHA = "a" * 40
WORKFLOW = "private-ci.yml@v1"
NONCE = "issue213-nonce"
RUNNER_LABEL = f"ac-private-ci-{NONCE}"
ENVIRONMENT_GENERATION = "win-image-2026-09-16"
AST_KEY = b"J" * 32
EVIDENCE_KEY = b"K" * 32
REGISTRATION_EVIDENCE = b"trusted registration preflight\n"
CLEANUP_EVIDENCE = b"trusted cleanup preflight\n"


def source_request(**changes):
    request = PrivateCiRequest(
        repository=REPOSITORY,
        repository_visibility="private",
        pull_request_number=PR_NUMBER,
        pull_request_state="open",
        pull_request_head_repository=REPOSITORY,
        expected_head_sha=TARGET_SHA,
        observed_head_sha=TARGET_SHA,
        workflow_identity=WORKFLOW,
        target_os=PrivateCiTargetOs.WINDOWS,
        runner_scope_repository=REPOSITORY,
        runner_nonce=NONCE,
        runner_label=RUNNER_LABEL,
        environment_generation=ENVIRONMENT_GENERATION,
        residual_runner_count=0,
        environment_reset_proven=True,
    )
    return replace(request, **changes)


def durable_binding(**changes):
    binding = DurablePrivateCiBinding(
        repository=REPOSITORY,
        pull_request_number=PR_NUMBER,
        expected_head_sha=TARGET_SHA,
        workflow_identity=WORKFLOW,
        target_os=PrivateCiTargetOs.WINDOWS,
        runner_scope_repository=REPOSITORY,
        runner_nonce=NONCE,
        runner_label=RUNNER_LABEL,
        environment_generation=ENVIRONMENT_GENERATION,
    )
    return replace(binding, **changes)


def candidate(name):
    return f"Write-Output '{name}'\n"


def mutation_spec(operation_id, step_id, evidence_bytes, allowed_effects):
    evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
    return OperatorStepSpec(
        operation_id=operation_id,
        step_id=step_id,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=REPOSITORY,
        pull_request_number=PR_NUMBER,
        target_sha=TARGET_SHA,
        target_host_role=OWNER_MACHINE_HOST_ROLE,
        required_identity=TRUSTED_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=f"issue213-{step_id}.log",
        expected_success_marker=f"ISSUE213_{step_id.upper().replace('-', '_')}_PASS",
        allowed_effect_families=allowed_effects,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id=f"{operation_id}-preflight",
            producer_step_id=f"{step_id}-preflight",
            evidence_sha256=evidence_sha,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=False,
        require_fail_fast=False,
    )


def authenticate_ast(spec, candidate_text, effects):
    report = PowerShellAstAttestation(
        runtime=WINDOWS_POWERSHELL_51,
        parser=WINDOWS_POWERSHELL_PARSER,
        candidate_sha256=hashlib.sha256(candidate_text.encode("utf-8")).hexdigest(),
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
        observed_effect_families=effects,
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


def authenticate_evidence(spec, evidence_bytes):
    requirement = spec.prior_evidence_requirement
    assert requirement is not None
    digest = hashlib.sha256(evidence_bytes).hexdigest()
    message = prior_evidence_auth_message(
        repository=spec.repository,
        pull_request_number=spec.pull_request_number,
        target_sha=spec.target_sha,
        producer_operation_id=requirement.producer_operation_id,
        producer_step_id=requirement.producer_step_id,
        evidence_sha256=digest,
    )
    tag = hmac.new(EVIDENCE_KEY, message, hashlib.sha256).hexdigest()
    return authenticate_prior_evidence(
        repository=spec.repository,
        pull_request_number=spec.pull_request_number,
        target_sha=spec.target_sha,
        producer_operation_id=requirement.producer_operation_id,
        producer_step_id=requirement.producer_step_id,
        evidence_bytes=evidence_bytes,
        auth_tag=tag,
    )


class OwnerMachineJitBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        gate._ACTIVE_CONTROLLER_AUTHORITY = None
        gate.configure_controller_authority(ast_hmac_key=AST_KEY, evidence_hmac_key=EVIDENCE_KEY)

    @classmethod
    def tearDownClass(cls):
        gate._ACTIVE_CONTROLLER_AUTHORITY = None

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tempdir.name) / "authority.sqlite3"
        self.authority = DurablePrivateCiAuthority(self.database_path)
        self.registration_spec = mutation_spec(
            "issue213-registration",
            "register-runner",
            REGISTRATION_EVIDENCE,
            ("RUNNER_REGISTRATION",),
        )
        self.cleanup_spec = mutation_spec(
            "issue213-cleanup",
            "cleanup-reset",
            CLEANUP_EVIDENCE,
            ("RUNNER_REGISTRATION", "FILESYSTEM_DESTRUCTIVE_MUTATION"),
        )
        self.registration_candidate = candidate("registration plan")
        self.cleanup_candidate = candidate("cleanup plan")

    def tearDown(self):
        self.tempdir.cleanup()

    def reserve(self, **changes):
        reservation = self.authority.reserve(durable_binding(**changes))
        self.assertIsNotNone(reservation)
        return reservation

    def make_bridge_request(self, **changes):
        request = OwnerMachineBridgeRequest(
            reservation=self.reserve(),
            source_request=source_request(),
            owner_machine_host_role=OWNER_MACHINE_HOST_ROLE,
            trusted_broker_identity=TRUSTED_BROKER_IDENTITY,
            target_execution_identity=TARGET_EXECUTION_IDENTITY,
            target_authority_exposure=(),
            registration_spec=self.registration_spec,
            registration_candidate=self.registration_candidate,
            registration_ast_attestation=authenticate_ast(
                self.registration_spec,
                self.registration_candidate,
                ("RUNNER_REGISTRATION",),
            ),
            registration_prior_evidence=authenticate_evidence(
                self.registration_spec,
                REGISTRATION_EVIDENCE,
            ),
            cleanup_spec=self.cleanup_spec,
            cleanup_candidate=self.cleanup_candidate,
            cleanup_ast_attestation=authenticate_ast(
                self.cleanup_spec,
                self.cleanup_candidate,
                ("RUNNER_REGISTRATION", "FILESYSTEM_DESTRUCTIVE_MUTATION"),
            ),
            cleanup_prior_evidence=authenticate_evidence(
                self.cleanup_spec,
                CLEANUP_EVIDENCE,
            ),
        )
        return replace(request, **changes)

    def build(self, request):
        return build_owner_machine_jit_bridge_plan(
            request,
            durable_authority=self.authority,
            allowed_repositories=frozenset({REPOSITORY}),
            allowed_workflow_identities=frozenset({WORKFLOW}),
        )

    def test_complete_non_live_chain_reaches_ready_for_live_pilot(self):
        result = self.build(self.make_bridge_request())
        self.assertIs(result.status, OwnerMachineBridgeStatus.READY_FOR_LIVE_PILOT)
        self.assertEqual(result.reason_codes, ())
        self.assertTrue(all(not phase.live_effects_allowed for phase in result.phases))
        runner_phase = next(
            phase for phase in result.phases if phase.phase is OwnerMachineBridgePhase.ONE_JOB_RUNNER
        )
        self.assertEqual(runner_phase.required_identity, TARGET_EXECUTION_IDENTITY)
        self.assertTrue(runner_phase.requires_heartbeat_or_progress)
        self.assertTrue(runner_phase.requires_child_exit_code)
        self.assertTrue(runner_phase.requires_fail_fast)

    def test_public_repository_is_rejected_by_reused_private_ci_contract(self):
        request = self.make_bridge_request(
            source_request=source_request(repository_visibility="public")
        )
        result = self.build(request)
        self.assertIs(result.status, OwnerMachineBridgeStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("PRIVATE_CI_CONTRACT_REJECTED",))

    def test_fork_head_is_rejected_by_reused_private_ci_contract(self):
        request = self.make_bridge_request(
            source_request=source_request(pull_request_head_repository="fork/private-repo")
        )
        result = self.build(request)
        self.assertEqual(result.reason_codes, ("PRIVATE_CI_CONTRACT_REJECTED",))

    def test_head_drift_is_rejected_by_reused_private_ci_contract(self):
        request = self.make_bridge_request(
            source_request=source_request(observed_head_sha="b" * 40)
        )
        result = self.build(request)
        self.assertEqual(result.reason_codes, ("PRIVATE_CI_CONTRACT_REJECTED",))

    def test_residual_runner_and_uncertain_reset_are_rejected_by_contract(self):
        for changes in (
            {"residual_runner_count": 1},
            {"environment_reset_proven": False},
        ):
            with self.subTest(changes=changes):
                request = self.make_bridge_request(source_request=source_request(**changes))
                result = self.build(request)
                self.assertEqual(result.reason_codes, ("PRIVATE_CI_CONTRACT_REJECTED",))

    def test_durable_binding_mismatch_is_rejected(self):
        request = self.make_bridge_request()
        other_authority = DurablePrivateCiAuthority(Path(self.tempdir.name) / "other.sqlite3")
        other_reservation = other_authority.reserve(durable_binding(expected_head_sha="b" * 40))
        self.assertIsNotNone(other_reservation)
        request = replace(request, reservation=other_reservation)
        result = build_owner_machine_jit_bridge_plan(
            request,
            durable_authority=other_authority,
            allowed_repositories=frozenset({REPOSITORY}),
            allowed_workflow_identities=frozenset({WORKFLOW}),
        )
        self.assertEqual(result.reason_codes, ("SOURCE_REQUEST_DURABLE_BINDING_MISMATCH",))

    def test_target_identity_cannot_receive_trusted_authority(self):
        request = self.make_bridge_request(
            target_authority_exposure=("GITHUB_AUTH", "AST_HMAC_KEY")
        )
        result = self.build(request)
        self.assertIn("TARGET_AUTHORITY_EXPOSURE_FORBIDDEN", result.reason_codes)

    def test_trusted_and_target_identities_cannot_collapse(self):
        request = self.make_bridge_request(target_execution_identity=TRUSTED_BROKER_IDENTITY)
        result = self.build(request)
        self.assertIn("TARGET_EXECUTION_IDENTITY_MISMATCH", result.reason_codes)
        self.assertIn("TRUSTED_AND_TARGET_IDENTITIES_MUST_DIFFER", result.reason_codes)

    def test_registration_spec_must_match_durable_binding(self):
        bad_spec = replace(self.registration_spec, repository="owner/other-private-repo")
        request = self.make_bridge_request(registration_spec=bad_spec)
        result = self.build(request)
        self.assertIn("REGISTRATION_SPEC_BINDING_MISMATCH", result.reason_codes)

    def test_operator_gate_blocks_unallowlisted_registration_effect(self):
        candidate_text = candidate("bad registration effect")
        ast_capability = authenticate_ast(
            self.registration_spec,
            candidate_text,
            ("FILESYSTEM_DESTRUCTIVE_MUTATION",),
        )
        request = self.make_bridge_request(
            registration_candidate=candidate_text,
            registration_ast_attestation=ast_capability,
        )
        result = self.build(request)
        self.assertIs(result.status, OwnerMachineBridgeStatus.BLOCKED)
        self.assertIn("REGISTRATION_GATE_AST_EFFECT_NOT_ALLOWED", result.reason_codes)

    def test_every_phase_is_plan_only(self):
        result = self.build(self.make_bridge_request())
        self.assertTrue(result.ready_for_live_pilot)
        self.assertTrue(all(phase.live_effects_allowed is False for phase in result.phases))


if __name__ == "__main__":
    unittest.main()
