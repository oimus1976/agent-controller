import hashlib
import hmac
import inspect
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path

import agent_controller.operator_step_gate as gate
import agent_controller.owner_machine_jit_bridge as bridge
from agent_controller.operator_step_gate import (
    WINDOWS_POWERSHELL_51,
    WINDOWS_POWERSHELL_PARSER,
    PowerShellAstAttestation,
    ast_attestation_auth_message,
    authenticate_ast_attestation,
    operator_step_spec_sha256,
)
from agent_controller.owner_machine_jit_bridge import (
    CLEANUP_EFFECTS,
    CLEANUP_OPERATION_ID,
    CLEANUP_STEP_ID,
    REGISTRATION_EFFECTS,
    REGISTRATION_OPERATION_ID,
    REGISTRATION_STEP_ID,
    TARGET_EXECUTION_IDENTITY,
    TRUSTED_BROKER_IDENTITY,
    AuthenticatedOwnerMachineObservation,
    OwnerMachineBridgePhase,
    OwnerMachineBridgeRequest,
    OwnerMachineBridgeStatus,
    authenticate_owner_machine_observation,
    build_cleanup_plan_spec,
    build_owner_machine_jit_bridge_plan,
    build_registration_plan_spec,
    configure_owner_machine_observation_authority,
    issue_owner_machine_observation_challenge,
    owner_machine_observation_auth_message,
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
OBSERVATION_KEY = b"O" * 32


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


def authenticate_observation(observation):
    challenge = issue_owner_machine_observation_challenge()
    tag = hmac.new(
        OBSERVATION_KEY,
        owner_machine_observation_auth_message(observation, challenge=challenge),
        hashlib.sha256,
    ).hexdigest()
    return authenticate_owner_machine_observation(
        observation,
        challenge=challenge,
        auth_tag=tag,
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


class OwnerMachineJitBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        gate._ACTIVE_CONTROLLER_AUTHORITY = None
        gate.configure_controller_authority(ast_hmac_key=AST_KEY, evidence_hmac_key=EVIDENCE_KEY)

    @classmethod
    def tearDownClass(cls):
        gate._ACTIVE_CONTROLLER_AUTHORITY = None
        bridge._ACTIVE_OBSERVATION_AUTHORITY = None

    def setUp(self):
        bridge._ACTIVE_OBSERVATION_AUTHORITY = None
        configure_owner_machine_observation_authority(
            hmac_key=OBSERVATION_KEY,
            allowed_repositories=frozenset({REPOSITORY}),
            allowed_workflow_identities=frozenset({WORKFLOW}),
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self._authority_generation = 0
        self.authority = self._new_authority()
        self.registration_spec = build_registration_plan_spec(
            repository=REPOSITORY,
            pull_request_number=PR_NUMBER,
            target_sha=TARGET_SHA,
        )
        self.cleanup_spec = build_cleanup_plan_spec(
            repository=REPOSITORY,
            pull_request_number=PR_NUMBER,
            target_sha=TARGET_SHA,
        )
        self.registration_candidate = candidate("registration plan")
        self.cleanup_candidate = candidate("cleanup plan")

    def tearDown(self):
        self.tempdir.cleanup()
        bridge._ACTIVE_OBSERVATION_AUTHORITY = None

    def _new_authority(self):
        self._authority_generation += 1
        database_path = Path(self.tempdir.name) / f"authority-{self._authority_generation}.sqlite3"
        return DurablePrivateCiAuthority(database_path)

    def reserve(self, **changes):
        reservation = self.authority.reserve(durable_binding(**changes))
        self.assertIsNotNone(reservation)
        return reservation

    def make_bridge_request(self, *, observation=None, reservation=None, **changes):
        observed = source_request() if observation is None else observation
        if reservation is None:
            self.authority = self._new_authority()
            reservation = self.reserve()
        request = OwnerMachineBridgeRequest(
            reservation=reservation,
            observation=authenticate_observation(observed),
            registration_candidate=self.registration_candidate,
            registration_ast_attestation=authenticate_ast(
                self.registration_spec,
                self.registration_candidate,
                REGISTRATION_EFFECTS,
            ),
            cleanup_candidate=self.cleanup_candidate,
            cleanup_ast_attestation=authenticate_ast(
                self.cleanup_spec,
                self.cleanup_candidate,
                CLEANUP_EFFECTS,
            ),
        )
        return replace(request, **changes)

    def build(self, request):
        return build_owner_machine_jit_bridge_plan(request, durable_authority=self.authority)

    def test_complete_non_live_chain_reaches_ready_for_live_pilot(self):
        result = self.build(self.make_bridge_request())
        self.assertIs(result.status, OwnerMachineBridgeStatus.READY_FOR_LIVE_PILOT)
        self.assertEqual(result.reason_codes, ())
        self.assertTrue(all(not phase.live_effects_allowed for phase in result.phases))
        runner_phase = next(
            phase for phase in result.phases if phase.phase is OwnerMachineBridgePhase.ONE_JOB_RUNNER
        )
        self.assertEqual(runner_phase.required_identity, TARGET_EXECUTION_IDENTITY)
        self.assertFalse(runner_phase.trusted_authority_allowed)
        self.assertTrue(runner_phase.requires_heartbeat_or_progress)
        self.assertTrue(runner_phase.requires_child_exit_code)
        self.assertTrue(runner_phase.requires_fail_fast)

    def test_caller_cannot_supply_allowlists_specs_or_identity_claims(self):
        request_fields = {field.name for field in fields(OwnerMachineBridgeRequest)}
        forbidden = {
            "source_request",
            "allowed_repositories",
            "allowed_workflow_identities",
            "registration_spec",
            "cleanup_spec",
            "trusted_broker_identity",
            "target_execution_identity",
            "target_authority_exposure",
        }
        self.assertTrue(forbidden.isdisjoint(request_fields))
        signature = inspect.signature(build_owner_machine_jit_bridge_plan)
        self.assertNotIn("allowed_repositories", signature.parameters)
        self.assertNotIn("allowed_workflow_identities", signature.parameters)

    def test_forged_observation_capability_cannot_reach_ready(self):
        request = self.make_bridge_request()
        forged = AuthenticatedOwnerMachineObservation(token="0" * 64)
        result = self.build(replace(request, observation=forged))
        self.assertIs(result.status, OwnerMachineBridgeStatus.BLOCKED)
        self.assertEqual(result.reason_codes, ("TRUSTED_OBSERVATION_UNKNOWN_OR_CONSUMED",))

    def test_observation_capability_is_single_use(self):
        request = self.make_bridge_request()
        first = self.build(request)
        second = self.build(request)
        self.assertTrue(first.ready_for_live_pilot)
        self.assertEqual(second.reason_codes, ("TRUSTED_OBSERVATION_UNKNOWN_OR_CONSUMED",))

    def test_observation_authentication_challenge_prevents_tag_replay(self):
        observation = source_request()
        challenge = issue_owner_machine_observation_challenge()
        tag = hmac.new(
            OBSERVATION_KEY,
            owner_machine_observation_auth_message(observation, challenge=challenge),
            hashlib.sha256,
        ).hexdigest()
        first = authenticate_owner_machine_observation(
            observation,
            challenge=challenge,
            auth_tag=tag,
        )
        self.assertIs(type(first), AuthenticatedOwnerMachineObservation)
        with self.assertRaisesRegex(ValueError, "challenge unknown or consumed"):
            authenticate_owner_machine_observation(
                observation,
                challenge=challenge,
                auth_tag=tag,
            )

    def test_fabricated_public_fork_head_or_stale_state_is_rejected_after_authentication(self):
        cases = (
            {"repository_visibility": "public"},
            {"pull_request_state": "closed"},
            {"pull_request_head_repository": "fork/private-repo"},
            {"observed_head_sha": "b" * 40},
            {"residual_runner_count": 1},
            {"environment_reset_proven": False},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                request = self.make_bridge_request(observation=source_request(**changes))
                result = self.build(request)
                self.assertEqual(result.reason_codes, ("PRIVATE_CI_CONTRACT_REJECTED",))

    def test_controller_owned_allowlist_rejects_authenticated_unallowlisted_identity(self):
        observation = source_request(workflow_identity="attacker.yml@v1")
        challenge = issue_owner_machine_observation_challenge()
        tag = hmac.new(
            OBSERVATION_KEY,
            owner_machine_observation_auth_message(observation, challenge=challenge),
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "controller-owned private-CI allowlist"):
            authenticate_owner_machine_observation(
                observation,
                challenge=challenge,
                auth_tag=tag,
            )

    def test_durable_binding_mismatch_is_rejected(self):
        other_authority = DurablePrivateCiAuthority(Path(self.tempdir.name) / "other.sqlite3")
        other_reservation = other_authority.reserve(durable_binding(expected_head_sha="b" * 40))
        self.assertIsNotNone(other_reservation)
        request = self.make_bridge_request(reservation=other_reservation)
        result = build_owner_machine_jit_bridge_plan(
            request,
            durable_authority=other_authority,
        )
        self.assertEqual(result.reason_codes, ("SOURCE_REQUEST_DURABLE_BINDING_MISMATCH",))

    def test_registration_and_cleanup_specs_are_fixed_bridge_policy(self):
        registration = self.registration_spec
        cleanup = self.cleanup_spec
        self.assertEqual(registration.operation_id, REGISTRATION_OPERATION_ID)
        self.assertEqual(registration.step_id, REGISTRATION_STEP_ID)
        self.assertEqual(registration.allowed_effect_families, REGISTRATION_EFFECTS)
        self.assertFalse(registration.require_child_exit_code)
        self.assertFalse(registration.require_fail_fast)
        self.assertEqual(cleanup.operation_id, CLEANUP_OPERATION_ID)
        self.assertEqual(cleanup.step_id, CLEANUP_STEP_ID)
        self.assertEqual(cleanup.allowed_effect_families, CLEANUP_EFFECTS)
        self.assertFalse(cleanup.require_child_exit_code)
        self.assertFalse(cleanup.require_fail_fast)

    def test_registration_attestation_with_unallowlisted_effect_is_blocked(self):
        candidate_text = candidate("bad registration effect")
        bad_attestation = authenticate_ast(
            self.registration_spec,
            candidate_text,
            ("FILESYSTEM_DESTRUCTIVE_MUTATION",),
        )
        request = self.make_bridge_request(
            registration_candidate=candidate_text,
            registration_ast_attestation=bad_attestation,
        )
        result = self.build(request)
        self.assertIs(result.status, OwnerMachineBridgeStatus.BLOCKED)
        self.assertIn("REGISTRATION_GATE_AST_EFFECT_NOT_ALLOWED", result.reason_codes)

    def test_failed_cleanup_plan_does_not_consume_any_execution_evidence(self):
        self.assertNotIn("registration_prior_evidence", {field.name for field in fields(OwnerMachineBridgeRequest)})
        self.assertNotIn("cleanup_prior_evidence", {field.name for field in fields(OwnerMachineBridgeRequest)})
        bad_candidate = candidate("bad cleanup")
        bad_attestation = authenticate_ast(
            self.cleanup_spec,
            bad_candidate,
            ("HTTP_API_ACCESS",),
        )
        request = self.make_bridge_request(
            cleanup_candidate=bad_candidate,
            cleanup_ast_attestation=bad_attestation,
        )
        result = self.build(request)
        self.assertIs(result.status, OwnerMachineBridgeStatus.BLOCKED)
        self.assertIn("CLEANUP_GATE_AST_EFFECT_NOT_ALLOWED", result.reason_codes)

    def test_every_phase_is_plan_only_and_target_never_gets_trusted_authority(self):
        result = self.build(self.make_bridge_request())
        self.assertTrue(result.ready_for_live_pilot)
        self.assertTrue(all(phase.live_effects_allowed is False for phase in result.phases))
        target_phases = [phase for phase in result.phases if phase.required_identity == TARGET_EXECUTION_IDENTITY]
        self.assertTrue(target_phases)
        self.assertTrue(all(phase.trusted_authority_allowed is False for phase in target_phases))


if __name__ == "__main__":
    unittest.main()
