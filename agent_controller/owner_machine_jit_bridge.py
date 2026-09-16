from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    AuthenticatedAstAttestation,
    OperatorEffectClass,
    OperatorGateStatus,
    OperatorStepSpec,
    PriorEvidenceRequirement,
    _attestation_reason_codes,
    _candidate_sha256,
    _spec_reason_codes,
)
from agent_controller.private_ci_contract import (
    PrivateCiNonceAuthority,
    PrivateCiRequest,
    PrivateCiTargetOs,
    PrivateCiValidationResult,
    validate_and_reserve_private_ci_request,
)
from agent_controller.private_ci_durable_authority import (
    DurablePrivateCiAuthority,
    DurablePrivateCiAuthorityError,
    DurablePrivateCiReservation,
)


OWNER_MACHINE_HOST_ROLE = "private-ci-owner-machine"
TRUSTED_BROKER_IDENTITY = "c-admin"
TARGET_EXECUTION_IDENTITY = "ac-runner"
PLANNING_EVIDENCE_SHA256 = "0" * 64
REGISTRATION_OPERATION_ID = "issue213-registration-plan"
REGISTRATION_STEP_ID = "register-runner-plan"
REGISTRATION_TRANSCRIPT = "issue213-register-runner-plan.log"
REGISTRATION_SUCCESS_MARKER = "ISSUE213_REGISTER_RUNNER_PLAN_PASS"
REGISTRATION_EFFECTS = ("RUNNER_REGISTRATION",)
CLEANUP_OPERATION_ID = "issue213-cleanup-plan"
CLEANUP_STEP_ID = "cleanup-reset-plan"
CLEANUP_TRANSCRIPT = "issue213-cleanup-reset-plan.log"
CLEANUP_SUCCESS_MARKER = "ISSUE213_CLEANUP_RESET_PLAN_PASS"
CLEANUP_EFFECTS = ("FILESYSTEM_DESTRUCTIVE_MUTATION", "RUNNER_REGISTRATION")


class OwnerMachineBridgeStatus(str, Enum):
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"
    READY_FOR_LIVE_PILOT = "READY_FOR_LIVE_PILOT"


class OwnerMachineBridgePhase(str, Enum):
    GITHUB_PREFLIGHT = "github-preflight"
    OWNER_MACHINE_PREFLIGHT = "owner-machine-preflight"
    AST_ATTESTATION = "ast-attestation"
    OPERATOR_GATE = "operator-gate"
    JIT_REGISTRATION = "jit-registration-plan"
    TARGET_ENVIRONMENT = "target-environment-plan"
    ONE_JOB_RUNNER = "one-job-runner-plan"
    CLEANUP_RESET = "cleanup-reset-plan"
    ZERO_RESIDUAL_READBACK = "zero-residual-readback-plan"


@dataclass(frozen=True, slots=True)
class OwnerMachineBridgePhasePlan:
    phase: OwnerMachineBridgePhase
    live_effects_allowed: bool
    required_identity: str
    trusted_authority_allowed: bool
    requires_heartbeat_or_progress: bool
    requires_child_exit_code: bool
    requires_fail_fast: bool


@dataclass(frozen=True, eq=False, slots=True)
class AuthenticatedOwnerMachineObservation:
    token: str


@dataclass(frozen=True, slots=True)
class OwnerMachineBridgeRequest:
    reservation: DurablePrivateCiReservation
    observation: AuthenticatedOwnerMachineObservation
    registration_candidate: str
    registration_ast_attestation: AuthenticatedAstAttestation
    cleanup_candidate: str
    cleanup_ast_attestation: AuthenticatedAstAttestation


@dataclass(frozen=True, slots=True)
class OwnerMachineBridgeResult:
    status: OwnerMachineBridgeStatus
    reason_codes: tuple[str, ...]
    phases: tuple[OwnerMachineBridgePhasePlan, ...]

    @property
    def ready_for_live_pilot(self) -> bool:
        return self.status is OwnerMachineBridgeStatus.READY_FOR_LIVE_PILOT


class _ObservationAuthority:
    def __init__(
        self,
        *,
        hmac_key: bytes,
        allowed_repositories: frozenset[str],
        allowed_workflow_identities: frozenset[str],
    ) -> None:
        self._hmac_key = hmac_key
        self._allowed_repositories = allowed_repositories
        self._allowed_workflow_identities = allowed_workflow_identities
        self._observations: dict[str, PrivateCiRequest] = {}
        self._challenges: set[str] = set()
        self._lock = threading.Lock()

    @property
    def allowed_repositories(self) -> frozenset[str]:
        return self._allowed_repositories

    @property
    def allowed_workflow_identities(self) -> frozenset[str]:
        return self._allowed_workflow_identities

    def issue_challenge(self) -> str:
        challenge = secrets.token_hex(32)
        with self._lock:
            self._challenges.add(challenge)
        return challenge

    def authenticate(
        self,
        observation: PrivateCiRequest,
        *,
        challenge: str,
        auth_tag: str,
    ) -> AuthenticatedOwnerMachineObservation:
        _validate_private_ci_request_shape(observation)
        if not _valid_digest(challenge):
            raise ValueError("invalid owner-machine observation challenge")
        if not _valid_digest(auth_tag):
            raise ValueError("invalid owner-machine observation authentication tag")
        expected = hmac.new(
            self._hmac_key,
            owner_machine_observation_auth_message(observation, challenge=challenge),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(auth_tag, expected):
            raise ValueError("owner-machine observation authentication failed")
        if observation.repository not in self._allowed_repositories:
            raise ValueError("repository is not in controller-owned private-CI allowlist")
        if observation.workflow_identity not in self._allowed_workflow_identities:
            raise ValueError("workflow identity is not in controller-owned private-CI allowlist")
        with self._lock:
            if challenge not in self._challenges:
                raise ValueError("owner-machine observation challenge unknown or consumed")
            self._challenges.remove(challenge)
            token = secrets.token_hex(32)
            self._observations[token] = observation
        return AuthenticatedOwnerMachineObservation(token=token)

    def claim(self, capability: object) -> Optional[PrivateCiRequest]:
        if type(capability) is not AuthenticatedOwnerMachineObservation:
            return None
        if not _valid_digest(capability.token):
            return None
        with self._lock:
            return self._observations.pop(capability.token, None)


_ACTIVE_OBSERVATION_AUTHORITY: Optional[_ObservationAuthority] = None
_OBSERVATION_CONFIG_LOCK = threading.Lock()


def configure_owner_machine_observation_authority(
    *,
    hmac_key: bytes,
    allowed_repositories: frozenset[str],
    allowed_workflow_identities: frozenset[str],
) -> None:
    global _ACTIVE_OBSERVATION_AUTHORITY
    if type(hmac_key) is not bytes or len(hmac_key) < 32:
        raise ValueError("observation HMAC key must be at least 32 bytes")
    if type(allowed_repositories) is not frozenset or not allowed_repositories:
        raise ValueError("allowed_repositories must be a non-empty exact frozenset")
    if type(allowed_workflow_identities) is not frozenset or not allowed_workflow_identities:
        raise ValueError("allowed_workflow_identities must be a non-empty exact frozenset")
    if not all(type(item) is str and bool(item.strip()) for item in allowed_repositories):
        raise ValueError("allowed repository entries must be plain non-empty strings")
    if not all(type(item) is str and bool(item.strip()) for item in allowed_workflow_identities):
        raise ValueError("allowed workflow entries must be plain non-empty strings")
    with _OBSERVATION_CONFIG_LOCK:
        if _ACTIVE_OBSERVATION_AUTHORITY is not None:
            raise RuntimeError("owner-machine observation authority already configured")
        _ACTIVE_OBSERVATION_AUTHORITY = _ObservationAuthority(
            hmac_key=hmac_key,
            allowed_repositories=allowed_repositories,
            allowed_workflow_identities=allowed_workflow_identities,
        )


def _active_observation_authority() -> Optional[_ObservationAuthority]:
    return _ACTIVE_OBSERVATION_AUTHORITY


def issue_owner_machine_observation_challenge() -> str:
    authority = _active_observation_authority()
    if authority is None:
        raise RuntimeError("owner-machine observation authority is not configured")
    return authority.issue_challenge()


def _valid_digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _private_ci_request_payload(request: PrivateCiRequest) -> dict[str, object]:
    return {
        "repository": request.repository,
        "repository_visibility": request.repository_visibility,
        "pull_request_number": request.pull_request_number,
        "pull_request_state": request.pull_request_state,
        "pull_request_head_repository": request.pull_request_head_repository,
        "expected_head_sha": request.expected_head_sha,
        "observed_head_sha": request.observed_head_sha,
        "workflow_identity": request.workflow_identity,
        "target_os": request.target_os.value,
        "runner_scope_repository": request.runner_scope_repository,
        "runner_nonce": request.runner_nonce,
        "runner_label": request.runner_label,
        "environment_generation": request.environment_generation,
        "residual_runner_count": request.residual_runner_count,
        "environment_reset_proven": request.environment_reset_proven,
    }


def _validate_private_ci_request_shape(request: object) -> None:
    if type(request) is not PrivateCiRequest:
        raise ValueError("owner-machine observation must be exact PrivateCiRequest")
    payload = _private_ci_request_payload(request)
    for key, value in payload.items():
        if key in {"pull_request_number", "residual_runner_count"}:
            if type(value) is not int:
                raise ValueError("owner-machine observation integer field type invalid")
        elif key == "environment_reset_proven":
            if type(value) is not bool:
                raise ValueError("owner-machine observation bool field type invalid")
        elif key == "target_os":
            if type(value) is not str:
                raise ValueError("owner-machine observation target_os invalid")
        elif type(value) is not str:
            raise ValueError("owner-machine observation string field type invalid")


def owner_machine_observation_auth_message(
    request: PrivateCiRequest,
    *,
    challenge: str,
) -> bytes:
    _validate_private_ci_request_shape(request)
    if not _valid_digest(challenge):
        raise ValueError("invalid owner-machine observation challenge")
    payload = _private_ci_request_payload(request)
    payload["authority_challenge"] = challenge
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def authenticate_owner_machine_observation(
    request: PrivateCiRequest,
    *,
    challenge: str,
    auth_tag: str,
) -> AuthenticatedOwnerMachineObservation:
    authority = _active_observation_authority()
    if authority is None:
        raise RuntimeError("owner-machine observation authority is not configured")
    return authority.authenticate(request, challenge=challenge, auth_tag=auth_tag)


def build_registration_plan_spec(
    *, repository: str, pull_request_number: int, target_sha: str
) -> OperatorStepSpec:
    return OperatorStepSpec(
        operation_id=REGISTRATION_OPERATION_ID,
        step_id=REGISTRATION_STEP_ID,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=repository,
        pull_request_number=pull_request_number,
        target_sha=target_sha,
        target_host_role=OWNER_MACHINE_HOST_ROLE,
        required_identity=TRUSTED_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=REGISTRATION_TRANSCRIPT,
        expected_success_marker=REGISTRATION_SUCCESS_MARKER,
        allowed_effect_families=REGISTRATION_EFFECTS,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id="issue213-registration-preflight",
            producer_step_id="registration-preflight",
            evidence_sha256=PLANNING_EVIDENCE_SHA256,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=False,
        require_fail_fast=False,
    )


def build_cleanup_plan_spec(
    *, repository: str, pull_request_number: int, target_sha: str
) -> OperatorStepSpec:
    return OperatorStepSpec(
        operation_id=CLEANUP_OPERATION_ID,
        step_id=CLEANUP_STEP_ID,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=repository,
        pull_request_number=pull_request_number,
        target_sha=target_sha,
        target_host_role=OWNER_MACHINE_HOST_ROLE,
        required_identity=TRUSTED_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=CLEANUP_TRANSCRIPT,
        expected_success_marker=CLEANUP_SUCCESS_MARKER,
        allowed_effect_families=CLEANUP_EFFECTS,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id="issue213-cleanup-preflight",
            producer_step_id="cleanup-preflight",
            evidence_sha256=PLANNING_EVIDENCE_SHA256,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=False,
        require_fail_fast=False,
    )


def _phases() -> tuple[OwnerMachineBridgePhasePlan, ...]:
    return (
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.GITHUB_PREFLIGHT, False, TRUSTED_BROKER_IDENTITY, True, False, False, True),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.OWNER_MACHINE_PREFLIGHT, False, TRUSTED_BROKER_IDENTITY, True, False, False, True),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.AST_ATTESTATION, False, TRUSTED_BROKER_IDENTITY, True, False, False, True),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.OPERATOR_GATE, False, TRUSTED_BROKER_IDENTITY, True, False, False, True),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.JIT_REGISTRATION, False, TRUSTED_BROKER_IDENTITY, True, False, False, False),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.TARGET_ENVIRONMENT, False, TRUSTED_BROKER_IDENTITY, True, False, False, False),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.ONE_JOB_RUNNER, False, TARGET_EXECUTION_IDENTITY, False, True, True, True),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.CLEANUP_RESET, False, TRUSTED_BROKER_IDENTITY, True, False, False, False),
        OwnerMachineBridgePhasePlan(OwnerMachineBridgePhase.ZERO_RESIDUAL_READBACK, False, TRUSTED_BROKER_IDENTITY, True, False, False, True),
    )


def _source_request_matches_durable_binding(request: PrivateCiRequest, binding: object) -> bool:
    return (
        request.repository == binding.repository
        and request.pull_request_number == binding.pull_request_number
        and request.expected_head_sha == binding.expected_head_sha
        and request.workflow_identity == binding.workflow_identity
        and request.target_os is binding.target_os
        and request.runner_scope_repository == binding.runner_scope_repository
        and request.runner_nonce == binding.runner_nonce
        and request.runner_label == binding.runner_label
        and request.environment_generation == binding.environment_generation
    )


def _validate_planning_candidate(
    spec: OperatorStepSpec,
    candidate: str,
    attestation: AuthenticatedAstAttestation,
) -> tuple[OperatorGateStatus, tuple[str, ...]]:
    spec_reasons = _spec_reason_codes(spec)
    if spec_reasons:
        return OperatorGateStatus.BLOCKED, spec_reasons
    if type(candidate) is not str or not candidate.strip():
        return OperatorGateStatus.BLOCKED, ("CANDIDATE_INVALID",)
    return _attestation_reason_codes(spec, _candidate_sha256(candidate), attestation)


def build_owner_machine_jit_bridge_plan(
    request: OwnerMachineBridgeRequest,
    *,
    durable_authority: DurablePrivateCiAuthority,
) -> OwnerMachineBridgeResult:
    """Validate the final non-live bridge without consuming live execution authority.

    The trusted observation is authenticated with a controller-issued one-time
    challenge and then represented by a one-time opaque capability. Repository
    and workflow allowlists are controller-owned configuration. Registration
    and cleanup specs are reconstructed from fixed bridge policy. Planning
    checks authenticated AST/effect evidence only and does not consume live
    execution prior-evidence capabilities. No live effect occurs here.
    """

    phases = _phases()
    if type(request) is not OwnerMachineBridgeRequest:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.BLOCKED, ("BRIDGE_REQUEST_TYPE_INVALID",), phases)
    if type(durable_authority) is not DurablePrivateCiAuthority:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.BLOCKED, ("DURABLE_AUTHORITY_TYPE_INVALID",), phases)

    observation_authority = _active_observation_authority()
    if observation_authority is None:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.UNCERTAIN, ("OBSERVATION_AUTHORITY_NOT_CONFIGURED",), phases)
    source_request = observation_authority.claim(request.observation)
    if source_request is None:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.BLOCKED, ("TRUSTED_OBSERVATION_UNKNOWN_OR_CONSUMED",), phases)

    contract_result = validate_and_reserve_private_ci_request(
        source_request,
        allowed_repositories=observation_authority.allowed_repositories,
        allowed_workflow_identities=observation_authority.allowed_workflow_identities,
        nonce_authority=PrivateCiNonceAuthority(),
    )
    if contract_result.result is not PrivateCiValidationResult.ACCEPT:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.BLOCKED, ("PRIVATE_CI_CONTRACT_REJECTED",), phases)

    try:
        binding = durable_authority.binding_for(request.reservation)
    except DurablePrivateCiAuthorityError:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.UNCERTAIN, ("DURABLE_AUTHORITY_READ_FAILED",), phases)
    if binding is None:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.BLOCKED, ("DURABLE_RESERVATION_UNKNOWN_OR_CONSUMED",), phases)

    reasons: list[str] = []
    if not _source_request_matches_durable_binding(source_request, binding):
        reasons.append("SOURCE_REQUEST_DURABLE_BINDING_MISMATCH")
    if binding.target_os is not PrivateCiTargetOs.WINDOWS:
        reasons.append("WINDOWS_LIVE_PILOT_REQUIRED")

    registration_spec = build_registration_plan_spec(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.expected_head_sha,
    )
    cleanup_spec = build_cleanup_plan_spec(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.expected_head_sha,
    )

    if reasons:
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.BLOCKED, tuple(reasons), phases)

    registration_status, registration_reasons = _validate_planning_candidate(
        registration_spec,
        request.registration_candidate,
        request.registration_ast_attestation,
    )
    if registration_status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            tuple(f"REGISTRATION_GATE_{reason}" for reason in registration_reasons) or ("REGISTRATION_GATE_NOT_PASS",),
            phases,
        )

    cleanup_status, cleanup_reasons = _validate_planning_candidate(
        cleanup_spec,
        request.cleanup_candidate,
        request.cleanup_ast_attestation,
    )
    if cleanup_status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            tuple(f"CLEANUP_GATE_{reason}" for reason in cleanup_reasons) or ("CLEANUP_GATE_NOT_PASS",),
            phases,
        )

    if any(phase.live_effects_allowed for phase in phases):
        return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.BLOCKED, ("NON_LIVE_BOUNDARY_VIOLATED",), phases)

    return OwnerMachineBridgeResult(OwnerMachineBridgeStatus.READY_FOR_LIVE_PILOT, (), phases)
