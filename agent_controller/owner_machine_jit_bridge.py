from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    AuthenticatedAstAttestation,
    OperatorEffectClass,
    OperatorGateStatus,
    OperatorStepSpec,
    PriorEvidenceCapability,
    validate_operator_step,
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
    requires_heartbeat_or_progress: bool
    requires_child_exit_code: bool
    requires_fail_fast: bool


@dataclass(frozen=True, slots=True)
class OwnerMachineBridgeRequest:
    reservation: DurablePrivateCiReservation
    source_request: PrivateCiRequest
    owner_machine_host_role: str
    trusted_broker_identity: str
    target_execution_identity: str
    target_authority_exposure: tuple[str, ...]
    registration_spec: OperatorStepSpec
    registration_candidate: str
    registration_ast_attestation: AuthenticatedAstAttestation
    registration_prior_evidence: PriorEvidenceCapability
    cleanup_spec: OperatorStepSpec
    cleanup_candidate: str
    cleanup_ast_attestation: AuthenticatedAstAttestation
    cleanup_prior_evidence: PriorEvidenceCapability


@dataclass(frozen=True, slots=True)
class OwnerMachineBridgeResult:
    status: OwnerMachineBridgeStatus
    reason_codes: tuple[str, ...]
    phases: tuple[OwnerMachineBridgePhasePlan, ...]

    @property
    def ready_for_live_pilot(self) -> bool:
        return self.status is OwnerMachineBridgeStatus.READY_FOR_LIVE_PILOT


def _phases() -> tuple[OwnerMachineBridgePhasePlan, ...]:
    return (
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.GITHUB_PREFLIGHT,
            False,
            TRUSTED_BROKER_IDENTITY,
            False,
            False,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.OWNER_MACHINE_PREFLIGHT,
            False,
            TRUSTED_BROKER_IDENTITY,
            False,
            False,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.AST_ATTESTATION,
            False,
            TRUSTED_BROKER_IDENTITY,
            False,
            False,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.OPERATOR_GATE,
            False,
            TRUSTED_BROKER_IDENTITY,
            False,
            False,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.JIT_REGISTRATION,
            False,
            TRUSTED_BROKER_IDENTITY,
            False,
            True,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.TARGET_ENVIRONMENT,
            False,
            TRUSTED_BROKER_IDENTITY,
            False,
            True,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.ONE_JOB_RUNNER,
            False,
            TARGET_EXECUTION_IDENTITY,
            True,
            True,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.CLEANUP_RESET,
            False,
            TRUSTED_BROKER_IDENTITY,
            True,
            True,
            True,
        ),
        OwnerMachineBridgePhasePlan(
            OwnerMachineBridgePhase.ZERO_RESIDUAL_READBACK,
            False,
            TRUSTED_BROKER_IDENTITY,
            False,
            False,
            True,
        ),
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


def _spec_matches_binding(
    spec: OperatorStepSpec,
    *,
    repository: str,
    pull_request_number: int,
    target_sha: str,
    host_role: str,
    required_identity: str,
) -> bool:
    return (
        type(spec) is OperatorStepSpec
        and spec.workstream == PRIVATE_LOCAL_CI_WORKSTREAM
        and spec.repository == repository
        and spec.pull_request_number == pull_request_number
        and spec.target_sha == target_sha
        and spec.target_host_role == host_role
        and spec.required_identity == required_identity
        and spec.evidence_root == AUTHORITATIVE_EVIDENCE_ROOT
        and spec.effect_class is OperatorEffectClass.BOUNDED_MUTATION
        and spec.require_parser_attestation is True
    )


def build_owner_machine_jit_bridge_plan(
    request: OwnerMachineBridgeRequest,
    *,
    durable_authority: DurablePrivateCiAuthority,
    allowed_repositories: FrozenSet[str],
    allowed_workflow_identities: FrozenSet[str],
) -> OwnerMachineBridgeResult:
    """Build the final deterministic non-live plan before the first live pilot.

    Source-of-truth observations are revalidated through the existing #208
    private-CI contract. Durable binding comes from the #210 SQLite authority.
    Mutation candidates are authorized only through the #212 operator gate.

    This function performs no GitHub, runner, account, ACL, service, task, or
    target-code execution.
    """

    phases = _phases()
    reasons: list[str] = []

    if type(request) is not OwnerMachineBridgeRequest:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            ("BRIDGE_REQUEST_TYPE_INVALID",),
            phases,
        )
    if type(durable_authority) is not DurablePrivateCiAuthority:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            ("DURABLE_AUTHORITY_TYPE_INVALID",),
            phases,
        )
    if type(allowed_repositories) is not frozenset or type(allowed_workflow_identities) is not frozenset:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            ("TRUSTED_ALLOWLIST_TYPE_INVALID",),
            phases,
        )

    contract_result = validate_and_reserve_private_ci_request(
        request.source_request,
        allowed_repositories=allowed_repositories,
        allowed_workflow_identities=allowed_workflow_identities,
        nonce_authority=PrivateCiNonceAuthority(),
    )
    if contract_result.result is not PrivateCiValidationResult.ACCEPT:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            ("PRIVATE_CI_CONTRACT_REJECTED",),
            phases,
        )

    try:
        binding = durable_authority.binding_for(request.reservation)
    except DurablePrivateCiAuthorityError:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.UNCERTAIN,
            ("DURABLE_AUTHORITY_READ_FAILED",),
            phases,
        )
    if binding is None:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            ("DURABLE_RESERVATION_UNKNOWN_OR_CONSUMED",),
            phases,
        )

    if not _source_request_matches_durable_binding(request.source_request, binding):
        reasons.append("SOURCE_REQUEST_DURABLE_BINDING_MISMATCH")
    if binding.target_os is not PrivateCiTargetOs.WINDOWS:
        reasons.append("WINDOWS_LIVE_PILOT_REQUIRED")

    if request.owner_machine_host_role != OWNER_MACHINE_HOST_ROLE:
        reasons.append("OWNER_MACHINE_HOST_ROLE_MISMATCH")
    if request.trusted_broker_identity != TRUSTED_BROKER_IDENTITY:
        reasons.append("TRUSTED_BROKER_IDENTITY_MISMATCH")
    if request.target_execution_identity != TARGET_EXECUTION_IDENTITY:
        reasons.append("TARGET_EXECUTION_IDENTITY_MISMATCH")
    if request.trusted_broker_identity == request.target_execution_identity:
        reasons.append("TRUSTED_AND_TARGET_IDENTITIES_MUST_DIFFER")
    if type(request.target_authority_exposure) is not tuple:
        reasons.append("TARGET_AUTHORITY_EXPOSURE_TYPE_INVALID")
    elif request.target_authority_exposure:
        reasons.append("TARGET_AUTHORITY_EXPOSURE_FORBIDDEN")

    if not _spec_matches_binding(
        request.registration_spec,
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.expected_head_sha,
        host_role=OWNER_MACHINE_HOST_ROLE,
        required_identity=TRUSTED_BROKER_IDENTITY,
    ):
        reasons.append("REGISTRATION_SPEC_BINDING_MISMATCH")
    if not _spec_matches_binding(
        request.cleanup_spec,
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.expected_head_sha,
        host_role=OWNER_MACHINE_HOST_ROLE,
        required_identity=TRUSTED_BROKER_IDENTITY,
    ):
        reasons.append("CLEANUP_SPEC_BINDING_MISMATCH")

    if reasons:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            tuple(reasons),
            phases,
        )

    registration_gate = validate_operator_step(
        request.registration_spec,
        request.registration_candidate,
        ast_attestation=request.registration_ast_attestation,
        prior_evidence_capability=request.registration_prior_evidence,
    )
    if registration_gate.status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            tuple(f"REGISTRATION_GATE_{reason}" for reason in registration_gate.reason_codes)
            or ("REGISTRATION_GATE_NOT_PASS",),
            phases,
        )

    cleanup_gate = validate_operator_step(
        request.cleanup_spec,
        request.cleanup_candidate,
        ast_attestation=request.cleanup_ast_attestation,
        prior_evidence_capability=request.cleanup_prior_evidence,
    )
    if cleanup_gate.status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            tuple(f"CLEANUP_GATE_{reason}" for reason in cleanup_gate.reason_codes)
            or ("CLEANUP_GATE_NOT_PASS",),
            phases,
        )

    if any(phase.live_effects_allowed for phase in phases):
        return OwnerMachineBridgeResult(
            OwnerMachineBridgeStatus.BLOCKED,
            ("NON_LIVE_BOUNDARY_VIOLATED",),
            phases,
        )

    return OwnerMachineBridgeResult(
        OwnerMachineBridgeStatus.READY_FOR_LIVE_PILOT,
        (),
        phases,
    )
