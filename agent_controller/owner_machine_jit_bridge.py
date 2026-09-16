from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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
from agent_controller.private_ci_contract import PrivateCiTargetOs
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
    observed_repository_visibility: str
    observed_pull_request_state: str
    observed_pull_request_head_repository: str
    observed_head_sha: str
    observed_workflow_identity: str
    observed_residual_runner_count: int
    environment_reset_proven: bool
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


def _plain_non_empty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _full_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


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
) -> OwnerMachineBridgeResult:
    """Build and validate the final non-live plan before the first live pilot.

    This function performs no GitHub, runner, account, ACL, service, task, or
    target-code execution. It only reads durable authority state and invokes the
    already-merged deterministic operator gate over supplied candidate text and
    authenticated capabilities.
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

    if type(binding.target_os) is not PrivateCiTargetOs or binding.target_os is not PrivateCiTargetOs.WINDOWS:
        reasons.append("WINDOWS_LIVE_PILOT_REQUIRED")
    if request.observed_repository_visibility != "private":
        reasons.append("REPOSITORY_NOT_PRIVATE")
    if request.observed_pull_request_state != "open":
        reasons.append("PULL_REQUEST_NOT_OPEN")
    if request.observed_pull_request_head_repository != binding.repository:
        reasons.append("FORK_OR_CROSS_REPOSITORY_HEAD")
    if not _full_sha(request.observed_head_sha) or request.observed_head_sha != binding.expected_head_sha:
        reasons.append("HEAD_SHA_DRIFT")
    if request.observed_workflow_identity != binding.workflow_identity:
        reasons.append("WORKFLOW_IDENTITY_DRIFT")
    if type(request.observed_residual_runner_count) is not int or request.observed_residual_runner_count != 0:
        reasons.append("RESIDUAL_RUNNER_PRESENT")
    if request.environment_reset_proven is not True:
        reasons.append("ENVIRONMENT_RESET_UNPROVEN")

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
