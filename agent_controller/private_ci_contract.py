from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import FrozenSet, Iterable, Optional, Tuple


class PrivateCiTargetOs(str, Enum):
    WINDOWS = "windows"
    UBUNTU = "ubuntu"


class PrivateCiValidationResult(str, Enum):
    ACCEPT = "ACCEPT"
    BLOCKED = "BLOCKED"


class PrivateCiPhaseStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_RUN = "NOT_RUN"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class PrivateCiRequest:
    repository: str
    repository_visibility: str
    pull_request_number: int
    pull_request_state: str
    pull_request_head_repository: str
    expected_head_sha: str
    observed_head_sha: str
    workflow_identity: str
    target_os: PrivateCiTargetOs
    runner_scope_repository: str
    runner_nonce: str
    runner_label: str
    environment_generation: str
    residual_runner_count: int
    environment_reset_proven: bool


@dataclass(frozen=True, eq=False)
class PrivateCiAcceptedRequest:
    """Opaque process-local proof that a request passed validation and reservation.

    Callers may hold and pass this object, but result validation accepts it only
    when the same nonce authority recorded this exact object identity while
    atomically burning the request nonce.
    """

    request: PrivateCiRequest


class PrivateCiNonceAuthority:
    """Process-local linear authority for nonce reservation and acceptance proof.

    The later owner-machine bridge must replace or wrap this with durable
    cross-process storage before live runner registration is allowed.
    """

    def __init__(self, used_nonces: Iterable[str] = ()) -> None:
        self._used_nonces = set(used_nonces)
        self._accepted_requests = set()
        self._lock = Lock()

    def _reserve_accepted(self, nonce: str, accepted: PrivateCiAcceptedRequest) -> bool:
        with self._lock:
            if nonce in self._used_nonces:
                return False
            self._used_nonces.add(nonce)
            self._accepted_requests.add(accepted)
            return True

    def is_used(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._used_nonces

    def owns(self, accepted: PrivateCiAcceptedRequest) -> bool:
        with self._lock:
            return accepted in self._accepted_requests


@dataclass(frozen=True)
class PrivateCiRequestValidation:
    valid: bool
    result: PrivateCiValidationResult
    reason: str
    accepted_request: Optional[PrivateCiAcceptedRequest] = None


@dataclass(frozen=True)
class PrivateCiExecutionResult:
    repository: str
    pull_request_number: int
    exact_head_sha: str
    workflow_identity: str
    target_os: PrivateCiTargetOs
    runner_scope_repository: str
    runner_nonce: str
    runner_label: str
    environment_generation: str
    registration: PrivateCiPhaseStatus
    dispatch: PrivateCiPhaseStatus
    target_execution: PrivateCiPhaseStatus
    cleanup: PrivateCiPhaseStatus
    post_cleanup_readback: PrivateCiPhaseStatus
    residual_runner_count: int
    environment_reset_proven: bool


@dataclass(frozen=True)
class PrivateCiResultValidation:
    valid: bool
    result: PrivateCiValidationResult
    reason: str


def _is_full_sha(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_non_empty_string(value: str) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_runner_nonce(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 64
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in value)
    )


def _canonical_runner_label(nonce: str) -> str:
    return f"ac-private-ci-{nonce}"


def validate_and_reserve_private_ci_request(
    request: PrivateCiRequest,
    *,
    allowed_repositories: FrozenSet[str],
    allowed_workflow_identities: FrozenSet[str],
    nonce_authority: PrivateCiNonceAuthority,
) -> PrivateCiRequestValidation:
    """Validate and atomically reserve one exact-head private-CI request.

    This contract does not register a runner, dispatch a workflow, mutate
    GitHub, or inspect the host. Callers must populate it from independently
    re-read trusted facts immediately before live execution. A request that
    passes every other precondition burns its nonce and receives an authority-
    owned acceptance proof before returning ACCEPT.
    """

    if not _is_non_empty_string(request.repository):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "repository is invalid")
    if request.repository not in allowed_repositories:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "repository is not allowlisted")
    if request.repository_visibility != "private":
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "repository is not private")
    if not isinstance(request.pull_request_number, int) or isinstance(request.pull_request_number, bool) or request.pull_request_number <= 0:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "pull request number is invalid")
    if request.pull_request_state != "open":
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "pull request is not open")
    if request.pull_request_head_repository != request.repository:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "fork or cross-repository pull request is not allowed")
    if not _is_full_sha(request.expected_head_sha) or not _is_full_sha(request.observed_head_sha):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "head SHA is invalid")
    if request.expected_head_sha != request.observed_head_sha:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "pull request head drifted")
    if not _is_non_empty_string(request.workflow_identity):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "workflow identity is invalid")
    if request.workflow_identity not in allowed_workflow_identities:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "workflow identity is not allowlisted")
    if not isinstance(request.target_os, PrivateCiTargetOs):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "target OS is invalid")
    if request.runner_scope_repository != request.repository:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner registration scope does not match repository")
    if not _is_runner_nonce(request.runner_nonce):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner nonce is invalid")
    if request.runner_label != _canonical_runner_label(request.runner_nonce):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner label is not canonically bound to nonce")
    if not _is_non_empty_string(request.environment_generation):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "environment generation is invalid")
    if not isinstance(request.residual_runner_count, int) or isinstance(request.residual_runner_count, bool) or request.residual_runner_count < 0:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "residual runner count is invalid")
    if request.residual_runner_count != 0:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "residual runner registration exists")
    if request.environment_reset_proven is not True:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "execution environment reset is not proven")
    if not isinstance(nonce_authority, PrivateCiNonceAuthority):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "nonce authority is invalid")

    accepted = PrivateCiAcceptedRequest(request=request)
    if not nonce_authority._reserve_accepted(request.runner_nonce, accepted):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner nonce was already used")

    return PrivateCiRequestValidation(
        True,
        PrivateCiValidationResult.ACCEPT,
        "request is bound, nonce was reserved, and acceptance proof was issued",
        accepted,
    )


def validate_private_ci_result(
    accepted_request: PrivateCiAcceptedRequest,
    result: PrivateCiExecutionResult,
    *,
    nonce_authority: PrivateCiNonceAuthority,
) -> PrivateCiResultValidation:
    """Validate fail-closed completion of one authority-accepted operation."""

    if not isinstance(nonce_authority, PrivateCiNonceAuthority):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "nonce authority is invalid")
    if not isinstance(accepted_request, PrivateCiAcceptedRequest):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "accepted request proof is invalid")
    if not nonce_authority.owns(accepted_request):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "accepted request proof is not owned by nonce authority")

    request = accepted_request.request

    if not _is_non_empty_string(result.repository):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result repository is invalid")
    if not isinstance(result.pull_request_number, int) or isinstance(result.pull_request_number, bool) or result.pull_request_number <= 0:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result pull request number is invalid")
    if not _is_full_sha(result.exact_head_sha):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result head SHA is invalid")
    if not _is_non_empty_string(result.workflow_identity):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result workflow identity is invalid")
    if not isinstance(result.target_os, PrivateCiTargetOs):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result target OS is invalid")
    if not _is_non_empty_string(result.runner_scope_repository):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result runner scope is invalid")
    if not _is_runner_nonce(result.runner_nonce):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result runner nonce is invalid")
    if result.runner_label != _canonical_runner_label(result.runner_nonce):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result runner label is invalid")
    if not _is_non_empty_string(result.environment_generation):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result environment generation is invalid")

    expected_binding: Tuple[object, ...] = (
        request.repository,
        request.pull_request_number,
        request.expected_head_sha,
        request.workflow_identity,
        request.target_os,
        request.runner_scope_repository,
        request.runner_nonce,
        request.runner_label,
        request.environment_generation,
    )
    observed_binding: Tuple[object, ...] = (
        result.repository,
        result.pull_request_number,
        result.exact_head_sha,
        result.workflow_identity,
        result.target_os,
        result.runner_scope_repository,
        result.runner_nonce,
        result.runner_label,
        result.environment_generation,
    )
    if observed_binding != expected_binding:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result binding does not match accepted request")

    phase_statuses = (
        result.registration,
        result.dispatch,
        result.target_execution,
        result.cleanup,
        result.post_cleanup_readback,
    )
    if any(not isinstance(status, PrivateCiPhaseStatus) for status in phase_statuses):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result contains invalid phase status")
    if any(status is not PrivateCiPhaseStatus.PASS for status in phase_statuses):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "one or more required phases did not pass")
    if not isinstance(result.residual_runner_count, int) or isinstance(result.residual_runner_count, bool) or result.residual_runner_count != 0:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "post-cleanup residual runner state is not zero")
    if result.environment_reset_proven is not True:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "post-cleanup environment reset is not proven")

    return PrivateCiResultValidation(True, PrivateCiValidationResult.ACCEPT, "private CI operation completed with zero residual authority")
