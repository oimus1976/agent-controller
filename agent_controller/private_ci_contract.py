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
    """Opaque immutable snapshot proving one request passed reservation.

    The proof stores only trusted snapshot values copied after validation. It
    never retains the caller-owned request object, so later caller mutation
    cannot retarget an accepted operation. Result validation accepts this proof
    only when the same exact nonce-authority implementation recorded this exact
    object identity while atomically burning the request nonce. Successful
    result validation consumes the proof exactly once.
    """

    repository: str
    pull_request_number: int
    expected_head_sha: str
    workflow_identity: str
    target_os: PrivateCiTargetOs
    runner_scope_repository: str
    runner_nonce: str
    runner_label: str
    environment_generation: str


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

    def _claim_accepted(self, accepted: PrivateCiAcceptedRequest) -> bool:
        """Atomically consume one authority-owned acceptance proof."""

        with self._lock:
            if accepted not in self._accepted_requests:
                return False
            self._accepted_requests.remove(accepted)
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


def _is_plain_non_empty_string(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _is_full_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_runner_nonce(value: object) -> bool:
    return (
        type(value) is str
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
    """Validate, snapshot, and atomically reserve one private-CI request."""

    if type(request) is not PrivateCiRequest:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "request type is invalid")
    if not _is_plain_non_empty_string(request.repository):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "repository is invalid")
    if request.repository not in allowed_repositories:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "repository is not allowlisted")
    if type(request.repository_visibility) is not str or request.repository_visibility != "private":
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "repository is not private")
    if type(request.pull_request_number) is not int or request.pull_request_number <= 0:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "pull request number is invalid")
    if type(request.pull_request_state) is not str or request.pull_request_state != "open":
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "pull request is not open")
    if not _is_plain_non_empty_string(request.pull_request_head_repository) or request.pull_request_head_repository != request.repository:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "fork or cross-repository pull request is not allowed")
    if not _is_full_sha(request.expected_head_sha) or not _is_full_sha(request.observed_head_sha):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "head SHA is invalid")
    if request.expected_head_sha != request.observed_head_sha:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "pull request head drifted")
    if not _is_plain_non_empty_string(request.workflow_identity):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "workflow identity is invalid")
    if request.workflow_identity not in allowed_workflow_identities:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "workflow identity is not allowlisted")
    if type(request.target_os) is not PrivateCiTargetOs:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "target OS is invalid")
    if not _is_plain_non_empty_string(request.runner_scope_repository) or request.runner_scope_repository != request.repository:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner registration scope does not match repository")
    if not _is_runner_nonce(request.runner_nonce):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner nonce is invalid")
    if type(request.runner_label) is not str or request.runner_label != _canonical_runner_label(request.runner_nonce):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner label is not canonically bound to nonce")
    if not _is_plain_non_empty_string(request.environment_generation):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "environment generation is invalid")
    if type(request.residual_runner_count) is not int or request.residual_runner_count < 0:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "residual runner count is invalid")
    if request.residual_runner_count != 0:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "residual runner registration exists")
    if request.environment_reset_proven is not True:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "execution environment reset is not proven")
    if type(nonce_authority) is not PrivateCiNonceAuthority:
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "nonce authority is invalid")

    accepted = PrivateCiAcceptedRequest(
        repository=request.repository,
        pull_request_number=request.pull_request_number,
        expected_head_sha=request.expected_head_sha,
        workflow_identity=request.workflow_identity,
        target_os=request.target_os,
        runner_scope_repository=request.runner_scope_repository,
        runner_nonce=request.runner_nonce,
        runner_label=request.runner_label,
        environment_generation=request.environment_generation,
    )
    if not nonce_authority._reserve_accepted(request.runner_nonce, accepted):
        return PrivateCiRequestValidation(False, PrivateCiValidationResult.BLOCKED, "runner nonce was already used")

    return PrivateCiRequestValidation(
        True,
        PrivateCiValidationResult.ACCEPT,
        "request was validated, snapshotted, reserved, and acceptance proof was issued",
        accepted,
    )


def validate_private_ci_result(
    accepted_request: PrivateCiAcceptedRequest,
    result: PrivateCiExecutionResult,
    *,
    nonce_authority: PrivateCiNonceAuthority,
) -> PrivateCiResultValidation:
    """Validate and atomically consume one accepted private-CI result."""

    if type(nonce_authority) is not PrivateCiNonceAuthority:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "nonce authority is invalid")
    if type(accepted_request) is not PrivateCiAcceptedRequest:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "accepted request proof is invalid")
    if type(result) is not PrivateCiExecutionResult:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result type is invalid")
    if not nonce_authority.owns(accepted_request):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "accepted request proof is not owned by nonce authority")

    if not _is_plain_non_empty_string(result.repository):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result repository is invalid")
    if type(result.pull_request_number) is not int or result.pull_request_number <= 0:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result pull request number is invalid")
    if not _is_full_sha(result.exact_head_sha):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result head SHA is invalid")
    if not _is_plain_non_empty_string(result.workflow_identity):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result workflow identity is invalid")
    if type(result.target_os) is not PrivateCiTargetOs:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result target OS is invalid")
    if not _is_plain_non_empty_string(result.runner_scope_repository):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result runner scope is invalid")
    if not _is_runner_nonce(result.runner_nonce):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result runner nonce is invalid")
    if type(result.runner_label) is not str or result.runner_label != _canonical_runner_label(result.runner_nonce):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result runner label is invalid")
    if not _is_plain_non_empty_string(result.environment_generation):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result environment generation is invalid")

    expected_binding: Tuple[object, ...] = (
        accepted_request.repository,
        accepted_request.pull_request_number,
        accepted_request.expected_head_sha,
        accepted_request.workflow_identity,
        accepted_request.target_os,
        accepted_request.runner_scope_repository,
        accepted_request.runner_nonce,
        accepted_request.runner_label,
        accepted_request.environment_generation,
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
    if any(type(status) is not PrivateCiPhaseStatus for status in phase_statuses):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "result contains invalid phase status")
    if any(status is not PrivateCiPhaseStatus.PASS for status in phase_statuses):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "one or more required phases did not pass")
    if type(result.residual_runner_count) is not int or result.residual_runner_count != 0:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "post-cleanup residual runner state is not zero")
    if result.environment_reset_proven is not True:
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "post-cleanup environment reset is not proven")
    if not nonce_authority._claim_accepted(accepted_request):
        return PrivateCiResultValidation(False, PrivateCiValidationResult.BLOCKED, "accepted request proof was already consumed")

    return PrivateCiResultValidation(True, PrivateCiValidationResult.ACCEPT, "private CI operation completed and acceptance proof was consumed")
