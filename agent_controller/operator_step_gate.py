from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Optional


AUTHORITATIVE_EVIDENCE_ROOT = r"C:\Users\Public\Documents\agent-controller-handoff"
PRIVATE_LOCAL_CI_WORKSTREAM = "private-local-ci-host"
WINDOWS_POWERSHELL_51 = "Windows PowerShell 5.1"
WINDOWS_POWERSHELL_PARSER = "System.Management.Automation.Language.Parser"


class OperatorEffectClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    BOUNDED_MUTATION = "BOUNDED_MUTATION"
    HUMAN_FINAL = "HUMAN_FINAL"


class OperatorGateStatus(str, Enum):
    PASS_TO_OPERATOR = "PASS_TO_OPERATOR"
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True, slots=True)
class PriorEvidenceRequirement:
    producer_operation_id: str
    producer_step_id: str
    evidence_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorStepSpec:
    operation_id: str
    step_id: str
    workstream: str
    repository: str
    pull_request_number: int
    target_sha: str
    target_host_role: str
    required_identity: str
    shell_runtime: str
    effect_class: OperatorEffectClass
    evidence_root: str
    transcript_filename: str
    expected_success_marker: str
    allowed_effect_families: tuple[str, ...]
    prior_evidence_requirement: Optional[PriorEvidenceRequirement]
    require_parser_attestation: bool
    require_heartbeat_or_progress: bool
    require_child_exit_code: bool
    require_fail_fast: bool


@dataclass(frozen=True, slots=True)
class PowerShellAstAttestation:
    runtime: str
    parser: str
    candidate_sha256: str
    spec_sha256: str
    parsed: bool
    error_count: int
    repository: str
    pull_request_number: int
    target_sha: str
    target_host_role: str
    required_identity: str
    evidence_root: str
    transcript_filename: str
    expected_success_marker: str
    observed_effect_families: tuple[str, ...]
    automatic_variable_collisions: tuple[str, ...]
    unresolved_placeholders: tuple[str, ...]
    forbidden_convenience_paths: tuple[str, ...]
    self_declared_gate_authority: bool
    heartbeat_or_progress_proven: bool
    child_exit_code_proven: bool
    fail_fast_proven: bool


@dataclass(frozen=True, slots=True)
class AuthenticatedAstAttestation:
    token: str


@dataclass(frozen=True, slots=True)
class PriorEvidenceCapability:
    token: str


@dataclass(frozen=True, slots=True)
class ResultPublicationCapability:
    token: str


@dataclass(frozen=True, slots=True)
class OperatorGateResult:
    status: OperatorGateStatus
    reason_codes: tuple[str, ...]
    candidate_sha256: str

    @property
    def passed(self) -> bool:
        return self.status is OperatorGateStatus.PASS_TO_OPERATOR


@dataclass(frozen=True, slots=True)
class _EvidenceBinding:
    repository: str
    pull_request_number: int
    target_sha: str
    producer_operation_id: str
    producer_step_id: str
    evidence_sha256: str


@dataclass(frozen=True, slots=True)
class _ResultPublicationBinding:
    phase: int
    result_sha256: str
    upstream_sha256: str


class _ControllerAuthority:
    __slots__ = (
        "_ast_hmac_key",
        "_evidence_hmac_key",
        "_ast_reports",
        "_evidence_bindings",
        "_consumed_evidence",
        "_evidence_lock",
        "_result_publication_bindings",
        "_consumed_result_publications",
        "_result_publication_lock",
    )

    def __init__(self, *, ast_hmac_key: bytes, evidence_hmac_key: bytes) -> None:
        self._ast_hmac_key = ast_hmac_key
        self._evidence_hmac_key = evidence_hmac_key
        self._ast_reports: dict[str, PowerShellAstAttestation] = {}
        self._evidence_bindings: dict[str, _EvidenceBinding] = {}
        self._consumed_evidence: set[str] = set()
        self._evidence_lock = threading.Lock()
        self._result_publication_bindings: dict[
            str, _ResultPublicationBinding
        ] = {}
        self._consumed_result_publications: set[str] = set()
        self._result_publication_lock = threading.Lock()

    def authenticate_ast(
        self,
        report: PowerShellAstAttestation,
        *,
        auth_tag: str,
    ) -> AuthenticatedAstAttestation:
        _validate_attestation_shape(report)
        if not _valid_digest(auth_tag):
            raise ValueError("invalid AST authentication tag")
        expected_tag = hmac.new(
            self._ast_hmac_key,
            ast_attestation_auth_message(report),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("AST authentication failed")
        token = secrets.token_hex(32)
        self._ast_reports[token] = report
        return AuthenticatedAstAttestation(token=token)

    def ast_report_for(self, capability: object) -> Optional[PowerShellAstAttestation]:
        if type(capability) is not AuthenticatedAstAttestation:
            return None
        if not _valid_digest(capability.token):
            return None
        return self._ast_reports.get(capability.token)

    def authenticate_evidence(
        self,
        *,
        repository: str,
        pull_request_number: int,
        target_sha: str,
        producer_operation_id: str,
        producer_step_id: str,
        evidence_bytes: bytes,
        auth_tag: str,
    ) -> PriorEvidenceCapability:
        values = (repository, target_sha, producer_operation_id, producer_step_id)
        if not all(_valid_nonempty_string(value) for value in values):
            raise ValueError("invalid evidence binding")
        if type(pull_request_number) is not int or pull_request_number <= 0:
            raise ValueError("invalid evidence PR number")
        if not _valid_sha(target_sha):
            raise ValueError("invalid evidence target SHA")
        if type(evidence_bytes) is not bytes:
            raise ValueError("evidence bytes must be exact bytes")
        if not _valid_digest(auth_tag):
            raise ValueError("invalid evidence authentication tag")

        evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
        message = prior_evidence_auth_message(
            repository=repository,
            pull_request_number=pull_request_number,
            target_sha=target_sha,
            producer_operation_id=producer_operation_id,
            producer_step_id=producer_step_id,
            evidence_sha256=evidence_sha256,
        )
        expected_tag = hmac.new(self._evidence_hmac_key, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("evidence authentication failed")

        token = secrets.token_hex(32)
        self._evidence_bindings[token] = _EvidenceBinding(
            repository=repository,
            pull_request_number=pull_request_number,
            target_sha=target_sha,
            producer_operation_id=producer_operation_id,
            producer_step_id=producer_step_id,
            evidence_sha256=evidence_sha256,
        )
        return PriorEvidenceCapability(token=token)

    def claim_evidence(
        self,
        capability: object,
        *,
        spec: OperatorStepSpec,
    ) -> tuple[bool, str]:
        if type(capability) is not PriorEvidenceCapability:
            return False, "PRIOR_EVIDENCE_CAPABILITY_TYPE_INVALID"
        if not _valid_digest(capability.token):
            return False, "PRIOR_EVIDENCE_CAPABILITY_INVALID"
        requirement = spec.prior_evidence_requirement
        if type(requirement) is not PriorEvidenceRequirement:
            return False, "PRIOR_EVIDENCE_REQUIREMENT_INVALID"
        expected = _EvidenceBinding(
            repository=spec.repository,
            pull_request_number=spec.pull_request_number,
            target_sha=spec.target_sha,
            producer_operation_id=requirement.producer_operation_id,
            producer_step_id=requirement.producer_step_id,
            evidence_sha256=requirement.evidence_sha256,
        )
        token = capability.token
        with self._evidence_lock:
            if token in self._consumed_evidence:
                return False, "PRIOR_EVIDENCE_ALREADY_CONSUMED"
            binding = self._evidence_bindings.get(token)
            if binding is None:
                return False, "PRIOR_EVIDENCE_UNKNOWN"
            if binding != expected:
                return False, "PRIOR_EVIDENCE_BINDING_MISMATCH"
            self._consumed_evidence.add(token)
        return True, ""

    def authenticate_result_publication(
        self,
        *,
        phase: int,
        result_bytes: bytes,
        upstream_sha256: str,
        auth_tag: str,
    ) -> ResultPublicationCapability:
        if phase not in (6, 7):
            raise ValueError("result publication phase invalid")
        if type(result_bytes) is not bytes:
            raise ValueError("result publication requires exact result bytes")
        if not _valid_digest(upstream_sha256):
            raise ValueError("result publication upstream SHA-256 invalid")
        if not _valid_digest(auth_tag):
            raise ValueError("result publication authentication tag invalid")

        result_sha256 = hashlib.sha256(result_bytes).hexdigest()
        message = result_publication_auth_message(
            phase=phase,
            result_sha256=result_sha256,
            upstream_sha256=upstream_sha256,
        )
        expected_tag = hmac.new(
            self._evidence_hmac_key,
            message,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("result publication authentication failed")

        token = secrets.token_hex(32)
        self._result_publication_bindings[token] = _ResultPublicationBinding(
            phase=phase,
            result_sha256=result_sha256,
            upstream_sha256=upstream_sha256,
        )
        return ResultPublicationCapability(token=token)

    def claim_result_publication(
        self,
        capability: object,
        *,
        phase: int,
        result_sha256: str,
        upstream_sha256: str,
    ) -> tuple[bool, str]:
        if type(capability) is not ResultPublicationCapability:
            return False, "RESULT_PUBLICATION_CAPABILITY_TYPE_INVALID"
        if not _valid_digest(capability.token):
            return False, "RESULT_PUBLICATION_CAPABILITY_INVALID"
        if phase not in (6, 7):
            return False, "RESULT_PUBLICATION_PHASE_INVALID"
        if not _valid_digest(result_sha256):
            return False, "RESULT_PUBLICATION_RESULT_SHA_INVALID"
        if not _valid_digest(upstream_sha256):
            return False, "RESULT_PUBLICATION_UPSTREAM_SHA_INVALID"

        expected = _ResultPublicationBinding(
            phase=phase,
            result_sha256=result_sha256,
            upstream_sha256=upstream_sha256,
        )
        token = capability.token
        with self._result_publication_lock:
            if token in self._consumed_result_publications:
                return False, "RESULT_PUBLICATION_ALREADY_CONSUMED"
            actual = self._result_publication_bindings.get(token)
            if actual is None:
                return False, "RESULT_PUBLICATION_UNKNOWN"
            if actual != expected:
                return False, "RESULT_PUBLICATION_BINDING_MISMATCH"
            self._consumed_result_publications.add(token)
        return True, ""


_ACTIVE_CONTROLLER_AUTHORITY: Optional[_ControllerAuthority] = None
_AUTHORITY_CONFIG_LOCK = threading.Lock()


def configure_controller_authority(*, ast_hmac_key: bytes, evidence_hmac_key: bytes) -> None:
    """Configure the trusted controller authority exactly once per process.

    Keys come from trusted controller bootstrap, never candidate text or target
    repository code. The validator does not accept caller-supplied authorities.
    """

    global _ACTIVE_CONTROLLER_AUTHORITY
    if type(ast_hmac_key) is not bytes or len(ast_hmac_key) < 32:
        raise ValueError("AST HMAC key must be at least 32 bytes")
    if type(evidence_hmac_key) is not bytes or len(evidence_hmac_key) < 32:
        raise ValueError("evidence HMAC key must be at least 32 bytes")
    with _AUTHORITY_CONFIG_LOCK:
        if _ACTIVE_CONTROLLER_AUTHORITY is not None:
            raise RuntimeError("controller authority already configured")
        _ACTIVE_CONTROLLER_AUTHORITY = _ControllerAuthority(
            ast_hmac_key=ast_hmac_key,
            evidence_hmac_key=evidence_hmac_key,
        )


def _active_authority() -> Optional[_ControllerAuthority]:
    return _ACTIVE_CONTROLLER_AUTHORITY


def authenticate_ast_attestation(
    report: PowerShellAstAttestation,
    *,
    auth_tag: str,
) -> AuthenticatedAstAttestation:
    authority = _active_authority()
    if authority is None:
        raise RuntimeError("controller authority is not configured")
    return authority.authenticate_ast(report, auth_tag=auth_tag)


def authenticate_prior_evidence(
    *,
    repository: str,
    pull_request_number: int,
    target_sha: str,
    producer_operation_id: str,
    producer_step_id: str,
    evidence_bytes: bytes,
    auth_tag: str,
) -> PriorEvidenceCapability:
    authority = _active_authority()
    if authority is None:
        raise RuntimeError("controller authority is not configured")
    return authority.authenticate_evidence(
        repository=repository,
        pull_request_number=pull_request_number,
        target_sha=target_sha,
        producer_operation_id=producer_operation_id,
        producer_step_id=producer_step_id,
        evidence_bytes=evidence_bytes,
        auth_tag=auth_tag,
    )


def authenticate_result_publication(
    *,
    phase: int,
    result_bytes: bytes,
    upstream_sha256: str,
    auth_tag: str,
) -> ResultPublicationCapability:
    authority = _active_authority()
    if authority is None:
        raise RuntimeError("controller authority is not configured")
    return authority.authenticate_result_publication(
        phase=phase,
        result_bytes=result_bytes,
        upstream_sha256=upstream_sha256,
        auth_tag=auth_tag,
    )


def consume_result_publication_capability(
    capability: object,
    *,
    phase: int,
    result_sha256: str,
    upstream_sha256: str,
) -> None:
    authority = _active_authority()
    if authority is None:
        raise RuntimeError("controller authority is not configured")
    claimed, reason = authority.claim_result_publication(
        capability,
        phase=phase,
        result_sha256=result_sha256,
        upstream_sha256=upstream_sha256,
    )
    if not claimed:
        raise ValueError(reason)


def _candidate_sha256(candidate: str) -> str:
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def _valid_nonempty_string(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _valid_sha(value: object) -> bool:
    return type(value) is str and len(value) == 40 and all(c in "0123456789abcdef" for c in value)


def _valid_digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _valid_filename(value: object) -> bool:
    if not _valid_nonempty_string(value):
        return False
    assert type(value) is str
    return not any(separator in value for separator in ("/", "\\")) and value not in (".", "..")


def _valid_plain_string_tuple(value: object) -> bool:
    return type(value) is tuple and all(_valid_nonempty_string(item) for item in value)


def _canonical_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def result_publication_auth_message(
    *,
    phase: int,
    result_sha256: str,
    upstream_sha256: str,
) -> bytes:
    if phase not in (6, 7):
        raise ValueError("result publication phase invalid")
    if not _valid_digest(result_sha256):
        raise ValueError("result publication result SHA-256 invalid")
    if not _valid_digest(upstream_sha256):
        raise ValueError("result publication upstream SHA-256 invalid")
    return _canonical_bytes(
        {
            "phase": phase,
            "result_sha256": result_sha256,
            "upstream_sha256": upstream_sha256,
        }
    )


def _spec_payload(spec: OperatorStepSpec) -> dict[str, object]:
    requirement = spec.prior_evidence_requirement
    prior = None
    if type(requirement) is PriorEvidenceRequirement:
        prior = {
            "producer_operation_id": requirement.producer_operation_id,
            "producer_step_id": requirement.producer_step_id,
            "evidence_sha256": requirement.evidence_sha256,
        }
    return {
        "operation_id": spec.operation_id,
        "step_id": spec.step_id,
        "workstream": spec.workstream,
        "repository": spec.repository,
        "pull_request_number": spec.pull_request_number,
        "target_sha": spec.target_sha,
        "target_host_role": spec.target_host_role,
        "required_identity": spec.required_identity,
        "shell_runtime": spec.shell_runtime,
        "effect_class": spec.effect_class.value,
        "evidence_root": spec.evidence_root,
        "transcript_filename": spec.transcript_filename,
        "expected_success_marker": spec.expected_success_marker,
        "allowed_effect_families": list(spec.allowed_effect_families),
        "prior_evidence_requirement": prior,
        "require_parser_attestation": spec.require_parser_attestation,
        "require_heartbeat_or_progress": spec.require_heartbeat_or_progress,
        "require_child_exit_code": spec.require_child_exit_code,
        "require_fail_fast": spec.require_fail_fast,
    }


def operator_step_spec_sha256(spec: OperatorStepSpec) -> str:
    return hashlib.sha256(_canonical_bytes(_spec_payload(spec))).hexdigest()


def _attestation_payload(report: PowerShellAstAttestation) -> dict[str, object]:
    return {
        "runtime": report.runtime,
        "parser": report.parser,
        "candidate_sha256": report.candidate_sha256,
        "spec_sha256": report.spec_sha256,
        "parsed": report.parsed,
        "error_count": report.error_count,
        "repository": report.repository,
        "pull_request_number": report.pull_request_number,
        "target_sha": report.target_sha,
        "target_host_role": report.target_host_role,
        "required_identity": report.required_identity,
        "evidence_root": report.evidence_root,
        "transcript_filename": report.transcript_filename,
        "expected_success_marker": report.expected_success_marker,
        "observed_effect_families": list(report.observed_effect_families),
        "automatic_variable_collisions": list(report.automatic_variable_collisions),
        "unresolved_placeholders": list(report.unresolved_placeholders),
        "forbidden_convenience_paths": list(report.forbidden_convenience_paths),
        "self_declared_gate_authority": report.self_declared_gate_authority,
        "heartbeat_or_progress_proven": report.heartbeat_or_progress_proven,
        "child_exit_code_proven": report.child_exit_code_proven,
        "fail_fast_proven": report.fail_fast_proven,
    }


def ast_attestation_auth_message(report: PowerShellAstAttestation) -> bytes:
    _validate_attestation_shape(report)
    return _canonical_bytes(_attestation_payload(report))


def prior_evidence_auth_message(
    *,
    repository: str,
    pull_request_number: int,
    target_sha: str,
    producer_operation_id: str,
    producer_step_id: str,
    evidence_sha256: str,
) -> bytes:
    return _canonical_bytes(
        {
            "repository": repository,
            "pull_request_number": pull_request_number,
            "target_sha": target_sha,
            "producer_operation_id": producer_operation_id,
            "producer_step_id": producer_step_id,
            "evidence_sha256": evidence_sha256,
        }
    )


def _validate_attestation_shape(report: object) -> None:
    if type(report) is not PowerShellAstAttestation:
        raise ValueError("invalid AST attestation type")
    string_fields = (
        report.runtime,
        report.parser,
        report.candidate_sha256,
        report.spec_sha256,
        report.repository,
        report.target_sha,
        report.target_host_role,
        report.required_identity,
        report.evidence_root,
        report.transcript_filename,
        report.expected_success_marker,
    )
    if not all(type(value) is str for value in string_fields):
        raise ValueError("invalid AST attestation string field")
    if not _valid_digest(report.candidate_sha256) or not _valid_digest(report.spec_sha256):
        raise ValueError("invalid AST attestation digest")
    if type(report.pull_request_number) is not int or report.pull_request_number <= 0:
        raise ValueError("invalid AST attestation PR")
    if type(report.parsed) is not bool or type(report.error_count) is not int:
        raise ValueError("invalid AST parse field")
    tuple_fields = (
        report.observed_effect_families,
        report.automatic_variable_collisions,
        report.unresolved_placeholders,
        report.forbidden_convenience_paths,
    )
    if not all(_valid_plain_string_tuple(value) for value in tuple_fields):
        raise ValueError("invalid AST attestation collection")
    bool_fields = (
        report.self_declared_gate_authority,
        report.heartbeat_or_progress_proven,
        report.child_exit_code_proven,
        report.fail_fast_proven,
    )
    if not all(type(value) is bool for value in bool_fields):
        raise ValueError("invalid AST attestation bool")


def _spec_reason_codes(spec: object) -> tuple[str, ...]:
    if type(spec) is not OperatorStepSpec:
        return ("SPEC_TYPE_INVALID",)
    reasons: list[str] = []
    required_strings = (
        ("OPERATION_ID_INVALID", spec.operation_id),
        ("STEP_ID_INVALID", spec.step_id),
        ("WORKSTREAM_INVALID", spec.workstream),
        ("REPOSITORY_INVALID", spec.repository),
        ("TARGET_HOST_ROLE_INVALID", spec.target_host_role),
        ("REQUIRED_IDENTITY_INVALID", spec.required_identity),
        ("SHELL_RUNTIME_INVALID", spec.shell_runtime),
        ("EXPECTED_SUCCESS_MARKER_INVALID", spec.expected_success_marker),
    )
    for reason, value in required_strings:
        if not _valid_nonempty_string(value):
            reasons.append(reason)
    if spec.workstream != PRIVATE_LOCAL_CI_WORKSTREAM:
        reasons.append("WORKSTREAM_NOT_PRIVATE_LOCAL_CI")
    if type(spec.pull_request_number) is not int or spec.pull_request_number <= 0:
        reasons.append("PR_NUMBER_INVALID")
    if not _valid_sha(spec.target_sha):
        reasons.append("TARGET_SHA_INVALID")
    if type(spec.effect_class) is not OperatorEffectClass:
        reasons.append("EFFECT_CLASS_INVALID")
    if type(spec.evidence_root) is not str or spec.evidence_root != AUTHORITATIVE_EVIDENCE_ROOT:
        reasons.append("EVIDENCE_ROOT_INVALID")
    if not _valid_filename(spec.transcript_filename):
        reasons.append("TRANSCRIPT_FILENAME_INVALID")
    if spec.shell_runtime != WINDOWS_POWERSHELL_51:
        reasons.append("SHELL_RUNTIME_UNSUPPORTED")
    if not _valid_plain_string_tuple(spec.allowed_effect_families):
        reasons.append("ALLOWED_EFFECT_FAMILIES_INVALID")
    if type(spec.require_parser_attestation) is not bool:
        reasons.append("PARSER_REQUIREMENT_INVALID")
    if type(spec.require_heartbeat_or_progress) is not bool:
        reasons.append("PROGRESS_REQUIREMENT_INVALID")
    if type(spec.require_child_exit_code) is not bool:
        reasons.append("EXIT_CODE_REQUIREMENT_INVALID")
    if type(spec.require_fail_fast) is not bool:
        reasons.append("FAIL_FAST_REQUIREMENT_INVALID")

    requirement = spec.prior_evidence_requirement
    if spec.effect_class is OperatorEffectClass.READ_ONLY:
        if requirement is not None:
            reasons.append("READ_ONLY_PRIOR_EVIDENCE_UNEXPECTED")
        if spec.allowed_effect_families:
            reasons.append("READ_ONLY_EFFECT_ALLOWLIST_MUST_BE_EMPTY")
    elif type(spec.effect_class) is OperatorEffectClass:
        if type(requirement) is not PriorEvidenceRequirement:
            reasons.append("MUTATION_PRIOR_EVIDENCE_REQUIRED")
        else:
            if not _valid_nonempty_string(requirement.producer_operation_id):
                reasons.append("PRIOR_PRODUCER_OPERATION_INVALID")
            if not _valid_nonempty_string(requirement.producer_step_id):
                reasons.append("PRIOR_PRODUCER_STEP_INVALID")
            if not _valid_digest(requirement.evidence_sha256):
                reasons.append("PRIOR_EVIDENCE_DIGEST_INVALID")
    return tuple(reasons)


def _attestation_reason_codes(
    spec: OperatorStepSpec,
    candidate_sha256: str,
    capability: object,
) -> tuple[OperatorGateStatus, tuple[str, ...]]:
    if not spec.require_parser_attestation:
        return OperatorGateStatus.UNCERTAIN, ("AST_ATTESTATION_REQUIRED_BY_POLICY",)
    authority = _active_authority()
    if authority is None:
        return OperatorGateStatus.UNCERTAIN, ("CONTROLLER_AUTHORITY_NOT_CONFIGURED",)
    if capability is None:
        return OperatorGateStatus.UNCERTAIN, ("AST_ATTESTATION_MISSING",)
    report = authority.ast_report_for(capability)
    if report is None:
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_UNAUTHENTICATED",)

    reasons: list[str] = []
    if report.runtime != WINDOWS_POWERSHELL_51:
        reasons.append("AST_RUNTIME_MISMATCH")
    if report.parser != WINDOWS_POWERSHELL_PARSER:
        reasons.append("AST_PARSER_IDENTITY_MISMATCH")
    if report.candidate_sha256 != candidate_sha256:
        reasons.append("AST_CANDIDATE_HASH_MISMATCH")
    if report.spec_sha256 != operator_step_spec_sha256(spec):
        reasons.append("AST_SPEC_HASH_MISMATCH")
    if not report.parsed or report.error_count != 0:
        reasons.append("AST_PARSE_FAILED")

    bindings = (
        ("AST_REPOSITORY_BINDING_MISMATCH", report.repository, spec.repository),
        ("AST_PR_BINDING_MISMATCH", report.pull_request_number, spec.pull_request_number),
        ("AST_SHA_BINDING_MISMATCH", report.target_sha, spec.target_sha),
        ("AST_HOST_ROLE_BINDING_MISMATCH", report.target_host_role, spec.target_host_role),
        ("AST_IDENTITY_BINDING_MISMATCH", report.required_identity, spec.required_identity),
        ("AST_EVIDENCE_ROOT_BINDING_MISMATCH", report.evidence_root, spec.evidence_root),
        ("AST_TRANSCRIPT_BINDING_MISMATCH", report.transcript_filename, spec.transcript_filename),
        ("AST_SUCCESS_MARKER_BINDING_MISMATCH", report.expected_success_marker, spec.expected_success_marker),
    )
    for reason, observed, expected in bindings:
        if observed != expected:
            reasons.append(reason)

    observed_effects = set(report.observed_effect_families)
    allowed_effects = set(spec.allowed_effect_families)
    if spec.effect_class is OperatorEffectClass.READ_ONLY:
        if observed_effects:
            reasons.append("AST_READ_ONLY_EFFECT_PRESENT")
    elif not observed_effects.issubset(allowed_effects):
        reasons.append("AST_EFFECT_NOT_ALLOWED")

    if report.automatic_variable_collisions:
        reasons.append("AST_AUTOMATIC_VARIABLE_COLLISION")
    if report.unresolved_placeholders:
        reasons.append("AST_UNRESOLVED_PLACEHOLDER")
    if report.forbidden_convenience_paths:
        reasons.append("AST_FORBIDDEN_CONVENIENCE_PATH")
    if report.self_declared_gate_authority:
        reasons.append("AST_SELF_DECLARED_GATE_AUTHORITY")
    if spec.require_heartbeat_or_progress and not report.heartbeat_or_progress_proven:
        reasons.append("AST_PROGRESS_PROOF_MISSING")
    if spec.require_child_exit_code and not report.child_exit_code_proven:
        reasons.append("AST_CHILD_EXIT_CODE_PROOF_MISSING")
    if spec.require_fail_fast and not report.fail_fast_proven:
        reasons.append("AST_FAIL_FAST_PROOF_MISSING")

    if reasons:
        return OperatorGateStatus.BLOCKED, tuple(reasons)
    return OperatorGateStatus.PASS_TO_OPERATOR, ()


def validate_operator_step(
    spec: OperatorStepSpec,
    candidate: str,
    *,
    ast_attestation: Optional[AuthenticatedAstAttestation] = None,
    prior_evidence_capability: Optional[PriorEvidenceCapability] = None,
) -> OperatorGateResult:
    """Validate a candidate without executing it or parsing PowerShell portably.

    PASS requires an AST/effect report authenticated by the configured trusted
    controller authority. Mutation steps also consume authenticated evidence
    produced for the required prior operation. No caller-supplied authority is
    accepted by this API.
    """

    candidate_sha256 = _candidate_sha256(candidate if type(candidate) is str else "")
    spec_reasons = _spec_reason_codes(spec)
    if spec_reasons:
        return OperatorGateResult(OperatorGateStatus.BLOCKED, spec_reasons, candidate_sha256)
    if type(candidate) is not str or not candidate.strip():
        return OperatorGateResult(OperatorGateStatus.BLOCKED, ("CANDIDATE_INVALID",), candidate_sha256)

    assert type(spec) is OperatorStepSpec
    status, reasons = _attestation_reason_codes(spec, candidate_sha256, ast_attestation)
    if status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return OperatorGateResult(status, reasons, candidate_sha256)

    if spec.effect_class is not OperatorEffectClass.READ_ONLY:
        authority = _active_authority()
        if authority is None:
            return OperatorGateResult(
                OperatorGateStatus.UNCERTAIN,
                ("CONTROLLER_AUTHORITY_NOT_CONFIGURED",),
                candidate_sha256,
            )
        claimed, reason = authority.claim_evidence(prior_evidence_capability, spec=spec)
        if not claimed:
            return OperatorGateResult(OperatorGateStatus.BLOCKED, (reason,), candidate_sha256)

    return OperatorGateResult(OperatorGateStatus.PASS_TO_OPERATOR, (), candidate_sha256)