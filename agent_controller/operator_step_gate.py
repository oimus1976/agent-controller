from __future__ import annotations

import hashlib
import json
import secrets
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
class PriorEvidenceCapability:
    token: str


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


class OperatorEvidenceAuthority:
    """Process-local one-time prior-evidence authority for this non-live slice.

    A later owner-machine bridge may replace this with durable authority. Callers
    only receive opaque capabilities; trusted bindings remain authority-owned.
    """

    __slots__ = ("_bindings", "_consumed")

    def __init__(self) -> None:
        self._bindings: dict[str, _EvidenceBinding] = {}
        self._consumed: set[str] = set()

    def issue(
        self,
        *,
        repository: str,
        pull_request_number: int,
        target_sha: str,
        producer_operation_id: str,
        producer_step_id: str,
        evidence_sha256: str,
    ) -> PriorEvidenceCapability:
        values = (
            repository,
            target_sha,
            producer_operation_id,
            producer_step_id,
            evidence_sha256,
        )
        if not all(_valid_nonempty_string(value) for value in values):
            raise ValueError("invalid evidence binding")
        if type(pull_request_number) is not int or pull_request_number <= 0:
            raise ValueError("invalid evidence PR number")
        if not _valid_sha(target_sha) or not _valid_digest(evidence_sha256):
            raise ValueError("invalid evidence digest binding")
        token = secrets.token_hex(32)
        self._bindings[token] = _EvidenceBinding(
            repository=repository,
            pull_request_number=pull_request_number,
            target_sha=target_sha,
            producer_operation_id=producer_operation_id,
            producer_step_id=producer_step_id,
            evidence_sha256=evidence_sha256,
        )
        return PriorEvidenceCapability(token=token)

    def claim(
        self,
        capability: object,
        *,
        spec: OperatorStepSpec,
    ) -> tuple[bool, str]:
        if type(capability) is not PriorEvidenceCapability:
            return False, "PRIOR_EVIDENCE_CAPABILITY_TYPE_INVALID"
        if type(capability.token) is not str or not _valid_digest(capability.token):
            return False, "PRIOR_EVIDENCE_CAPABILITY_INVALID"
        token = capability.token
        if token in self._consumed:
            return False, "PRIOR_EVIDENCE_ALREADY_CONSUMED"
        binding = self._bindings.get(token)
        if binding is None:
            return False, "PRIOR_EVIDENCE_UNKNOWN"
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
        if binding != expected:
            return False, "PRIOR_EVIDENCE_BINDING_MISMATCH"
        self._consumed.add(token)
        return True, ""


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
    payload = json.dumps(_spec_payload(spec), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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
    if spec.evidence_root != AUTHORITATIVE_EVIDENCE_ROOT:
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
    attestation: object,
) -> tuple[OperatorGateStatus, tuple[str, ...]]:
    if not spec.require_parser_attestation:
        return OperatorGateStatus.UNCERTAIN, ("AST_ATTESTATION_REQUIRED_BY_POLICY",)
    if attestation is None:
        return OperatorGateStatus.UNCERTAIN, ("AST_ATTESTATION_MISSING",)
    if type(attestation) is not PowerShellAstAttestation:
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_TYPE_INVALID",)

    string_fields = (
        attestation.runtime,
        attestation.parser,
        attestation.candidate_sha256,
        attestation.spec_sha256,
        attestation.repository,
        attestation.target_sha,
        attestation.target_host_role,
        attestation.required_identity,
        attestation.evidence_root,
        attestation.transcript_filename,
        attestation.expected_success_marker,
    )
    if not all(type(value) is str for value in string_fields):
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_FIELD_TYPE_INVALID",)
    if not _valid_digest(attestation.candidate_sha256) or not _valid_digest(attestation.spec_sha256):
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_DIGEST_INVALID",)
    if type(attestation.pull_request_number) is not int or attestation.pull_request_number <= 0:
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_PR_INVALID",)
    if type(attestation.parsed) is not bool or type(attestation.error_count) is not int:
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_PARSE_FIELD_INVALID",)
    tuple_fields = (
        attestation.observed_effect_families,
        attestation.automatic_variable_collisions,
        attestation.unresolved_placeholders,
        attestation.forbidden_convenience_paths,
    )
    if not all(_valid_plain_string_tuple(value) for value in tuple_fields):
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_COLLECTION_INVALID",)
    bool_fields = (
        attestation.self_declared_gate_authority,
        attestation.heartbeat_or_progress_proven,
        attestation.child_exit_code_proven,
        attestation.fail_fast_proven,
    )
    if not all(type(value) is bool for value in bool_fields):
        return OperatorGateStatus.BLOCKED, ("AST_ATTESTATION_BOOL_INVALID",)

    reasons: list[str] = []
    if attestation.runtime != WINDOWS_POWERSHELL_51:
        reasons.append("AST_RUNTIME_MISMATCH")
    if attestation.parser != WINDOWS_POWERSHELL_PARSER:
        reasons.append("AST_PARSER_IDENTITY_MISMATCH")
    if attestation.candidate_sha256 != candidate_sha256:
        reasons.append("AST_CANDIDATE_HASH_MISMATCH")
    if attestation.spec_sha256 != operator_step_spec_sha256(spec):
        reasons.append("AST_SPEC_HASH_MISMATCH")
    if not attestation.parsed or attestation.error_count != 0:
        reasons.append("AST_PARSE_FAILED")

    bindings = (
        ("AST_REPOSITORY_BINDING_MISMATCH", attestation.repository, spec.repository),
        ("AST_PR_BINDING_MISMATCH", attestation.pull_request_number, spec.pull_request_number),
        ("AST_SHA_BINDING_MISMATCH", attestation.target_sha, spec.target_sha),
        ("AST_HOST_ROLE_BINDING_MISMATCH", attestation.target_host_role, spec.target_host_role),
        ("AST_IDENTITY_BINDING_MISMATCH", attestation.required_identity, spec.required_identity),
        ("AST_EVIDENCE_ROOT_BINDING_MISMATCH", attestation.evidence_root, spec.evidence_root),
        ("AST_TRANSCRIPT_BINDING_MISMATCH", attestation.transcript_filename, spec.transcript_filename),
        ("AST_SUCCESS_MARKER_BINDING_MISMATCH", attestation.expected_success_marker, spec.expected_success_marker),
    )
    for reason, observed, expected in bindings:
        if observed != expected:
            reasons.append(reason)

    observed_effects = set(attestation.observed_effect_families)
    allowed_effects = set(spec.allowed_effect_families)
    if spec.effect_class is OperatorEffectClass.READ_ONLY:
        if observed_effects:
            reasons.append("AST_READ_ONLY_EFFECT_PRESENT")
    elif not observed_effects.issubset(allowed_effects):
        reasons.append("AST_EFFECT_NOT_ALLOWED")

    if attestation.automatic_variable_collisions:
        reasons.append("AST_AUTOMATIC_VARIABLE_COLLISION")
    if attestation.unresolved_placeholders:
        reasons.append("AST_UNRESOLVED_PLACEHOLDER")
    if attestation.forbidden_convenience_paths:
        reasons.append("AST_FORBIDDEN_CONVENIENCE_PATH")
    if attestation.self_declared_gate_authority:
        reasons.append("AST_SELF_DECLARED_GATE_AUTHORITY")
    if spec.require_heartbeat_or_progress and not attestation.heartbeat_or_progress_proven:
        reasons.append("AST_PROGRESS_PROOF_MISSING")
    if spec.require_child_exit_code and not attestation.child_exit_code_proven:
        reasons.append("AST_CHILD_EXIT_CODE_PROOF_MISSING")
    if spec.require_fail_fast and not attestation.fail_fast_proven:
        reasons.append("AST_FAIL_FAST_PROOF_MISSING")

    if reasons:
        return OperatorGateStatus.BLOCKED, tuple(reasons)
    return OperatorGateStatus.PASS_TO_OPERATOR, ()


def validate_operator_step(
    spec: OperatorStepSpec,
    candidate: str,
    *,
    ast_attestation: Optional[PowerShellAstAttestation] = None,
    prior_evidence_authority: Optional[OperatorEvidenceAuthority] = None,
    prior_evidence_capability: Optional[PriorEvidenceCapability] = None,
) -> OperatorGateResult:
    """Validate an operator candidate without executing it.

    The portable validator never claims to parse PowerShell. PASS requires a
    trusted Windows PowerShell AST/effect attestation bound to the exact
    candidate and frozen spec. Mutating steps additionally consume a one-time
    authority-owned prior-evidence capability.
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
        if type(prior_evidence_authority) is not OperatorEvidenceAuthority:
            return OperatorGateResult(
                OperatorGateStatus.BLOCKED,
                ("PRIOR_EVIDENCE_AUTHORITY_INVALID",),
                candidate_sha256,
            )
        claimed, reason = prior_evidence_authority.claim(prior_evidence_capability, spec=spec)
        if not claimed:
            return OperatorGateResult(OperatorGateStatus.BLOCKED, (reason,), candidate_sha256)

    return OperatorGateResult(OperatorGateStatus.PASS_TO_OPERATOR, (), candidate_sha256)
