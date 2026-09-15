from __future__ import annotations

import hashlib
import re
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
class PowerShellParserAttestation:
    runtime: str
    parser: str
    candidate_sha256: str
    parsed: bool
    error_count: int


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
    required_prior_evidence_marker: Optional[str]
    require_parser_attestation: bool
    require_heartbeat_or_progress: bool
    require_child_exit_code: bool
    require_fail_fast: bool


@dataclass(frozen=True, slots=True)
class OperatorGateResult:
    status: OperatorGateStatus
    reason_codes: tuple[str, ...]
    candidate_sha256: str

    @property
    def passed(self) -> bool:
        return self.status is OperatorGateStatus.PASS_TO_OPERATOR


_AUTOMATIC_VARIABLES = (
    "args",
    "input",
    "matches",
    "error",
    "home",
    "pid",
    "profile",
)

_UNRESOLVED_PLACEHOLDER_PATTERNS = (
    re.compile(r"\{\{[^{}]+\}\}"),
    re.compile(r"<[A-Z][A-Z0-9_ .:-]*>"),
    re.compile(r"\bTODO_PLACEHOLDER\b", re.IGNORECASE),
    re.compile(r"__[A-Z][A-Z0-9_]+__"),
)

_FORBIDDEN_CONVENIENCE_PATH_PATTERNS = (
    re.compile(r"%TEMP%", re.IGNORECASE),
    re.compile(r"\$env:TEMP\b", re.IGNORECASE),
    re.compile(r"\$env:TMP\b", re.IGNORECASE),
    re.compile(r"GetTempPath\s*\(", re.IGNORECASE),
    re.compile(r"\$PWD\b", re.IGNORECASE),
    re.compile(r"\bGet-Location\b", re.IGNORECASE),
)

_READ_ONLY_MUTATION_PATTERNS = (
    ("ACCOUNT_MUTATION", re.compile(r"\b(?:New|Remove|Enable|Disable|Set)-LocalUser\b", re.IGNORECASE)),
    ("GROUP_MUTATION", re.compile(r"\b(?:Add|Remove)-LocalGroupMember\b", re.IGNORECASE)),
    ("ACL_MUTATION", re.compile(r"\bSet-Acl\b|\bicacls(?:\.exe)?\b", re.IGNORECASE)),
    (
        "SERVICE_TASK_MUTATION",
        re.compile(
            r"\b(?:New|Set|Remove|Start|Stop|Restart)-Service\b|"
            r"\b(?:Register|Unregister|Set|Enable|Disable)-ScheduledTask\b|"
            r"\bschtasks(?:\.exe)?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "RUNNER_MUTATION",
        re.compile(
            r"(?:^|[\\/])config\.(?:cmd|sh)\b|"
            r"\bactions-runner\b|"
            r"\bremove-token\b|"
            r"\bregistration-token\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "WORKFLOW_MUTATION",
        re.compile(r"\bgh\s+(?:workflow\s+run|run\s+rerun)\b", re.IGNORECASE),
    ),
    (
        "GIT_DESTRUCTIVE_MUTATION",
        re.compile(
            r"\bgit\s+(?:push|clean\b|reset\s+--hard|branch\s+-D|tag\s+-d)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "FILESYSTEM_DESTRUCTIVE_MUTATION",
        re.compile(r"\b(?:Remove-Item|Clear-Content)\b", re.IGNORECASE),
    ),
    (
        "HTTP_API_MUTATION",
        re.compile(
            r"\b(?:Invoke-RestMethod|Invoke-WebRequest)\b[^\r\n]*\b-Method\s+(?:POST|PUT|PATCH|DELETE)\b|"
            r"\bcurl(?:\.exe)?\b[^\r\n]*\s-X\s*(?:POST|PUT|PATCH|DELETE)\b",
            re.IGNORECASE,
        ),
    ),
)


def _candidate_sha256(candidate: str) -> str:
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def _valid_nonempty_string(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _valid_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_filename(value: object) -> bool:
    if not _valid_nonempty_string(value):
        return False
    assert isinstance(value, str)
    return not any(separator in value for separator in ("/", "\\")) and value not in (".", "..")


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
    if type(spec.require_parser_attestation) is not bool:
        reasons.append("PARSER_REQUIREMENT_INVALID")
    if type(spec.require_heartbeat_or_progress) is not bool:
        reasons.append("PROGRESS_REQUIREMENT_INVALID")
    if type(spec.require_child_exit_code) is not bool:
        reasons.append("EXIT_CODE_REQUIREMENT_INVALID")
    if type(spec.require_fail_fast) is not bool:
        reasons.append("FAIL_FAST_REQUIREMENT_INVALID")

    if spec.required_prior_evidence_marker is not None and not _valid_nonempty_string(
        spec.required_prior_evidence_marker
    ):
        reasons.append("PRIOR_EVIDENCE_REQUIREMENT_INVALID")

    if type(spec.effect_class) is OperatorEffectClass:
        if spec.effect_class is OperatorEffectClass.READ_ONLY:
            if spec.required_prior_evidence_marker is not None:
                reasons.append("READ_ONLY_PRIOR_EVIDENCE_UNEXPECTED")
        elif spec.required_prior_evidence_marker is None:
            reasons.append("MUTATION_PRIOR_EVIDENCE_REQUIRED")

    return tuple(reasons)


def _binding_reason_codes(spec: OperatorStepSpec, candidate: str) -> tuple[str, ...]:
    reasons: list[str] = []
    required_literals = (
        ("REPOSITORY_BINDING_MISSING", spec.repository),
        ("PR_BINDING_MISSING", str(spec.pull_request_number)),
        ("SHA_BINDING_MISSING", spec.target_sha),
        ("HOST_ROLE_BINDING_MISSING", spec.target_host_role),
        ("IDENTITY_BINDING_MISSING", spec.required_identity),
        ("EVIDENCE_ROOT_BINDING_MISSING", spec.evidence_root),
        ("TRANSCRIPT_BINDING_MISSING", spec.transcript_filename),
        ("SUCCESS_MARKER_BINDING_MISSING", spec.expected_success_marker),
    )
    for reason, literal in required_literals:
        if literal not in candidate:
            reasons.append(reason)
    return tuple(reasons)


def _placeholder_reason_codes(candidate: str) -> tuple[str, ...]:
    if any(pattern.search(candidate) for pattern in _UNRESOLVED_PLACEHOLDER_PATTERNS):
        return ("UNRESOLVED_PLACEHOLDER",)
    return ()


def _convenience_path_reason_codes(candidate: str) -> tuple[str, ...]:
    if any(pattern.search(candidate) for pattern in _FORBIDDEN_CONVENIENCE_PATH_PATTERNS):
        return ("FORBIDDEN_CONVENIENCE_PATH",)
    return ()


def _automatic_variable_collision_reason_codes(candidate: str) -> tuple[str, ...]:
    reasons: list[str] = []
    names = "|".join(re.escape(name) for name in _AUTOMATIC_VARIABLES)
    assignment_pattern = re.compile(rf"(?im)^\s*\$(?P<name>{names})\s*=", re.IGNORECASE)
    parameter_blocks = re.finditer(r"(?is)\bparam\s*\((?P<body>.*?)\)", candidate)

    if assignment_pattern.search(candidate):
        reasons.append("POWERSHELL_AUTOMATIC_VARIABLE_ASSIGNMENT")

    parameter_name_pattern = re.compile(rf"\$(?:{names})\b", re.IGNORECASE)
    if any(parameter_name_pattern.search(match.group("body")) for match in parameter_blocks):
        reasons.append("POWERSHELL_AUTOMATIC_VARIABLE_PARAMETER")

    return tuple(reasons)


def _read_only_mutation_reason_codes(candidate: str) -> tuple[str, ...]:
    reasons: list[str] = []
    for reason, pattern in _READ_ONLY_MUTATION_PATTERNS:
        if pattern.search(candidate):
            reasons.append(reason)
    return tuple(reasons)


def _prior_evidence_reason_codes(
    spec: OperatorStepSpec,
    prior_evidence_marker: Optional[str],
) -> tuple[str, ...]:
    if spec.effect_class is OperatorEffectClass.READ_ONLY:
        return ()
    if type(prior_evidence_marker) is not str or not prior_evidence_marker:
        return ("PRIOR_EVIDENCE_MISSING",)
    if prior_evidence_marker != spec.required_prior_evidence_marker:
        return ("PRIOR_EVIDENCE_MISMATCH",)
    return ()


def _parser_attestation_result(
    spec: OperatorStepSpec,
    candidate_sha256: str,
    parser_attestation: Optional[PowerShellParserAttestation],
) -> tuple[OperatorGateStatus, tuple[str, ...]]:
    if not spec.require_parser_attestation:
        return OperatorGateStatus.PASS_TO_OPERATOR, ()
    if parser_attestation is None:
        return OperatorGateStatus.UNCERTAIN, ("PARSER_ATTESTATION_MISSING",)
    if type(parser_attestation) is not PowerShellParserAttestation:
        return OperatorGateStatus.BLOCKED, ("PARSER_ATTESTATION_TYPE_INVALID",)

    reasons: list[str] = []
    if parser_attestation.runtime != WINDOWS_POWERSHELL_51:
        reasons.append("PARSER_RUNTIME_MISMATCH")
    if parser_attestation.parser != WINDOWS_POWERSHELL_PARSER:
        reasons.append("PARSER_IDENTITY_MISMATCH")
    if parser_attestation.candidate_sha256 != candidate_sha256:
        reasons.append("PARSER_CANDIDATE_HASH_MISMATCH")
    if type(parser_attestation.parsed) is not bool or not parser_attestation.parsed:
        reasons.append("PARSER_PARSE_FAILED")
    if type(parser_attestation.error_count) is not int or parser_attestation.error_count != 0:
        reasons.append("PARSER_ERRORS_PRESENT")

    if reasons:
        return OperatorGateStatus.BLOCKED, tuple(reasons)
    return OperatorGateStatus.PASS_TO_OPERATOR, ()


def validate_operator_step(
    spec: OperatorStepSpec,
    candidate: str,
    *,
    parser_attestation: Optional[PowerShellParserAttestation] = None,
    prior_evidence_marker: Optional[str] = None,
) -> OperatorGateResult:
    """Validate a candidate operator script without executing it.

    The returned status is deterministic for the same frozen inputs. A PASS is
    authority to present the candidate to the human operator only; it is not
    authority to execute the command automatically and does not change ADR #90.
    """

    candidate_sha256 = _candidate_sha256(candidate if type(candidate) is str else "")
    spec_reasons = _spec_reason_codes(spec)
    if spec_reasons:
        return OperatorGateResult(
            status=OperatorGateStatus.BLOCKED,
            reason_codes=spec_reasons,
            candidate_sha256=candidate_sha256,
        )
    if type(candidate) is not str or not candidate.strip():
        return OperatorGateResult(
            status=OperatorGateStatus.BLOCKED,
            reason_codes=("CANDIDATE_INVALID",),
            candidate_sha256=candidate_sha256,
        )

    assert type(spec) is OperatorStepSpec
    reasons: list[str] = []
    reasons.extend(_binding_reason_codes(spec, candidate))
    reasons.extend(_placeholder_reason_codes(candidate))
    reasons.extend(_convenience_path_reason_codes(candidate))
    reasons.extend(_automatic_variable_collision_reason_codes(candidate))
    reasons.extend(_prior_evidence_reason_codes(spec, prior_evidence_marker))

    if "PASS_TO_OPERATOR" in candidate:
        reasons.append("SELF_DECLARED_GATE_AUTHORITY")

    if spec.effect_class is OperatorEffectClass.READ_ONLY:
        reasons.extend(_read_only_mutation_reason_codes(candidate))

    if reasons:
        return OperatorGateResult(
            status=OperatorGateStatus.BLOCKED,
            reason_codes=tuple(reasons),
            candidate_sha256=candidate_sha256,
        )

    parser_status, parser_reasons = _parser_attestation_result(
        spec,
        candidate_sha256,
        parser_attestation,
    )
    if parser_status is not OperatorGateStatus.PASS_TO_OPERATOR:
        return OperatorGateResult(
            status=parser_status,
            reason_codes=parser_reasons,
            candidate_sha256=candidate_sha256,
        )

    return OperatorGateResult(
        status=OperatorGateStatus.PASS_TO_OPERATOR,
        reason_codes=(),
        candidate_sha256=candidate_sha256,
    )
