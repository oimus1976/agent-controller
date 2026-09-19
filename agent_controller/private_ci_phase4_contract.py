from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath, PureWindowsPath

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    OperatorEffectClass,
    OperatorStepSpec,
    PriorEvidenceRequirement,
)


@dataclass(frozen=True, slots=True)
class PrivateCiPilotBinding:
    """Immutable cross-phase identity for one private-CI pilot attempt.

    This object carries identity only. It does not itself prove that any phase
    passed and it carries no mutation authority or reusable credential.
    """

    repository: str
    pull_request_number: int
    target_sha: str
    workflow_sha: str
    workflow_path: str
    runner_id: int
    runner_name: str
    runner_label: str
    environment_generation: str
    runner_root: str
    work_folder: str
    host: str
    broker_identity: str
    target_identity: str


def _plain_nonempty(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _full_lower_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _workflow_path_valid(value: object) -> bool:
    if not _plain_nonempty(value):
        return False
    assert type(value) is str
    if "\\" in value:
        return False
    path = PurePosixPath(value)
    parts = path.parts
    return (
        not path.is_absolute()
        and ".." not in parts
        and len(parts) >= 3
        and parts[:2] == (".github", "workflows")
        and path.suffix in (".yml", ".yaml")
        and str(path) == value
    )


def _windows_root_valid(value: object) -> bool:
    if not _plain_nonempty(value):
        return False
    assert type(value) is str
    path = PureWindowsPath(value)
    return path.is_absolute() and ".." not in path.parts


def _work_folder_valid(value: object) -> bool:
    if not _plain_nonempty(value):
        return False
    assert type(value) is str
    return (
        value not in (".", "..")
        and "/" not in value
        and "\\" not in value
    )


def pilot_binding_reason_codes(binding: object) -> tuple[str, ...]:
    if type(binding) is not PrivateCiPilotBinding:
        return ("PILOT_BINDING_TYPE_INVALID",)

    reasons: list[str] = []

    if (
        not _plain_nonempty(binding.repository)
        or binding.repository.count("/") != 1
        or any(not part for part in binding.repository.split("/"))
    ):
        reasons.append("PILOT_BINDING_REPOSITORY_INVALID")
    if (
        type(binding.pull_request_number) is not int
        or binding.pull_request_number <= 0
    ):
        reasons.append("PILOT_BINDING_PR_NUMBER_INVALID")
    if not _full_lower_sha(binding.target_sha):
        reasons.append("PILOT_BINDING_TARGET_SHA_INVALID")
    if not _full_lower_sha(binding.workflow_sha):
        reasons.append("PILOT_BINDING_WORKFLOW_SHA_INVALID")
    if not _workflow_path_valid(binding.workflow_path):
        reasons.append("PILOT_BINDING_WORKFLOW_PATH_INVALID")
    if type(binding.runner_id) is not int or binding.runner_id <= 0:
        reasons.append("PILOT_BINDING_RUNNER_ID_INVALID")
    if not _plain_nonempty(binding.runner_name):
        reasons.append("PILOT_BINDING_RUNNER_NAME_INVALID")
    if not _plain_nonempty(binding.runner_label):
        reasons.append("PILOT_BINDING_RUNNER_LABEL_INVALID")
    if not _plain_nonempty(binding.environment_generation):
        reasons.append("PILOT_BINDING_ENVIRONMENT_GENERATION_INVALID")
    if not _windows_root_valid(binding.runner_root):
        reasons.append("PILOT_BINDING_RUNNER_ROOT_INVALID")
    if not _work_folder_valid(binding.work_folder):
        reasons.append("PILOT_BINDING_WORK_FOLDER_INVALID")
    if not _plain_nonempty(binding.host):
        reasons.append("PILOT_BINDING_HOST_INVALID")
    if not _plain_nonempty(binding.broker_identity):
        reasons.append("PILOT_BINDING_BROKER_IDENTITY_INVALID")
    if not _plain_nonempty(binding.target_identity):
        reasons.append("PILOT_BINDING_TARGET_IDENTITY_INVALID")
    if (
        _plain_nonempty(binding.broker_identity)
        and _plain_nonempty(binding.target_identity)
        and binding.broker_identity.casefold() == binding.target_identity.casefold()
    ):
        reasons.append("PILOT_BINDING_IDENTITY_SEPARATION_INVALID")

    return tuple(reasons)


REGISTRATION_HANDOFF_SCHEMA = "agent-controller.private-ci-registration-handoff.v1"


@dataclass(frozen=True, slots=True)
class RegistrationHandoffEvidence:
    """Canonical secret-free digest bridge from registration to Phase 4.

    This is evidence, not authority. Phase 4 must authenticate and durably
    consume the exact handoff before any live effect is authorized.
    """

    schema: str
    binding: PrivateCiPilotBinding
    phase0_evidence_sha256: str
    registration_plan_sha256: str
    human_approval_sha256: str
    registration_consumption_sha256: str
    registration_result_sha256: str
    local_runner_settings_sha256: str
    registration_status: str


def _sha256_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def registration_handoff_reason_codes(
    evidence: object,
) -> tuple[str, ...]:
    if type(evidence) is not RegistrationHandoffEvidence:
        return ("REGISTRATION_HANDOFF_TYPE_INVALID",)

    reasons: list[str] = []
    if evidence.schema != REGISTRATION_HANDOFF_SCHEMA:
        reasons.append("REGISTRATION_HANDOFF_SCHEMA_INVALID")
    binding_reasons = pilot_binding_reason_codes(evidence.binding)
    reasons.extend(
        f"REGISTRATION_HANDOFF_{reason}"
        for reason in binding_reasons
    )

    digest_fields = (
        (
            "REGISTRATION_HANDOFF_PHASE0_SHA256_INVALID",
            evidence.phase0_evidence_sha256,
        ),
        (
            "REGISTRATION_HANDOFF_PLAN_SHA256_INVALID",
            evidence.registration_plan_sha256,
        ),
        (
            "REGISTRATION_HANDOFF_APPROVAL_SHA256_INVALID",
            evidence.human_approval_sha256,
        ),
        (
            "REGISTRATION_HANDOFF_CONSUMPTION_SHA256_INVALID",
            evidence.registration_consumption_sha256,
        ),
        (
            "REGISTRATION_HANDOFF_RESULT_SHA256_INVALID",
            evidence.registration_result_sha256,
        ),
        (
            "REGISTRATION_HANDOFF_LOCAL_SETTINGS_SHA256_INVALID",
            evidence.local_runner_settings_sha256,
        ),
    )
    for reason, value in digest_fields:
        if not _sha256_digest(value):
            reasons.append(reason)

    if evidence.registration_status != "REGISTERED":
        reasons.append("REGISTRATION_HANDOFF_STATUS_NOT_REGISTERED")

    return tuple(reasons)


def _registration_handoff_payload(
    evidence: RegistrationHandoffEvidence,
) -> dict[str, object]:
    return {
        "schema": evidence.schema,
        "binding": asdict(evidence.binding),
        "phase0_evidence_sha256": evidence.phase0_evidence_sha256,
        "registration_plan_sha256": evidence.registration_plan_sha256,
        "human_approval_sha256": evidence.human_approval_sha256,
        "registration_consumption_sha256": evidence.registration_consumption_sha256,
        "registration_result_sha256": evidence.registration_result_sha256,
        "local_runner_settings_sha256": evidence.local_runner_settings_sha256,
        "registration_status": evidence.registration_status,
    }


def registration_handoff_bytes(
    evidence: RegistrationHandoffEvidence,
) -> bytes:
    reasons = registration_handoff_reason_codes(evidence)
    if reasons:
        raise ValueError(
            "registration handoff invalid: " + ",".join(reasons)
        )
    return (
        json.dumps(
            _registration_handoff_payload(evidence),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_registration_handoff_bytes(
    raw: bytes,
) -> RegistrationHandoffEvidence:
    if type(raw) is not bytes:
        raise ValueError("registration handoff must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("registration handoff JSON invalid") from error

    required = {
        "schema",
        "binding",
        "phase0_evidence_sha256",
        "registration_plan_sha256",
        "human_approval_sha256",
        "registration_consumption_sha256",
        "registration_result_sha256",
        "local_runner_settings_sha256",
        "registration_status",
    }
    if type(payload) is not dict or set(payload) != required:
        raise ValueError("registration handoff shape invalid")
    binding_payload = payload.get("binding")
    if type(binding_payload) is not dict:
        raise ValueError("registration handoff binding invalid")
    expected_binding_fields = set(PrivateCiPilotBinding.__dataclass_fields__)
    if set(binding_payload) != expected_binding_fields:
        raise ValueError("registration handoff binding shape invalid")

    try:
        binding = PrivateCiPilotBinding(**binding_payload)
        evidence = RegistrationHandoffEvidence(
            schema=payload["schema"],
            binding=binding,
            phase0_evidence_sha256=payload["phase0_evidence_sha256"],
            registration_plan_sha256=payload["registration_plan_sha256"],
            human_approval_sha256=payload["human_approval_sha256"],
            registration_consumption_sha256=payload[
                "registration_consumption_sha256"
            ],
            registration_result_sha256=payload["registration_result_sha256"],
            local_runner_settings_sha256=payload[
                "local_runner_settings_sha256"
            ],
            registration_status=payload["registration_status"],
        )
    except TypeError as error:
        raise ValueError("registration handoff field types invalid") from error

    canonical = registration_handoff_bytes(evidence)
    if raw != canonical:
        raise ValueError("registration handoff is not canonical")
    return evidence


PHASE4_OPERATION_ID = "issue225-phase4-target-environment"
PHASE4_STEP_ID = "prepare-target-environment"
PHASE4_HOST_ROLE = "private-ci-owner-machine"
PHASE4_BROKER_IDENTITY = "c-admin"
PHASE4_TRANSCRIPT_FILENAME = "issue225-phase4-target-environment.log"
PHASE4_SUCCESS_MARKER = "PHASE4_TARGET_ENVIRONMENT_PASS"
PHASE4_EFFECTS = ("PRIVATE_CI_PHASE4_TARGET_ENVIRONMENT",)
REGISTRATION_HANDOFF_OPERATION_ID = "issue225-registration-handoff"
REGISTRATION_HANDOFF_STEP_ID = "registration-handoff"


def build_phase4_target_environment_spec(
    binding: PrivateCiPilotBinding,
    *,
    registration_handoff_sha256: str,
) -> OperatorStepSpec:
    binding_reasons = pilot_binding_reason_codes(binding)
    if binding_reasons:
        raise ValueError(
            "pilot binding invalid: " + ",".join(binding_reasons)
        )
    if not _sha256_digest(registration_handoff_sha256):
        raise ValueError("registration handoff SHA-256 invalid")

    return OperatorStepSpec(
        operation_id=PHASE4_OPERATION_ID,
        step_id=PHASE4_STEP_ID,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        target_host_role=PHASE4_HOST_ROLE,
        required_identity=PHASE4_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=PHASE4_TRANSCRIPT_FILENAME,
        expected_success_marker=PHASE4_SUCCESS_MARKER,
        allowed_effect_families=PHASE4_EFFECTS,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id=REGISTRATION_HANDOFF_OPERATION_ID,
            producer_step_id=REGISTRATION_HANDOFF_STEP_ID,
            evidence_sha256=registration_handoff_sha256,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=True,
        require_fail_fast=True,
    )
