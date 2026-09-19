from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath, PureWindowsPath

from agent_controller.operator_step_gate import (
    AUTHORITATIVE_EVIDENCE_ROOT,
    PRIVATE_LOCAL_CI_WORKSTREAM,
    WINDOWS_POWERSHELL_51,
    AuthenticatedAstAttestation,
    OperatorEffectClass,
    OperatorGateResult,
    OperatorGateStatus,
    OperatorStepSpec,
    PriorEvidenceRequirement,
    _attestation_reason_codes,
    _candidate_sha256,
    _spec_reason_codes,
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
    controller_main_sha: str
    controller_tree: str
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
    if not _full_lower_sha(binding.controller_main_sha):
        reasons.append("PILOT_BINDING_CONTROLLER_MAIN_SHA_INVALID")
    if not _windows_root_valid(binding.controller_tree):
        reasons.append("PILOT_BINDING_CONTROLLER_TREE_INVALID")
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
PHASE4_EFFECTS = (
    "ACL_MUTATION",
    "FILESYSTEM_WRITE_MUTATION",
    "PROCESS_CONTROL",
    "PROCESS_LAUNCH",
)
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


PHASE4_TARGET_PROBE_FILENAME = "Invoke-PrivateCiPhase4TargetProbe.ps1"
PHASE4_TARGET_PROBE_COPY_FILENAME = "issue225-phase4-target-probe.ps1"
PHASE4_TARGET_PROBE_RESULT_FILENAME = "issue225-phase4-target-probe-result.json"
PHASE4_TARGET_PROBE_STDOUT_FILENAME = "issue225-phase4-target-probe-stdout.log"
PHASE4_TARGET_PROBE_STDERR_FILENAME = "issue225-phase4-target-probe-stderr.log"
PHASE4_AUTHORITY_ROOT = r"C:\ProgramData\agent-controller-private-ci-authority"
PHASE4_TARGET_TIMEOUT_SECONDS = 60
PHASE4_HEARTBEAT_SECONDS = 5
PHASE4_TRUSTED_GH_PATH = r"C:\Program Files\GitHub CLI\gh.exe"


def _ps_single_quoted(value: str) -> str:
    if type(value) is not str:
        raise ValueError("PowerShell literal must be string")
    return "'" + value.replace("'", "''") + "'"


def _phase4_registration_marker_path(handoff: RegistrationHandoffEvidence) -> str:
    return str(
        PureWindowsPath(PHASE4_AUTHORITY_ROOT)
        / (
            "issue217-live-registration-"
            + handoff.registration_plan_sha256
            + ".consumed.json"
        )
    )


def render_phase4_target_environment_candidate(
    binding: PrivateCiPilotBinding,
    handoff: RegistrationHandoffEvidence,
    *,
    target_probe_sha256: str,
) -> str:
    binding_reasons = pilot_binding_reason_codes(binding)
    if binding_reasons:
        raise ValueError("pilot binding invalid: " + ",".join(binding_reasons))
    handoff_reasons = registration_handoff_reason_codes(handoff)
    if handoff_reasons:
        raise ValueError(
            "registration handoff invalid: " + ",".join(handoff_reasons)
        )
    if handoff.binding != binding:
        raise ValueError("registration handoff binding mismatch")
    if not _sha256_digest(target_probe_sha256):
        raise ValueError("target probe SHA-256 invalid")

    source_probe = str(
        PureWindowsPath(binding.controller_tree)
        / "scripts"
        / PHASE4_TARGET_PROBE_FILENAME
    )
    copied_probe = str(
        PureWindowsPath(binding.runner_root)
        / PHASE4_TARGET_PROBE_COPY_FILENAME
    )
    probe_result = str(
        PureWindowsPath(binding.runner_root)
        / PHASE4_TARGET_PROBE_RESULT_FILENAME
    )
    probe_stdout = str(
        PureWindowsPath(binding.runner_root)
        / PHASE4_TARGET_PROBE_STDOUT_FILENAME
    )
    probe_stderr = str(
        PureWindowsPath(binding.runner_root)
        / PHASE4_TARGET_PROBE_STDERR_FILENAME
    )
    work_path = str(PureWindowsPath(binding.runner_root) / binding.work_folder)
    marker_path = _phase4_registration_marker_path(handoff)
    qualified_target = f"{binding.host}\\{binding.target_identity}"

    lines = [
        f"$BridgeRepository = {_ps_single_quoted(binding.repository)}",
        f"$BridgePullRequestNumber = {binding.pull_request_number}",
        f"$BridgeTargetSha = {_ps_single_quoted(binding.target_sha)}",
        f"$BridgeTargetHostRole = {_ps_single_quoted(PHASE4_HOST_ROLE)}",
        f"$BridgeRequiredIdentity = {_ps_single_quoted(PHASE4_BROKER_IDENTITY)}",
        f"$BridgeEvidenceRoot = {_ps_single_quoted(AUTHORITATIVE_EVIDENCE_ROOT)}",
        f"$BridgeTranscriptFilename = {_ps_single_quoted(PHASE4_TRANSCRIPT_FILENAME)}",
        f"$BridgeExpectedSuccessMarker = {_ps_single_quoted(PHASE4_SUCCESS_MARKER)}",
        f"$BridgeControllerMainSha = {_ps_single_quoted(binding.controller_main_sha)}",
        f"$BridgeControllerTree = {_ps_single_quoted(binding.controller_tree)}",
        f"$BridgeWorkflowSha = {_ps_single_quoted(binding.workflow_sha)}",
        f"$BridgeWorkflowPath = {_ps_single_quoted(binding.workflow_path)}",
        f"$BridgeRunnerId = {binding.runner_id}",
        f"$BridgeRunnerName = {_ps_single_quoted(binding.runner_name)}",
        f"$BridgeRunnerLabel = {_ps_single_quoted(binding.runner_label)}",
        f"$BridgeEnvironmentGeneration = {_ps_single_quoted(binding.environment_generation)}",
        f"$BridgeRunnerRoot = {_ps_single_quoted(binding.runner_root)}",
        f"$BridgeWorkFolder = {_ps_single_quoted(binding.work_folder)}",
        f"$BridgeWorkPath = {_ps_single_quoted(work_path)}",
        f"$BridgeHost = {_ps_single_quoted(binding.host)}",
        f"$BridgeBrokerIdentity = {_ps_single_quoted(binding.broker_identity)}",
        f"$BridgeTargetIdentity = {_ps_single_quoted(binding.target_identity)}",
        f"$BridgeQualifiedTargetIdentity = {_ps_single_quoted(qualified_target)}",
        f"$BridgeRegistrationPlanSha = {_ps_single_quoted(handoff.registration_plan_sha256)}",
        f"$BridgeRegistrationMarkerPath = {_ps_single_quoted(marker_path)}",
        f"$BridgeTargetProbeSource = {_ps_single_quoted(source_probe)}",
        f"$BridgeTargetProbePath = {_ps_single_quoted(copied_probe)}",
        f"$BridgeTargetProbeSha256 = {_ps_single_quoted(target_probe_sha256)}",
        f"$BridgeTargetProbeResultPath = {_ps_single_quoted(probe_result)}",
        f"$BridgeTargetProbeStdoutPath = {_ps_single_quoted(probe_stdout)}",
        f"$BridgeTargetProbeStderrPath = {_ps_single_quoted(probe_stderr)}",
        f"$BridgeTrustedGhPath = {_ps_single_quoted(PHASE4_TRUSTED_GH_PATH)}",
        f"$BridgeTargetTimeoutSeconds = {PHASE4_TARGET_TIMEOUT_SECONDS}",
        f"$BridgeHeartbeatSeconds = {PHASE4_HEARTBEAT_SECONDS}",
        "$ErrorActionPreference = 'Stop'",
        "",
        "$BridgeObservedHost = hostname.exe",
        "if ($BridgeObservedHost -ine $BridgeHost) { throw 'Phase 4 host mismatch' }",
        "$BridgeObservedIdentity = whoami.exe",
        "if ($BridgeObservedIdentity -ine $BridgeBrokerIdentity) { throw 'Phase 4 broker identity mismatch' }",
        "",
        "$BridgeTargetUser = Get-LocalUser -Name $BridgeTargetIdentity -ErrorAction Stop",
        "if (-not $BridgeTargetUser.Enabled) { throw 'Phase 4 target identity is disabled' }",
        "$BridgeTargetSid = $BridgeTargetUser.SID.Value",
        "$BridgeAdminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)",
        "if ($null -ne ($BridgeAdminMembers | Where-Object { $_.SID.Value -eq $BridgeTargetSid })) {",
        "    throw 'Phase 4 target identity is local admin'",
        "}",
        "",
        "if (-not (Test-Path -LiteralPath $BridgeRunnerRoot -PathType Container)) { throw 'Phase 4 runner root missing' }",
        "if (Test-Path -LiteralPath $BridgeWorkPath) { throw 'Phase 4 prior workspace exists' }",
        "foreach ($BridgeFreshPath in @($BridgeTargetProbePath, $BridgeTargetProbeResultPath, $BridgeTargetProbeStdoutPath, $BridgeTargetProbeStderrPath)) {",
        "    if (Test-Path -LiteralPath $BridgeFreshPath) { throw 'Phase 4 generated path already exists' }",
        "}",
        "if (-not (Test-Path -LiteralPath $BridgeRegistrationMarkerPath -PathType Leaf)) { throw 'Phase 4 registration marker missing' }",
        "",
        "$BridgePendingPaths = @($BridgeRunnerRoot)",
        "while ($BridgePendingPaths.Count -gt 0) {",
        "    $BridgeCurrentPath = $BridgePendingPaths[0]",
        "    if ($BridgePendingPaths.Count -eq 1) { $BridgePendingPaths = @() }",
        "    else { $BridgePendingPaths = @($BridgePendingPaths[1..($BridgePendingPaths.Count - 1)]) }",
        "    $BridgeCurrentItem = Get-Item -LiteralPath $BridgeCurrentPath -Force -ErrorAction Stop",
        "    if (($BridgeCurrentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Phase 4 reparse point blocked' }",
        "    if ($BridgeCurrentItem.PSIsContainer) {",
        "        foreach ($BridgeChildItem in @(Get-ChildItem -LiteralPath $BridgeCurrentPath -Force -ErrorAction Stop)) {",
        "            if (($BridgeChildItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Phase 4 child reparse point blocked' }",
        "            if ($BridgeChildItem.PSIsContainer) { $BridgePendingPaths += $BridgeChildItem.FullName }",
        "        }",
        "    }",
        "}",
        "",
        "$BridgeRunnerProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -match 'Runner|actions' })",
        "if ($BridgeRunnerProcesses.Count -ne 0) { throw 'Phase 4 stale runner process detected' }",
        "$BridgeRunnerServices = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -match 'runner|actions' -or $_.DisplayName -match 'runner|actions' })",
        "if ($BridgeRunnerServices.Count -ne 0) { throw 'Phase 4 stale runner service detected' }",
        "$BridgeRunnerTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -match 'runner|actions' -or $_.TaskPath -match 'runner|actions' })",
        "if ($BridgeRunnerTasks.Count -ne 0) { throw 'Phase 4 stale runner task detected' }",
        "",
        "$BridgeSourceProbeHash = (Get-FileHash -LiteralPath $BridgeTargetProbeSource -Algorithm SHA256).Hash",
        "if ($BridgeSourceProbeHash -ine $BridgeTargetProbeSha256) { throw 'Phase 4 target probe source hash mismatch' }",
        "Copy-Item -LiteralPath $BridgeTargetProbeSource -Destination $BridgeTargetProbePath -ErrorAction Stop",
        "$BridgeCopiedProbeHash = (Get-FileHash -LiteralPath $BridgeTargetProbePath -Algorithm SHA256).Hash",
        "if ($BridgeCopiedProbeHash -ine $BridgeTargetProbeSha256) { throw 'Phase 4 copied target probe hash mismatch' }",
        "",
        "icacls.exe $BridgeRunnerRoot /inheritance:r /grant:r ('*' + $BridgeTargetSid + ':(OI)(CI)(M)') /T /C | Write-Host",
        "$BridgeAclExitCode = $LASTEXITCODE",
        "if ($BridgeAclExitCode -ne 0) { throw 'Phase 4 runner-root ACL preparation failed' }",
        "",
        "$BridgeTargetCredential = Get-Credential -UserName $BridgeQualifiedTargetIdentity -Message 'Enter the local ac-runner credential for the reviewed Phase 4 plan.'",
        "if ($null -eq $BridgeTargetCredential) { throw 'Phase 4 target credential was not supplied' }",
        "if ($BridgeTargetCredential.UserName -ine $BridgeQualifiedTargetIdentity) { throw 'Phase 4 target credential identity mismatch' }",
        "",
        "$BridgeStartedAt = Get-Date",
        "$BridgeChild = Start-Process -FilePath 'powershell.exe' -ArgumentList @(",
        "    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',",
        "    '-File', $BridgeTargetProbePath,",
        "    '-ExpectedHost', $BridgeHost,",
        "    '-ExpectedIdentity', $BridgeQualifiedTargetIdentity,",
        "    '-AuthorityMarkerPath', $BridgeRegistrationMarkerPath,",
        "    '-ResultPath', $BridgeTargetProbeResultPath,",
        "    '-TrustedGhPath', $BridgeTrustedGhPath",
        ") -Credential $BridgeTargetCredential -LoadUserProfile -WorkingDirectory $BridgeRunnerRoot -RedirectStandardOutput $BridgeTargetProbeStdoutPath -RedirectStandardError $BridgeTargetProbeStderrPath -PassThru",
        "while (-not $BridgeChild.HasExited) {",
        "    $BridgeElapsedSeconds = [int]((Get-Date) - $BridgeStartedAt).TotalSeconds",
        '    Write-Host ("heartbeat phase=phase4 elapsed_seconds={0}" -f $BridgeElapsedSeconds)',
        "    if ($BridgeElapsedSeconds -ge $BridgeTargetTimeoutSeconds) {",
        "        Stop-Process -Id $BridgeChild.Id -Force -ErrorAction Stop",
        "        throw 'Phase 4 target probe timeout'",
        "    }",
        "    Start-Sleep -Seconds 5",
        "}",
        "$BridgeChildExitCode = $BridgeChild.ExitCode",
        "if ($BridgeChildExitCode -ne 0) { throw 'Phase 4 target probe failed' }",
        "",
        "if (-not (Test-Path -LiteralPath $BridgeTargetProbeResultPath -PathType Leaf)) { throw 'Phase 4 target probe result missing' }",
        "$BridgeProbeResult = Get-Content -LiteralPath $BridgeTargetProbeResultPath -Raw -Encoding UTF8 | ConvertFrom-Json",
        "if ($BridgeProbeResult.schema -cne 'agent-controller.private-ci-phase4-target-probe.v1') { throw 'Phase 4 target probe schema mismatch' }",
        "if ($BridgeProbeResult.status -cne 'TARGET_PROBE_PASS') { throw 'Phase 4 target probe did not pass' }",
        "if ($BridgeProbeResult.host -ine $BridgeHost) { throw 'Phase 4 target probe host mismatch' }",
        "if ($BridgeProbeResult.identity -ine $BridgeQualifiedTargetIdentity) { throw 'Phase 4 target probe identity mismatch' }",
        "if ($BridgeProbeResult.admin_sid_present -ne $false) { throw 'Phase 4 target probe admin status unsafe' }",
        "if ($BridgeProbeResult.high_integrity_present -ne $false) { throw 'Phase 4 target probe integrity unsafe' }",
        "if ($BridgeProbeResult.forbidden_environment_count -ne 0) { throw 'Phase 4 target probe environment unsafe' }",
        "if ($BridgeProbeResult.broker_credential_roots_readable -ne 0) { throw 'Phase 4 broker credential isolation failed' }",
        "if ($BridgeProbeResult.gh_authenticated -ne $false) { throw 'Phase 4 target gh authentication isolation failed' }",
        "if ($BridgeProbeResult.authority_marker_write_denied -ne $true) { throw 'Phase 4 durable authority isolation failed' }",
        "",
        "Write-Output 'PHASE4_TARGET_ENVIRONMENT_PASS'",
        "",
    ]
    return "\n".join(lines)



def phase4_target_probe_sha256(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise ValueError("target probe must be exact bytes")
    return hashlib.sha256(raw).hexdigest()


def plan_phase4_target_environment(
    *,
    registration_handoff_bytes: bytes,
    target_probe_bytes: bytes,
    candidate: str,
    ast_attestation: AuthenticatedAstAttestation | None,
) -> OperatorGateResult:
    candidate_sha = _candidate_sha256(
        candidate if type(candidate) is str else ""
    )
    try:
        handoff = parse_registration_handoff_bytes(
            registration_handoff_bytes
        )
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        return OperatorGateResult(
            OperatorGateStatus.BLOCKED,
            ("REGISTRATION_HANDOFF_INVALID",),
            candidate_sha,
        )

    try:
        probe_sha = phase4_target_probe_sha256(target_probe_bytes)
    except ValueError:
        return OperatorGateResult(
            OperatorGateStatus.BLOCKED,
            ("PHASE4_TARGET_PROBE_BYTES_INVALID",),
            candidate_sha,
        )

    expected = render_phase4_target_environment_candidate(
        handoff.binding,
        handoff,
        target_probe_sha256=probe_sha,
    )
    handoff_sha = hashlib.sha256(registration_handoff_bytes).hexdigest()
    spec = build_phase4_target_environment_spec(
        handoff.binding,
        registration_handoff_sha256=handoff_sha,
    )

    reasons: list[str] = []
    if type(candidate) is not str or candidate != expected:
        reasons.append("PHASE4_CANDIDATE_NOT_CANONICAL")
    reasons.extend(_spec_reason_codes(spec))
    if reasons:
        return OperatorGateResult(
            OperatorGateStatus.BLOCKED,
            tuple(reasons),
            candidate_sha,
        )

    status, attestation_reasons = _attestation_reason_codes(
        spec,
        candidate_sha,
        ast_attestation,
    )
    return OperatorGateResult(
        status,
        attestation_reasons,
        candidate_sha,
    )
