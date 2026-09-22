from __future__ import annotations

import hashlib
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
from agent_controller.private_ci_phase4_contract import (
    PrivateCiPilotBinding,
    pilot_binding_reason_codes,
)
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_STATUS,
    parse_phase5_result_bytes,
)


PHASE6_CLEANUP_PLAN_SCHEMA = "agent-controller.private-ci-phase6-cleanup-plan.v1"
PHASE6_OPERATION_ID = "issue230-phase6-cleanup"
PHASE6_STEP_ID = "cleanup-fresh-pilot"
PHASE6_HOST_ROLE = "private-ci-owner-machine"
PHASE6_BROKER_IDENTITY = "c-admin"
PHASE6_TRANSCRIPT_FILENAME = "issue230-phase6-cleanup.log"
PHASE6_SUCCESS_MARKER = "PHASE6_CLEANUP_PASS"
PHASE6_EFFECTS = (
    "ACL_MUTATION",
    "GENERATION_RETIREMENT",
    "HTTP_API_ACCESS",
    "PROCESS_CONTROL",
    "RUNNER_DEREGISTRATION",
)
PHASE5_RESULT_PRODUCER_OPERATION_ID = "issue225-phase5-exactly-one-job"
PHASE5_RESULT_PRODUCER_STEP_ID = "run-exactly-one-job"
PHASE6_PRIVATE_CI_ROOT = r"C:\ProgramData\agent-controller\private-ci"
GITHUB_API_VERSION = "2026-03-10"


@dataclass(frozen=True, slots=True)
class Phase6CleanupPlan:
    schema: str
    phase5_result_sha256: str
    binding: PrivateCiPilotBinding
    runner_id: int
    runner_name: str
    runner_label: str
    runner_process_id: int
    environment_generation: str
    generation_root: str
    runner_root: str
    work_folder: str
    workspace_root: str
    require_zero_services: bool
    require_zero_tasks: bool


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _canonical_paths(
    binding: PrivateCiPilotBinding,
) -> tuple[str, str, str]:
    generation_root = str(
        PureWindowsPath(PHASE6_PRIVATE_CI_ROOT)
        / binding.environment_generation
    )
    runner_root = str(PureWindowsPath(generation_root) / "runner")
    workspace_root = str(
        PureWindowsPath(runner_root) / binding.work_folder
    )
    return generation_root, runner_root, workspace_root


def _reason_codes(plan: object) -> tuple[str, ...]:
    if type(plan) is not Phase6CleanupPlan:
        return ("PHASE6_PLAN_TYPE_INVALID",)

    reasons: list[str] = []
    if plan.schema != PHASE6_CLEANUP_PLAN_SCHEMA:
        reasons.append("PHASE6_PLAN_SCHEMA_INVALID")
    for reason in pilot_binding_reason_codes(plan.binding):
        reasons.append("PHASE6_PLAN_" + reason)
    if not _digest(plan.phase5_result_sha256):
        reasons.append("PHASE6_PLAN_PHASE5_SHA_INVALID")

    expected_generation, expected_runner, expected_workspace = _canonical_paths(
        plan.binding
    )
    exact = (
        ("RUNNER_ID", plan.runner_id, plan.binding.runner_id),
        ("RUNNER_NAME", plan.runner_name, plan.binding.runner_name),
        ("RUNNER_LABEL", plan.runner_label, plan.binding.runner_label),
        (
            "ENVIRONMENT_GENERATION",
            plan.environment_generation,
            plan.binding.environment_generation,
        ),
        ("GENERATION_ROOT", plan.generation_root, expected_generation),
        ("RUNNER_ROOT", plan.runner_root, expected_runner),
        ("BINDING_RUNNER_ROOT", plan.binding.runner_root, expected_runner),
        ("WORK_FOLDER", plan.work_folder, plan.binding.work_folder),
        ("WORKSPACE_ROOT", plan.workspace_root, expected_workspace),
    )
    for label, observed, expected in exact:
        if observed != expected:
            reasons.append("PHASE6_PLAN_" + label + "_MISMATCH")

    if not _positive_int(plan.runner_process_id):
        reasons.append("PHASE6_PLAN_RUNNER_PROCESS_ID_INVALID")
    if plan.require_zero_services is not True:
        reasons.append("PHASE6_PLAN_SERVICES_POLICY_INVALID")
    if plan.require_zero_tasks is not True:
        reasons.append("PHASE6_PLAN_TASKS_POLICY_INVALID")
    return tuple(reasons)


def build_phase6_cleanup_plan(phase5_result_bytes: bytes) -> Phase6CleanupPlan:
    evidence = parse_phase5_result_bytes(phase5_result_bytes)
    if evidence.status != PHASE5_RESULT_STATUS:
        raise ValueError("Phase 5 result status invalid for cleanup plan")

    binding = evidence.binding
    generation_root, runner_root, workspace_root = _canonical_paths(binding)
    if binding.runner_root != runner_root:
        raise ValueError("Phase 5 binding runner root is not canonical")

    return Phase6CleanupPlan(
        schema=PHASE6_CLEANUP_PLAN_SCHEMA,
        phase5_result_sha256=hashlib.sha256(phase5_result_bytes).hexdigest(),
        binding=binding,
        runner_id=binding.runner_id,
        runner_name=binding.runner_name,
        runner_label=binding.runner_label,
        runner_process_id=evidence.runner_process_id,
        environment_generation=binding.environment_generation,
        generation_root=generation_root,
        runner_root=runner_root,
        work_folder=binding.work_folder,
        workspace_root=workspace_root,
        require_zero_services=True,
        require_zero_tasks=True,
    )


def phase6_cleanup_plan_bytes(plan: Phase6CleanupPlan) -> bytes:
    reasons = _reason_codes(plan)
    if reasons:
        raise ValueError("Phase 6 cleanup plan invalid: " + ",".join(reasons))
    return (
        json.dumps(
            asdict(plan),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def parse_phase6_cleanup_plan_bytes(raw: bytes) -> Phase6CleanupPlan:
    if type(raw) is not bytes:
        raise ValueError("Phase 6 cleanup plan must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Phase 6 cleanup plan JSON invalid") from error

    expected = set(Phase6CleanupPlan.__dataclass_fields__)
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError("Phase 6 cleanup plan shape invalid")

    binding_payload = payload.get("binding")
    if (
        type(binding_payload) is not dict
        or set(binding_payload) != set(PrivateCiPilotBinding.__dataclass_fields__)
    ):
        raise ValueError("Phase 6 cleanup plan binding shape invalid")

    try:
        plan = Phase6CleanupPlan(
            schema=payload["schema"],
            phase5_result_sha256=payload["phase5_result_sha256"],
            binding=PrivateCiPilotBinding(**binding_payload),
            runner_id=payload["runner_id"],
            runner_name=payload["runner_name"],
            runner_label=payload["runner_label"],
            runner_process_id=payload["runner_process_id"],
            environment_generation=payload["environment_generation"],
            generation_root=payload["generation_root"],
            runner_root=payload["runner_root"],
            work_folder=payload["work_folder"],
            workspace_root=payload["workspace_root"],
            require_zero_services=payload["require_zero_services"],
            require_zero_tasks=payload["require_zero_tasks"],
        )
    except TypeError as error:
        raise ValueError("Phase 6 cleanup plan fields invalid") from error

    if raw != phase6_cleanup_plan_bytes(plan):
        raise ValueError("Phase 6 cleanup plan is not canonical")
    return plan


def build_phase6_cleanup_operator_spec(
    plan: Phase6CleanupPlan,
    *,
    phase6_plan_sha256: str,
) -> OperatorStepSpec:
    reasons = _reason_codes(plan)
    if reasons:
        raise ValueError("Phase 6 cleanup plan invalid: " + ",".join(reasons))
    if not _digest(phase6_plan_sha256):
        raise ValueError("Phase 6 plan SHA-256 invalid")

    return OperatorStepSpec(
        operation_id=PHASE6_OPERATION_ID,
        step_id=PHASE6_STEP_ID,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=plan.binding.repository,
        pull_request_number=plan.binding.pull_request_number,
        target_sha=plan.binding.target_sha,
        target_host_role=PHASE6_HOST_ROLE,
        required_identity=PHASE6_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=PHASE6_TRANSCRIPT_FILENAME,
        expected_success_marker=PHASE6_SUCCESS_MARKER,
        allowed_effect_families=PHASE6_EFFECTS,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id=PHASE5_RESULT_PRODUCER_OPERATION_ID,
            producer_step_id=PHASE5_RESULT_PRODUCER_STEP_ID,
            evidence_sha256=plan.phase5_result_sha256,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=False,
        require_child_exit_code=False,
        require_fail_fast=True,
    )


def _ps_single_quoted(value: str) -> str:
    if type(value) is not str:
        raise ValueError("PowerShell literal must be string")
    return "'" + value.replace("'", "''") + "'"


def render_phase6_cleanup_candidate(plan: Phase6CleanupPlan) -> str:
    reasons = _reason_codes(plan)
    if reasons:
        raise ValueError("Phase 6 cleanup plan invalid: " + ",".join(reasons))

    binding = plan.binding
    workflow_filename = PurePosixPath(binding.workflow_path).name
    api_header = "X-GitHub-Api-Version: " + GITHUB_API_VERSION
    runners_endpoint = (
        f"repos/{binding.repository}/actions/runners?per_page=100"
    )
    runner_delete_endpoint = (
        f"repos/{binding.repository}/actions/runners/{plan.runner_id}"
    )
    pr_endpoint = (
        f"repos/{binding.repository}/pulls/{binding.pull_request_number}"
    )
    main_ref_endpoint = f"repos/{binding.repository}/git/ref/heads/main"
    active_statuses = (
        "queued",
        "in_progress",
        "requested",
        "waiting",
        "pending",
    )
    active_endpoints = {
        status: (
            f"repos/{binding.repository}/actions/workflows/"
            f"{workflow_filename}/runs"
            f"?event=workflow_dispatch&branch=main&status={status}&per_page=100"
        )
        for status in active_statuses
    }
    qualified_target = f"{binding.host}\\{binding.target_identity}"
    generation_retirement_helper = str(
        PureWindowsPath(binding.controller_tree)
        / "scripts"
        / "retire_private_ci_generation.py"
    )

    def gh_read(endpoint: str) -> str:
        return (
            "gh.exe api "
            f"-H {_ps_single_quoted(api_header)} "
            f"{_ps_single_quoted(endpoint)}"
        )

    lines = [
        f"$BridgeRepository = {_ps_single_quoted(binding.repository)}",
        f"$BridgePullRequestNumber = {binding.pull_request_number}",
        f"$BridgeTargetSha = {_ps_single_quoted(binding.target_sha)}",
        f"$BridgeTargetHostRole = {_ps_single_quoted(PHASE6_HOST_ROLE)}",
        f"$BridgeRequiredIdentity = {_ps_single_quoted(PHASE6_BROKER_IDENTITY)}",
        f"$BridgeEvidenceRoot = {_ps_single_quoted(AUTHORITATIVE_EVIDENCE_ROOT)}",
        f"$BridgeTranscriptFilename = {_ps_single_quoted(PHASE6_TRANSCRIPT_FILENAME)}",
        f"$BridgeExpectedSuccessMarker = {_ps_single_quoted(PHASE6_SUCCESS_MARKER)}",
        f"$BridgeControllerMainSha = {_ps_single_quoted(binding.controller_main_sha)}",
        f"$BridgeWorkflowSha = {_ps_single_quoted(binding.workflow_sha)}",
        f"$BridgeWorkflowPath = {_ps_single_quoted(binding.workflow_path)}",
        f"$BridgeRunnerId = {plan.runner_id}",
        f"$BridgeRunnerName = {_ps_single_quoted(plan.runner_name)}",
        f"$BridgeRunnerLabel = {_ps_single_quoted(plan.runner_label)}",
        f"$BridgeRunnerProcessId = {plan.runner_process_id}",
        f"$BridgeEnvironmentGeneration = {_ps_single_quoted(plan.environment_generation)}",
        f"$BridgeGenerationRoot = {_ps_single_quoted(plan.generation_root)}",
        f"$BridgeRunnerRoot = {_ps_single_quoted(plan.runner_root)}",
        f"$BridgeWorkspaceRoot = {_ps_single_quoted(plan.workspace_root)}",
        f"$BridgeWorkFolder = {_ps_single_quoted(plan.work_folder)}",
        f"$BridgeHost = {_ps_single_quoted(binding.host)}",
        f"$BridgeBrokerIdentity = {_ps_single_quoted(binding.broker_identity)}",
        f"$BridgeTargetIdentity = {_ps_single_quoted(binding.target_identity)}",
        f"$BridgeQualifiedTargetIdentity = {_ps_single_quoted(qualified_target)}",
        "$ErrorActionPreference = 'Stop'",
        "",
        "function Invoke-PrivateCiGenerationRetirement {",
        "    $BridgeRetirementOutput = python.exe "
        + _ps_single_quoted(generation_retirement_helper)
        + " --generation-root $BridgeGenerationRoot --expected-generation $BridgeEnvironmentGeneration",
        "    $BridgeRetirementExitCode = $LASTEXITCODE",
        "    if ($BridgeRetirementExitCode -ne 0) { throw 'Phase 6 generation retirement helper failed; do not retry' }",
        "    if (@($BridgeRetirementOutput) -notcontains 'PHASE6_GENERATION_RETIREMENT_IDENTITY_BOUND') { throw 'Phase 6 generation retirement proof missing' }",
        "}",
        "",
        "Write-Host 'progress phase=phase6 step=identity-readback'",
        "$BridgeObservedHost = hostname.exe",
        "if ($BridgeObservedHost -ine $BridgeHost) { throw 'Phase 6 host mismatch' }",
        "$BridgeObservedIdentity = whoami.exe",
        "if ($BridgeObservedIdentity -ine $BridgeBrokerIdentity) { throw 'Phase 6 broker identity mismatch' }",
        "",
        "Write-Host 'progress phase=phase6 step=target-readback'",
        f"$BridgePrJson = {gh_read(pr_endpoint)}",
        "$BridgePrReadExitCode = $LASTEXITCODE",
        "if ($BridgePrReadExitCode -ne 0) { throw 'Phase 6 target PR readback failed' }",
        "$BridgePr = $BridgePrJson | ConvertFrom-Json",
        "if ($BridgePr.state -cne 'open' -or $BridgePr.draft -ne $true -or $BridgePr.head.sha -cne $BridgeTargetSha -or $BridgePr.head.repo.full_name -cne $BridgeRepository -or $BridgePr.base.ref -cne 'main') { throw 'Phase 6 target PR binding drift' }",
        f"$BridgeMainRefJson = {gh_read(main_ref_endpoint)}",
        "$BridgeMainRefReadExitCode = $LASTEXITCODE",
        "if ($BridgeMainRefReadExitCode -ne 0) { throw 'Phase 6 trusted workflow ref readback failed' }",
        "$BridgeMainRef = $BridgeMainRefJson | ConvertFrom-Json",
        "if ($BridgeMainRef.object.sha -cne $BridgeWorkflowSha) { throw 'Phase 6 trusted workflow SHA drift' }",
        "",
    ]

    for status in active_statuses:
        variable = {
            "queued": "Queued",
            "in_progress": "InProgress",
            "requested": "Requested",
            "waiting": "Waiting",
            "pending": "Pending",
        }[status]
        lines.extend(
            [
                f"$BridgeActive{variable}Json = {gh_read(active_endpoints[status])}",
                f"$BridgeActive{variable}ExitCode = $LASTEXITCODE",
                f"if ($BridgeActive{variable}ExitCode -ne 0) {{ throw 'Phase 6 active workflow readback failed' }}",
                f"$BridgeActive{variable} = $BridgeActive{variable}Json | ConvertFrom-Json",
                f"if ($null -eq $BridgeActive{variable}.total_count -or [int]$BridgeActive{variable}.total_count -ne 0) {{ throw 'Phase 6 active workflow residual blocks cleanup' }}",
            ]
        )

    lines.extend(
        [
            "",
            "Write-Host 'progress phase=phase6 step=runner-readback'",
            f"$BridgeRunnerReadJson = {gh_read(runners_endpoint)}",
            "$BridgeRunnerReadExitCode = $LASTEXITCODE",
            "if ($BridgeRunnerReadExitCode -ne 0) { throw 'Phase 6 runner readback failed' }",
            "$BridgeRunnerRead = $BridgeRunnerReadJson | ConvertFrom-Json",
            "if ($null -eq $BridgeRunnerRead.total_count -or $null -eq $BridgeRunnerRead.runners) { throw 'Phase 6 runner readback shape invalid' }",
            "$BridgeRunnerItems = @($BridgeRunnerRead.runners)",
            "if ([int]$BridgeRunnerRead.total_count -gt $BridgeRunnerItems.Count) { throw 'Phase 6 runner readback incomplete' }",
            "$BridgeEligibleRunners = @($BridgeRunnerItems | Where-Object {",
            "    $BridgeObservedLabels = @($_.labels.name)",
            "    $_.id -eq $BridgeRunnerId -or",
            "    $_.name -eq $BridgeRunnerName -or",
            "    $BridgeObservedLabels -contains $BridgeRunnerLabel",
            "})",
            "if ($BridgeEligibleRunners.Count -gt 1) { throw 'Phase 6 ambiguous runner identity' }",
            "if ($BridgeEligibleRunners.Count -eq 0) { throw 'Phase 6 runner absent without exact prior cleanup evidence' }",
            "$BridgeRemoteRunnerPresent = $false",
            "if ($BridgeEligibleRunners.Count -eq 1) {",
            "    $BridgeRemoteRunner = $BridgeEligibleRunners[0]",
            "    $BridgeRemoteLabels = @($BridgeRemoteRunner.labels.name)",
            "    if ([long]$BridgeRemoteRunner.id -ne $BridgeRunnerId -or $BridgeRemoteRunner.name -cne $BridgeRunnerName -or $BridgeRemoteLabels -notcontains $BridgeRunnerLabel) { throw 'Phase 6 runner identity drift' }",
            "    if ([bool]$BridgeRemoteRunner.busy) { throw 'Phase 6 runner remains busy' }",
            "    $BridgeRemoteRunnerPresent = $true",
            "}",
            "",
            "Write-Host 'progress phase=phase6 step=local-preflight'",
            "if (-not (Test-Path -LiteralPath $BridgeGenerationRoot -PathType Container)) { throw 'Phase 6 generation root missing' }",
            "if (-not (Test-Path -LiteralPath $BridgeRunnerRoot -PathType Container)) { throw 'Phase 6 runner root missing' }",
            "$BridgeGenerationItem = Get-Item -LiteralPath $BridgeGenerationRoot -Force -ErrorAction Stop",
            "if (($BridgeGenerationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Phase 6 generation root reparse point blocked' }",
            "$BridgeRunnerItem = Get-Item -LiteralPath $BridgeRunnerRoot -Force -ErrorAction Stop",
            "if (($BridgeRunnerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Phase 6 runner root reparse point blocked' }",
            "$BridgeAllProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop)",
            "$BridgeGenerationProcesses = @($BridgeAllProcesses | Where-Object {",
            "    ($null -ne $_.CommandLine -and $_.CommandLine -like ('*' + $BridgeGenerationRoot + '*')) -or",
            "    ($null -ne $_.ExecutablePath -and $_.ExecutablePath -like ('*' + $BridgeGenerationRoot + '*'))",
            "})",
            "if ($BridgeGenerationProcesses.Count -gt 1) { throw 'Phase 6 unexpected generation-bound process' }",
            "if ($BridgeGenerationProcesses.Count -eq 1 -and [long]$BridgeGenerationProcesses[0].ProcessId -ne $BridgeRunnerProcessId) { throw 'Phase 6 unexpected generation-bound process' }",
            "$BridgeTargetOwnedProcesses = @()",
            "foreach ($BridgeObservedProcess in $BridgeAllProcesses) {",
            "    $BridgeObservedOwner = Invoke-CimMethod -InputObject $BridgeObservedProcess -MethodName GetOwner",
            "    if ($BridgeObservedOwner.ReturnValue -eq 0) {",
            "        $BridgeObservedQualifiedOwner = $BridgeObservedOwner.Domain + '\\' + $BridgeObservedOwner.User",
            "        if ($BridgeObservedQualifiedOwner -ieq $BridgeQualifiedTargetIdentity) { $BridgeTargetOwnedProcesses += $BridgeObservedProcess }",
            "    }",
            "}",
            "$BridgeUnexpectedTargetProcesses = @($BridgeTargetOwnedProcesses | Where-Object { [long]$_.ProcessId -ne $BridgeRunnerProcessId })",
            "if ($BridgeUnexpectedTargetProcesses.Count -ne 0) { throw 'Phase 6 unexpected target-owned process' }",
            "$BridgeRunnerProcessPresent = @($BridgeTargetOwnedProcesses | Where-Object { [long]$_.ProcessId -eq $BridgeRunnerProcessId }).Count -eq 1",
            "",
            "$BridgeGenerationServices = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $null -ne $_.PathName -and $_.PathName -like ('*' + $BridgeGenerationRoot + '*') })",
            "if ($BridgeGenerationServices.Count -ne 0) { throw 'Phase 6 unexpected generation-bound service' }",
            "$BridgeGenerationTasks = @()",
            "foreach ($BridgeScheduledTask in @(Get-ScheduledTask -ErrorAction Stop)) {",
            "    foreach ($BridgeTaskAction in @($BridgeScheduledTask.Actions)) {",
            "        if (([string]$BridgeTaskAction.Execute -like ('*' + $BridgeGenerationRoot + '*')) -or ([string]$BridgeTaskAction.Arguments -like ('*' + $BridgeGenerationRoot + '*'))) {",
            "            $BridgeGenerationTasks += $BridgeScheduledTask",
            "            break",
            "        }",
            "    }",
            "}",
            "if ($BridgeGenerationTasks.Count -ne 0) { throw 'Phase 6 unexpected generation-bound scheduled task' }",
            "",
            "Write-Host 'progress phase=phase6 step=acl-lock'",
            "icacls.exe $BridgeGenerationRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' /T /C",
            "$BridgeGenerationAclGrantExitCode = $LASTEXITCODE",
            "if ($BridgeGenerationAclGrantExitCode -ne 0) { throw 'Phase 6 generation-root ACL lock failed' }",
            "icacls.exe $BridgeGenerationRoot /remove:g $BridgeQualifiedTargetIdentity /T /C",
            "$BridgeGenerationAclRemoveExitCode = $LASTEXITCODE",
            "if ($BridgeGenerationAclRemoveExitCode -ne 0) { throw 'Phase 6 generation target ACL removal failed' }",
            "icacls.exe $BridgeRunnerRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'",
            "$BridgeAclRootGrantExitCode = $LASTEXITCODE",
            "if ($BridgeAclRootGrantExitCode -ne 0) { throw 'Phase 6 runner-root ACL lock failed' }",
            "icacls.exe $BridgeRunnerRoot /remove:g $BridgeQualifiedTargetIdentity",
            "$BridgeAclRootRemoveExitCode = $LASTEXITCODE",
            "if ($BridgeAclRootRemoveExitCode -ne 0) { throw 'Phase 6 target ACL removal failed' }",
            "",
            "if ($BridgeRunnerProcessPresent) {",
            "    Write-Host 'progress phase=phase6 step=stop-runner'",
            "    Stop-Process -Id $BridgeRunnerProcessId -Force -ErrorAction Stop",
            "}",
            "$BridgeProcessesAfterStop = @(Get-CimInstance Win32_Process -ErrorAction Stop)",
            "$BridgeGenerationProcessesAfterStop = @($BridgeProcessesAfterStop | Where-Object {",
            "    ($null -ne $_.CommandLine -and $_.CommandLine -like ('*' + $BridgeGenerationRoot + '*')) -or",
            "    ($null -ne $_.ExecutablePath -and $_.ExecutablePath -like ('*' + $BridgeGenerationRoot + '*'))",
            "})",
            "if ($BridgeGenerationProcessesAfterStop.Count -ne 0) { throw 'Phase 6 generation-bound process remains after stop' }",
            "$BridgeTargetOwnedAfterStop = @()",
            "foreach ($BridgeObservedProcessAfterStop in $BridgeProcessesAfterStop) {",
            "    $BridgeObservedOwnerAfterStop = Invoke-CimMethod -InputObject $BridgeObservedProcessAfterStop -MethodName GetOwner",
            "    if ($BridgeObservedOwnerAfterStop.ReturnValue -eq 0) {",
            "        $BridgeObservedQualifiedOwnerAfterStop = $BridgeObservedOwnerAfterStop.Domain + '\\' + $BridgeObservedOwnerAfterStop.User",
            "        if ($BridgeObservedQualifiedOwnerAfterStop -ieq $BridgeQualifiedTargetIdentity) { $BridgeTargetOwnedAfterStop += $BridgeObservedProcessAfterStop }",
            "    }",
            "}",
            "if ($BridgeTargetOwnedAfterStop.Count -ne 0) { throw 'Phase 6 target-owned process remains after stop' }",
            "",
            "Write-Host 'progress phase=phase6 step=reparse-scan'",
            "$BridgePendingPaths = @($BridgeGenerationRoot)",
            "while ($BridgePendingPaths.Count -gt 0) {",
            "    $BridgeCurrentPath = $BridgePendingPaths[0]",
            "    if ($BridgePendingPaths.Count -eq 1) { $BridgePendingPaths = @() }",
            "    else { $BridgePendingPaths = @($BridgePendingPaths[1..($BridgePendingPaths.Count - 1)]) }",
            "    $BridgeCurrentItem = Get-Item -LiteralPath $BridgeCurrentPath -Force -ErrorAction Stop",
            "    if (($BridgeCurrentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Phase 6 reparse point blocked before delete' }",
            "    if ($BridgeCurrentItem.PSIsContainer) {",
            "        foreach ($BridgeChildItem in @(Get-ChildItem -LiteralPath $BridgeCurrentPath -Force -ErrorAction Stop)) {",
            "            if (($BridgeChildItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Phase 6 reparse point blocked before delete' }",
            "            if ($BridgeChildItem.PSIsContainer) { $BridgePendingPaths += $BridgeChildItem.FullName }",
            "        }",
            "    }",
            "}",
            "icacls.exe $BridgeRunnerRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' /T /C",
            "$BridgeAclTreeGrantExitCode = $LASTEXITCODE",
            "if ($BridgeAclTreeGrantExitCode -ne 0) { throw 'Phase 6 recursive ACL lock failed' }",
            "icacls.exe $BridgeRunnerRoot /remove:g $BridgeQualifiedTargetIdentity /T /C",
            "$BridgeAclTreeRemoveExitCode = $LASTEXITCODE",
            "if ($BridgeAclTreeRemoveExitCode -ne 0) { throw 'Phase 6 recursive target ACL removal failed' }",
            "",
            "if ($BridgeRemoteRunnerPresent) {",
            "    Write-Host 'progress phase=phase6 step=deregister-runner'",
            "    gh.exe api --method DELETE "
            + f"-H {_ps_single_quoted(api_header)} "
            + f"{_ps_single_quoted(runner_delete_endpoint)}",
            "    $BridgeRunnerDeleteExitCode = $LASTEXITCODE",
            "    if ($BridgeRunnerDeleteExitCode -ne 0) { throw 'Phase 6 runner deregistration failed; do not retry' }",
            "}",
            "",
            "Write-Host 'progress phase=phase6 step=retire-generation'",
            "Invoke-PrivateCiGenerationRetirement",
            "if (Test-Path -LiteralPath $BridgeGenerationRoot) { throw 'Phase 6 generation removal failed' }",
            "",
            "Write-Host 'progress phase=phase6 step=post-readback'",
            f"$BridgeRunnerPostJson = {gh_read(runners_endpoint)}",
            "$BridgeRunnerPostExitCode = $LASTEXITCODE",
            "if ($BridgeRunnerPostExitCode -ne 0) { throw 'Phase 6 post-cleanup runner readback failed' }",
            "$BridgeRunnerPost = $BridgeRunnerPostJson | ConvertFrom-Json",
            "if ($null -eq $BridgeRunnerPost.total_count -or $null -eq $BridgeRunnerPost.runners) { throw 'Phase 6 post-cleanup runner readback shape invalid' }",
            "$BridgeRunnerPostItems = @($BridgeRunnerPost.runners)",
            "if ([int]$BridgeRunnerPost.total_count -gt $BridgeRunnerPostItems.Count) { throw 'Phase 6 post-cleanup runner readback incomplete' }",
            "$BridgeRunnerPostMatches = @($BridgeRunnerPostItems | Where-Object {",
            "    $BridgePostLabels = @($_.labels.name)",
            "    $_.id -eq $BridgeRunnerId -or",
            "    $_.name -eq $BridgeRunnerName -or",
            "    $BridgePostLabels -contains $BridgeRunnerLabel",
            "})",
            "if ($BridgeRunnerPostMatches.Count -ne 0) { throw 'Phase 6 runner residual after deregistration' }",
            "",
            "Write-Output 'PHASE6_CLEANUP_PASS'",
            "",
        ]
    )
    return "\n".join(lines)
