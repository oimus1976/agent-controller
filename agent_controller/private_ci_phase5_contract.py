from __future__ import annotations

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


PHASE5_OPERATION_ID = "issue225-phase5-exactly-one-job"
PHASE5_STEP_ID = "run-exactly-one-job"
PHASE5_HOST_ROLE = "private-ci-owner-machine"
PHASE5_BROKER_IDENTITY = "c-admin"
PHASE5_TRANSCRIPT_FILENAME = "issue225-phase5-exactly-one-job.log"
PHASE5_SUCCESS_MARKER = "PHASE5_EXACTLY_ONE_JOB_ATTEMPT_COMPLETE"
PHASE5_EFFECTS = (
    "PROCESS_CONTROL",
    "PROCESS_LAUNCH",
    "WORKFLOW_DISPATCH",
)
PHASE5_RUNNER_STDOUT_FILENAME = "issue225-phase5-runner-stdout.log"
PHASE5_RUNNER_STDERR_FILENAME = "issue225-phase5-runner-stderr.log"
PHASE5_HEARTBEAT_SECONDS = 5
PHASE5_RUNNER_TIMEOUT_SECONDS = 660
PHASE4_RESULT_PRODUCER_OPERATION_ID = "issue225-phase4-target-environment"
PHASE4_RESULT_PRODUCER_STEP_ID = "prepare-target-environment"
GITHUB_API_VERSION = "2026-03-10"


def _digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _ps_single_quoted(value: str) -> str:
    if type(value) is not str:
        raise ValueError("PowerShell literal must be string")
    return "'" + value.replace("'", "''") + "'"


def build_phase5_exactly_one_job_spec(
    binding: PrivateCiPilotBinding,
    *,
    phase4_result_sha256: str,
) -> OperatorStepSpec:
    binding_reasons = pilot_binding_reason_codes(binding)
    if binding_reasons:
        raise ValueError(
            "pilot binding invalid: " + ",".join(binding_reasons)
        )
    if not _digest(phase4_result_sha256):
        raise ValueError("Phase 4 result SHA-256 invalid")

    return OperatorStepSpec(
        operation_id=PHASE5_OPERATION_ID,
        step_id=PHASE5_STEP_ID,
        workstream=PRIVATE_LOCAL_CI_WORKSTREAM,
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        target_host_role=PHASE5_HOST_ROLE,
        required_identity=PHASE5_BROKER_IDENTITY,
        shell_runtime=WINDOWS_POWERSHELL_51,
        effect_class=OperatorEffectClass.BOUNDED_MUTATION,
        evidence_root=AUTHORITATIVE_EVIDENCE_ROOT,
        transcript_filename=PHASE5_TRANSCRIPT_FILENAME,
        expected_success_marker=PHASE5_SUCCESS_MARKER,
        allowed_effect_families=PHASE5_EFFECTS,
        prior_evidence_requirement=PriorEvidenceRequirement(
            producer_operation_id=PHASE4_RESULT_PRODUCER_OPERATION_ID,
            producer_step_id=PHASE4_RESULT_PRODUCER_STEP_ID,
            evidence_sha256=phase4_result_sha256,
        ),
        require_parser_attestation=True,
        require_heartbeat_or_progress=True,
        require_child_exit_code=True,
        require_fail_fast=True,
    )


def render_phase5_exactly_one_job_candidate(
    binding: PrivateCiPilotBinding,
    *,
    phase4_result_sha256: str,
) -> str:
    binding_reasons = pilot_binding_reason_codes(binding)
    if binding_reasons:
        raise ValueError(
            "pilot binding invalid: " + ",".join(binding_reasons)
        )
    if not _digest(phase4_result_sha256):
        raise ValueError("Phase 4 result SHA-256 invalid")

    workflow_filename = PurePosixPath(binding.workflow_path).name
    dispatch_endpoint = (
        f"repos/{binding.repository}/actions/workflows/"
        f"{workflow_filename}/dispatches"
    )
    qualified_target = f"{binding.host}\\{binding.target_identity}"
    runner_command = str(PureWindowsPath(binding.runner_root) / "run.cmd")
    runner_stdout = str(
        PureWindowsPath(binding.runner_root)
        / PHASE5_RUNNER_STDOUT_FILENAME
    )
    runner_stderr = str(
        PureWindowsPath(binding.runner_root)
        / PHASE5_RUNNER_STDERR_FILENAME
    )

    dispatch_command = (
        "gh.exe api --method POST "
        f"-H {_ps_single_quoted('X-GitHub-Api-Version: ' + GITHUB_API_VERSION)} "
        f"{_ps_single_quoted(dispatch_endpoint)} "
        "-F 'return_run_details=true' "
        "-f 'ref=main' "
        f"-f {_ps_single_quoted('inputs[pr_number]=' + str(binding.pull_request_number))} "
        f"-f {_ps_single_quoted('inputs[expected_sha]=' + binding.target_sha)} "
        f"-f {_ps_single_quoted('inputs[expected_workflow_sha]=' + binding.workflow_sha)} "
        f"-f {_ps_single_quoted('inputs[expected_runner_name]=' + binding.runner_name)}"
    )

    lines = [
        f"$BridgeRepository = {_ps_single_quoted(binding.repository)}",
        f"$BridgePullRequestNumber = {binding.pull_request_number}",
        f"$BridgeTargetSha = {_ps_single_quoted(binding.target_sha)}",
        f"$BridgeTargetHostRole = {_ps_single_quoted(PHASE5_HOST_ROLE)}",
        f"$BridgeRequiredIdentity = {_ps_single_quoted(PHASE5_BROKER_IDENTITY)}",
        f"$BridgeEvidenceRoot = {_ps_single_quoted(AUTHORITATIVE_EVIDENCE_ROOT)}",
        f"$BridgeTranscriptFilename = {_ps_single_quoted(PHASE5_TRANSCRIPT_FILENAME)}",
        f"$BridgeExpectedSuccessMarker = {_ps_single_quoted(PHASE5_SUCCESS_MARKER)}",
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
        f"$BridgeHost = {_ps_single_quoted(binding.host)}",
        f"$BridgeBrokerIdentity = {_ps_single_quoted(binding.broker_identity)}",
        f"$BridgeTargetIdentity = {_ps_single_quoted(binding.target_identity)}",
        f"$BridgeQualifiedTargetIdentity = {_ps_single_quoted(qualified_target)}",
        f"$BridgePhase4ResultSha256 = {_ps_single_quoted(phase4_result_sha256)}",
        f"$BridgeRunnerCommand = {_ps_single_quoted(runner_command)}",
        f"$BridgeRunnerStdoutPath = {_ps_single_quoted(runner_stdout)}",
        f"$BridgeRunnerStderrPath = {_ps_single_quoted(runner_stderr)}",
        f"$BridgeDispatchEndpoint = {_ps_single_quoted(dispatch_endpoint)}",
        f"$BridgeRunnerTimeoutSeconds = {PHASE5_RUNNER_TIMEOUT_SECONDS}",
        "$ErrorActionPreference = 'Stop'",
        "",
        "if (-not (Test-Path -LiteralPath $BridgeRunnerCommand -PathType Leaf)) { throw 'Phase 5 run.cmd missing' }",
        "foreach ($BridgeFreshPath in @($BridgeRunnerStdoutPath, $BridgeRunnerStderrPath)) {",
        "    if (Test-Path -LiteralPath $BridgeFreshPath) { throw 'Phase 5 runner output path already exists' }",
        "}",
        "$BridgeTargetCredential = Get-Credential -UserName $BridgeQualifiedTargetIdentity -Message 'Enter the local ac-runner credential for the reviewed Phase 5 plan.'",
        "if ($null -eq $BridgeTargetCredential) { throw 'Phase 5 target credential was not supplied' }",
        "if ($BridgeTargetCredential.UserName -ine $BridgeQualifiedTargetIdentity) { throw 'Phase 5 target credential identity mismatch' }",
        "",
        "$BridgeStartedAt = Get-Date",
        "$BridgeChild = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/s','/c','run.cmd') -Credential $BridgeTargetCredential -LoadUserProfile -WorkingDirectory $BridgeRunnerRoot -RedirectStandardOutput $BridgeRunnerStdoutPath -RedirectStandardError $BridgeRunnerStderrPath -PassThru",
        "Start-Sleep -Seconds 1",
        "if ($BridgeChild.HasExited) {",
        "    $BridgeChildExitCode = $BridgeChild.ExitCode",
        "    throw 'Phase 5 runner listener exited before dispatch'",
        "}",
        "",
        f"$BridgeDispatchJson = {dispatch_command}",
        "$BridgeDispatchExitCode = $LASTEXITCODE",
        "if ($BridgeDispatchExitCode -ne 0) { throw 'Phase 5 dispatch request failed; do not retry' }",
        "if ([string]::IsNullOrWhiteSpace([string]$BridgeDispatchJson)) { throw 'Phase 5 dispatch response was empty; do not retry' }",
        "$BridgeDispatch = $BridgeDispatchJson | ConvertFrom-Json",
        "if ($null -eq $BridgeDispatch.workflow_run_id -or [long]$BridgeDispatch.workflow_run_id -le 0) { throw 'Phase 5 dispatch response workflow_run_id invalid; do not retry' }",
        "$BridgeWorkflowRunId = [long]$BridgeDispatch.workflow_run_id",
        'Write-Output ("PHASE5_WORKFLOW_RUN_ID={0}" -f $BridgeWorkflowRunId)',
        "",
        "while (-not $BridgeChild.HasExited) {",
        "    $BridgeElapsedSeconds = [int]((Get-Date) - $BridgeStartedAt).TotalSeconds",
        '    Write-Host ("heartbeat phase=phase5 elapsed_seconds={0}" -f $BridgeElapsedSeconds)',
        "    if ($BridgeElapsedSeconds -ge $BridgeRunnerTimeoutSeconds) {",
        "        Stop-Process -Id $BridgeChild.Id -Force -ErrorAction Stop",
        "        throw 'Phase 5 runner listener timeout; dispatch must not be retried'",
        "    }",
        f"    Start-Sleep -Seconds {PHASE5_HEARTBEAT_SECONDS}",
        "}",
        "$BridgeChildExitCode = $BridgeChild.ExitCode",
        "if ($BridgeChildExitCode -ne 0) { throw 'Phase 5 runner listener failed' }",
        "",
        f"Write-Output {_ps_single_quoted(PHASE5_SUCCESS_MARKER)}",
        "",
    ]
    return "\n".join(lines)
