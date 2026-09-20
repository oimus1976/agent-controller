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
    PHASE4_AUTHORITY_ROOT,
    PHASE4_TARGET_PROBE_COPY_FILENAME,
    PHASE4_TARGET_TIMEOUT_SECONDS,
    PHASE4_TRUSTED_GH_PATH,
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
    "HTTP_API_ACCESS",
    "PROCESS_CONTROL",
    "PROCESS_LAUNCH",
    "WORKFLOW_DISPATCH",
)
PHASE5_RUNNER_STDOUT_FILENAME = "issue225-phase5-runner-stdout.log"
PHASE5_RUNNER_STDERR_FILENAME = "issue225-phase5-runner-stderr.log"
PHASE5_SECURITY_PROBE_RESULT_FILENAME = "issue225-phase5-security-probe-result.json"
PHASE5_SECURITY_PROBE_STDOUT_FILENAME = "issue225-phase5-security-probe-stdout.log"
PHASE5_SECURITY_PROBE_STDERR_FILENAME = "issue225-phase5-security-probe-stderr.log"
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
    target_probe_sha256: str,
) -> str:
    binding_reasons = pilot_binding_reason_codes(binding)
    if binding_reasons:
        raise ValueError(
            "pilot binding invalid: " + ",".join(binding_reasons)
        )
    if not _digest(phase4_result_sha256):
        raise ValueError("Phase 4 result SHA-256 invalid")
    if not _digest(target_probe_sha256):
        raise ValueError("Phase 4 target probe SHA-256 invalid")

    workflow_filename = PurePosixPath(binding.workflow_path).name
    dispatch_endpoint = (
        f"repos/{binding.repository}/actions/workflows/"
        f"{workflow_filename}/dispatches"
    )
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
    runners_endpoint = (
        f"repos/{binding.repository}/actions/runners?per_page=100"
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
    security_probe = str(
        PureWindowsPath(binding.runner_root)
        / PHASE4_TARGET_PROBE_COPY_FILENAME
    )
    security_probe_result = str(
        PureWindowsPath(binding.runner_root)
        / PHASE5_SECURITY_PROBE_RESULT_FILENAME
    )
    security_probe_stdout = str(
        PureWindowsPath(binding.runner_root)
        / PHASE5_SECURITY_PROBE_STDOUT_FILENAME
    )
    security_probe_stderr = str(
        PureWindowsPath(binding.runner_root)
        / PHASE5_SECURITY_PROBE_STDERR_FILENAME
    )
    phase5_authority_marker = str(
        PureWindowsPath(PHASE4_AUTHORITY_ROOT)
        / (
            "issue225-phase5-result-"
            + phase4_result_sha256
            + ".consumed.json"
        )
    )

    active_read_commands = {
        status: (
            "gh.exe api "
            f"-H {_ps_single_quoted('X-GitHub-Api-Version: ' + GITHUB_API_VERSION)} "
            f"{_ps_single_quoted(active_endpoints[status])}"
        )
        for status in active_statuses
    }
    runner_read_command = (
        "gh.exe api "
        f"-H {_ps_single_quoted('X-GitHub-Api-Version: ' + GITHUB_API_VERSION)} "
        f"{_ps_single_quoted(runners_endpoint)}"
    )

    dispatch_command = (
        "gh.exe api --method POST "
        f"-H {_ps_single_quoted('X-GitHub-Api-Version: ' + GITHUB_API_VERSION)} "
        f"{_ps_single_quoted(dispatch_endpoint)} "
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
        f"$BridgeSecurityProbePath = {_ps_single_quoted(security_probe)}",
        f"$BridgeSecurityProbeSha256 = {_ps_single_quoted(target_probe_sha256)}",
        f"$BridgeSecurityProbeResultPath = {_ps_single_quoted(security_probe_result)}",
        f"$BridgeSecurityProbeStdoutPath = {_ps_single_quoted(security_probe_stdout)}",
        f"$BridgeSecurityProbeStderrPath = {_ps_single_quoted(security_probe_stderr)}",
        f"$BridgePhase5AuthorityMarkerPath = {_ps_single_quoted(phase5_authority_marker)}",
        f"$BridgeTrustedGhPath = {_ps_single_quoted(PHASE4_TRUSTED_GH_PATH)}",
        f"$BridgeSecurityProbeTimeoutSeconds = {PHASE4_TARGET_TIMEOUT_SECONDS}",
        f"$BridgeRunnerCommand = {_ps_single_quoted(runner_command)}",
        f"$BridgeRunnerStdoutPath = {_ps_single_quoted(runner_stdout)}",
        f"$BridgeRunnerStderrPath = {_ps_single_quoted(runner_stderr)}",
        f"$BridgeDispatchEndpoint = {_ps_single_quoted(dispatch_endpoint)}",
        f"$BridgeActiveQueuedEndpoint = {_ps_single_quoted(active_endpoints['queued'])}",
        f"$BridgeActiveInProgressEndpoint = {_ps_single_quoted(active_endpoints['in_progress'])}",
        f"$BridgeActiveRequestedEndpoint = {_ps_single_quoted(active_endpoints['requested'])}",
        f"$BridgeActiveWaitingEndpoint = {_ps_single_quoted(active_endpoints['waiting'])}",
        f"$BridgeActivePendingEndpoint = {_ps_single_quoted(active_endpoints['pending'])}",
        f"$BridgeRunnersEndpoint = {_ps_single_quoted(runners_endpoint)}",
        f"$BridgeRunnerTimeoutSeconds = {PHASE5_RUNNER_TIMEOUT_SECONDS}",
        "$ErrorActionPreference = 'Stop'",
        "",
        "if (-not (Test-Path -LiteralPath $BridgeRunnerCommand -PathType Leaf)) { throw 'Phase 5 run.cmd missing' }",
        "if (-not (Test-Path -LiteralPath $BridgeSecurityProbePath -PathType Leaf)) { throw 'Phase 5 security probe missing' }",
        "$BridgeSecurityProbeObservedSha = (Get-FileHash -LiteralPath $BridgeSecurityProbePath -Algorithm SHA256).Hash",
        "if ($BridgeSecurityProbeObservedSha -ine $BridgeSecurityProbeSha256) { throw 'Phase 5 security probe hash mismatch' }",
        "if (-not (Test-Path -LiteralPath $BridgePhase5AuthorityMarkerPath -PathType Leaf)) { throw 'Phase 5 durable authority marker missing' }",
        "foreach ($BridgeFreshPath in @($BridgeRunnerStdoutPath, $BridgeRunnerStderrPath, $BridgeSecurityProbeResultPath, $BridgeSecurityProbeStdoutPath, $BridgeSecurityProbeStderrPath)) {",
        "    if (Test-Path -LiteralPath $BridgeFreshPath) { throw 'Phase 5 runner output path already exists' }",
        "}",
        "$BridgeForbiddenBrokerEnvironment = @(Get-ChildItem Env: | Where-Object {",
        "    $_.Name -match '^(GH_TOKEN|GITHUB_TOKEN|ACTIONS_RUNNER_INPUT_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY)$' -or",
        "    $_.Name -match '^(AGENT_CONTROLLER|PRIVATE_CI).*(HMAC|KEY|SECRET|TOKEN|AUTH)'",
        "})",
        "if ($BridgeForbiddenBrokerEnvironment.Count -ne 0) { throw 'Phase 5 broker environment contains forbidden inheritable authority material' }",
        "",
        "$BridgeExistingRunnerProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -match 'Runner|actions' })",
        "if ($BridgeExistingRunnerProcesses.Count -ne 0) { throw 'Phase 5 stale local runner process detected before start' }",
        "",
        f"$BridgeQueuedBeforeStartJson = {active_read_commands['queued']}",
        "$BridgeQueuedBeforeStartExitCode = $LASTEXITCODE",
        "if ($BridgeQueuedBeforeStartExitCode -ne 0) { throw 'Phase 5 queued-run readback failed before runner start' }",
        "$BridgeQueuedBeforeStart = $BridgeQueuedBeforeStartJson | ConvertFrom-Json",
        "if ($null -eq $BridgeQueuedBeforeStart.total_count -or [int]$BridgeQueuedBeforeStart.total_count -ne 0) { throw 'Phase 5 queued trusted workflow exists before runner start' }",
        f"$BridgeInProgressBeforeStartJson = {active_read_commands['in_progress']}",
        "$BridgeInProgressBeforeStartExitCode = $LASTEXITCODE",
        "if ($BridgeInProgressBeforeStartExitCode -ne 0) { throw 'Phase 5 in-progress-run readback failed before runner start' }",
        "$BridgeInProgressBeforeStart = $BridgeInProgressBeforeStartJson | ConvertFrom-Json",
        "if ($null -eq $BridgeInProgressBeforeStart.total_count -or [int]$BridgeInProgressBeforeStart.total_count -ne 0) { throw 'Phase 5 in-progress trusted workflow exists before runner start' }",
        f"$BridgeRequestedBeforeStartJson = {active_read_commands['requested']}",
        "$BridgeRequestedBeforeStartExitCode = $LASTEXITCODE",
        "if ($BridgeRequestedBeforeStartExitCode -ne 0) { throw 'Phase 5 requested-run readback failed before runner start' }",
        "$BridgeRequestedBeforeStart = $BridgeRequestedBeforeStartJson | ConvertFrom-Json",
        "if ($null -eq $BridgeRequestedBeforeStart.total_count -or [int]$BridgeRequestedBeforeStart.total_count -ne 0) { throw 'Phase 5 requested trusted workflow exists before runner start' }",
        f"$BridgeWaitingBeforeStartJson = {active_read_commands['waiting']}",
        "$BridgeWaitingBeforeStartExitCode = $LASTEXITCODE",
        "if ($BridgeWaitingBeforeStartExitCode -ne 0) { throw 'Phase 5 waiting-run readback failed before runner start' }",
        "$BridgeWaitingBeforeStart = $BridgeWaitingBeforeStartJson | ConvertFrom-Json",
        "if ($null -eq $BridgeWaitingBeforeStart.total_count -or [int]$BridgeWaitingBeforeStart.total_count -ne 0) { throw 'Phase 5 waiting trusted workflow exists before runner start' }",
        f"$BridgePendingBeforeStartJson = {active_read_commands['pending']}",
        "$BridgePendingBeforeStartExitCode = $LASTEXITCODE",
        "if ($BridgePendingBeforeStartExitCode -ne 0) { throw 'Phase 5 pending-run readback failed before runner start' }",
        "$BridgePendingBeforeStart = $BridgePendingBeforeStartJson | ConvertFrom-Json",
        "if ($null -eq $BridgePendingBeforeStart.total_count -or [int]$BridgePendingBeforeStart.total_count -ne 0) { throw 'Phase 5 pending trusted workflow exists before runner start' }",
        "",
        "$BridgeTargetCredential = Get-Credential -UserName $BridgeQualifiedTargetIdentity -Message 'Enter the local ac-runner credential for the reviewed Phase 5 plan.'",
        "if ($null -eq $BridgeTargetCredential) { throw 'Phase 5 target credential was not supplied' }",
        "if ($BridgeTargetCredential.UserName -ine $BridgeQualifiedTargetIdentity) { throw 'Phase 5 target credential identity mismatch' }",
        "$BridgeSecurityProbePrelaunchSha = (Get-FileHash -LiteralPath $BridgeSecurityProbePath -Algorithm SHA256).Hash",
        "if ($BridgeSecurityProbePrelaunchSha -ine $BridgeSecurityProbeSha256) { throw 'Phase 5 security probe drift before launch' }",
        "",
        "$BridgeSecurityProbeStartedAt = Get-Date",
        "$BridgeSecurityProbeChild = Start-Process -FilePath 'powershell.exe' -ArgumentList @(",
        "    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',",
        "    '-File', $BridgeSecurityProbePath,",
        "    '-ExpectedHost', $BridgeHost,",
        "    '-ExpectedIdentity', $BridgeQualifiedTargetIdentity,",
        "    '-AuthorityMarkerPath', $BridgePhase5AuthorityMarkerPath,",
        "    '-ResultPath', $BridgeSecurityProbeResultPath,",
        "    '-TrustedGhPath', $BridgeTrustedGhPath",
        ") -Credential $BridgeTargetCredential -LoadUserProfile -WorkingDirectory $BridgeRunnerRoot -RedirectStandardOutput $BridgeSecurityProbeStdoutPath -RedirectStandardError $BridgeSecurityProbeStderrPath -PassThru",
        "while (-not $BridgeSecurityProbeChild.HasExited) {",
        "    $BridgeSecurityProbeElapsedSeconds = [int]((Get-Date) - $BridgeSecurityProbeStartedAt).TotalSeconds",
        '    Write-Host ("heartbeat phase=phase5-security elapsed_seconds={0}" -f $BridgeSecurityProbeElapsedSeconds)',
        "    if ($BridgeSecurityProbeElapsedSeconds -ge $BridgeSecurityProbeTimeoutSeconds) {",
        "        Stop-Process -Id $BridgeSecurityProbeChild.Id -Force -ErrorAction Stop",
        "        throw 'Phase 5 security probe timeout; dispatch must not be attempted'",
        "    }",
        "    Start-Sleep -Seconds 1",
        "}",
        "$BridgeSecurityProbeExitCode = $BridgeSecurityProbeChild.ExitCode",
        "if ($BridgeSecurityProbeExitCode -ne 0) { throw 'Phase 5 security probe failed; dispatch must not be attempted' }",
        "if (-not (Test-Path -LiteralPath $BridgeSecurityProbeResultPath -PathType Leaf)) { throw 'Phase 5 security probe result missing' }",
        "$BridgeSecurityProbeResult = Get-Content -LiteralPath $BridgeSecurityProbeResultPath -Raw -Encoding UTF8 | ConvertFrom-Json",
        "if ($BridgeSecurityProbeResult.schema -cne 'agent-controller.private-ci-phase4-target-probe.v1') { throw 'Phase 5 security probe schema mismatch' }",
        "if ($BridgeSecurityProbeResult.status -cne 'TARGET_PROBE_PASS') { throw 'Phase 5 security probe did not pass' }",
        "if ($BridgeSecurityProbeResult.host -ine $BridgeHost) { throw 'Phase 5 security probe host mismatch' }",
        "if ($BridgeSecurityProbeResult.identity -ine $BridgeQualifiedTargetIdentity) { throw 'Phase 5 security probe identity mismatch' }",
        "if ($BridgeSecurityProbeResult.admin_sid_present -ne $false) { throw 'Phase 5 security probe admin status unsafe' }",
        "if ($BridgeSecurityProbeResult.high_integrity_present -ne $false) { throw 'Phase 5 security probe integrity unsafe' }",
        "if ($BridgeSecurityProbeResult.forbidden_environment_count -ne 0) { throw 'Phase 5 security probe environment unsafe' }",
        "if ($BridgeSecurityProbeResult.broker_credential_roots_readable -ne 0) { throw 'Phase 5 broker credential isolation failed' }",
        "if ($BridgeSecurityProbeResult.gh_authenticated -ne $false) { throw 'Phase 5 target gh authentication isolation failed' }",
        "if ($BridgeSecurityProbeResult.authority_marker_write_denied -ne $true) { throw 'Phase 5 durable authority isolation failed' }",
        "Write-Output 'PHASE5_SECURITY_CONTEXT_REVALIDATED'",
        "",
        "$BridgeStartedAt = Get-Date",
        "$BridgeChild = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/s','/c','run.cmd') -Credential $BridgeTargetCredential -LoadUserProfile -WorkingDirectory $BridgeRunnerRoot -RedirectStandardOutput $BridgeRunnerStdoutPath -RedirectStandardError $BridgeRunnerStderrPath -PassThru",
        "Start-Sleep -Seconds 1",
        "if ($BridgeChild.HasExited) {",
        "    $BridgeChildExitCode = $BridgeChild.ExitCode",
        "    throw 'Phase 5 runner listener exited before dispatch'",
        "}",
        "$BridgeListenerProcess = $null",
        "while ($null -eq $BridgeListenerProcess -and -not $BridgeChild.HasExited) {",
        "    $BridgeListenerCandidates = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {",
        "        $_.Name -ieq 'Runner.Listener.exe' -and",
        "        $_.CommandLine -like ('*' + $BridgeRunnerRoot + '*')",
        "    })",
        "    if ($BridgeListenerCandidates.Count -gt 1) { throw 'Phase 5 multiple runner listener processes detected' }",
        "    if ($BridgeListenerCandidates.Count -eq 1) { $BridgeListenerProcess = $BridgeListenerCandidates[0] }",
        "    if ($null -eq $BridgeListenerProcess) {",
        "        $BridgeListenerElapsedSeconds = [int]((Get-Date) - $BridgeStartedAt).TotalSeconds",
        "        Write-Host (\"heartbeat phase=phase5-listener-start elapsed_seconds={0}\" -f $BridgeListenerElapsedSeconds)",
        "        if ($BridgeListenerElapsedSeconds -ge 30) { throw 'Phase 5 runner listener process did not appear' }",
        "        Start-Sleep -Seconds 1",
        "    }",
        "}",
        "if ($BridgeChild.HasExited) {",
        "    $BridgeChildExitCode = $BridgeChild.ExitCode",
        "    throw 'Phase 5 runner listener exited before owner verification'",
        "}",
        "$BridgeListenerOwner = Invoke-CimMethod -InputObject $BridgeListenerProcess -MethodName GetOwner",
        "if ($BridgeListenerOwner.ReturnValue -ne 0) { throw 'Phase 5 runner listener owner readback failed' }",
        "$BridgeListenerQualifiedOwner = $BridgeListenerOwner.Domain + '\\' + $BridgeListenerOwner.User",
        "if ($BridgeListenerQualifiedOwner -ine $BridgeQualifiedTargetIdentity) { throw 'Phase 5 runner listener owner mismatch' }",
        "Write-Output (\"PHASE5_RUNNER_PROCESS_ID={0}\" -f $BridgeListenerProcess.ProcessId)",
        "Write-Output (\"PHASE5_RUNNER_PROCESS_OWNER={0}\" -f $BridgeListenerQualifiedOwner)",
        "",
        f"$BridgeRunnerReadJson = {runner_read_command}",
        "$BridgeRunnerReadExitCode = $LASTEXITCODE",
        "if ($BridgeRunnerReadExitCode -ne 0) { throw 'Phase 5 pre-dispatch runner readback failed; dispatch must not be attempted' }",
        "if (-not $BridgeRunnerReadJson) { throw 'Phase 5 pre-dispatch runner readback was empty; dispatch must not be attempted' }",
        "$BridgeRunnerRead = $BridgeRunnerReadJson | ConvertFrom-Json",
        "if ($null -eq $BridgeRunnerRead.total_count -or $null -eq $BridgeRunnerRead.runners) { throw 'Phase 5 pre-dispatch runner readback shape invalid; dispatch must not be attempted' }",
        "$BridgeRunnerItems = @($BridgeRunnerRead.runners)",
        "if ([int]$BridgeRunnerRead.total_count -gt $BridgeRunnerItems.Count) { throw 'Phase 5 pre-dispatch runner readback incomplete; dispatch must not be attempted' }",
        "$BridgeEligibleRunners = @($BridgeRunnerItems | Where-Object {",
        "    $BridgeObservedLabels = @($_.labels.name)",
        "    $_.id -eq $BridgeRunnerId -or",
        "    $_.name -eq $BridgeRunnerName -or",
        "    $BridgeObservedLabels -contains $BridgeRunnerLabel",
        "})",
        "if ($BridgeEligibleRunners.Count -ne 1) { throw 'Phase 5 pre-dispatch eligible runner cardinality invalid' }",
        "$BridgeRemoteRunner = $BridgeEligibleRunners[0]",
        "$BridgeRemoteLabels = @($BridgeRemoteRunner.labels.name)",
        "if ([long]$BridgeRemoteRunner.id -ne $BridgeRunnerId) { throw 'Phase 5 pre-dispatch runner id mismatch' }",
        "if ($BridgeRemoteRunner.name -cne $BridgeRunnerName) { throw 'Phase 5 pre-dispatch runner name mismatch' }",
        "if ($BridgeRemoteLabels -notcontains $BridgeRunnerLabel) { throw 'Phase 5 pre-dispatch runner label mismatch' }",
        "if ($BridgeRemoteRunner.status -cne 'online') { throw 'Phase 5 pre-dispatch runner is not online' }",
        "if ([bool]$BridgeRemoteRunner.busy) { throw 'Phase 5 pre-dispatch runner is busy' }",
        "",
        f"$BridgeQueuedBeforeDispatchJson = {active_read_commands['queued']}",
        "$BridgeQueuedBeforeDispatchExitCode = $LASTEXITCODE",
        "if ($BridgeQueuedBeforeDispatchExitCode -ne 0) { throw 'Phase 5 queued-run readback failed before dispatch' }",
        "$BridgeQueuedBeforeDispatch = $BridgeQueuedBeforeDispatchJson | ConvertFrom-Json",
        "if ($null -eq $BridgeQueuedBeforeDispatch.total_count -or [int]$BridgeQueuedBeforeDispatch.total_count -ne 0) { throw 'Phase 5 queued trusted workflow exists before dispatch' }",
        f"$BridgeInProgressBeforeDispatchJson = {active_read_commands['in_progress']}",
        "$BridgeInProgressBeforeDispatchExitCode = $LASTEXITCODE",
        "if ($BridgeInProgressBeforeDispatchExitCode -ne 0) { throw 'Phase 5 in-progress-run readback failed before dispatch' }",
        "$BridgeInProgressBeforeDispatch = $BridgeInProgressBeforeDispatchJson | ConvertFrom-Json",
        "if ($null -eq $BridgeInProgressBeforeDispatch.total_count -or [int]$BridgeInProgressBeforeDispatch.total_count -ne 0) { throw 'Phase 5 in-progress trusted workflow exists before dispatch' }",
        f"$BridgeRequestedBeforeDispatchJson = {active_read_commands['requested']}",
        "$BridgeRequestedBeforeDispatchExitCode = $LASTEXITCODE",
        "if ($BridgeRequestedBeforeDispatchExitCode -ne 0) { throw 'Phase 5 requested-run readback failed before dispatch' }",
        "$BridgeRequestedBeforeDispatch = $BridgeRequestedBeforeDispatchJson | ConvertFrom-Json",
        "if ($null -eq $BridgeRequestedBeforeDispatch.total_count -or [int]$BridgeRequestedBeforeDispatch.total_count -ne 0) { throw 'Phase 5 requested trusted workflow exists before dispatch' }",
        f"$BridgeWaitingBeforeDispatchJson = {active_read_commands['waiting']}",
        "$BridgeWaitingBeforeDispatchExitCode = $LASTEXITCODE",
        "if ($BridgeWaitingBeforeDispatchExitCode -ne 0) { throw 'Phase 5 waiting-run readback failed before dispatch' }",
        "$BridgeWaitingBeforeDispatch = $BridgeWaitingBeforeDispatchJson | ConvertFrom-Json",
        "if ($null -eq $BridgeWaitingBeforeDispatch.total_count -or [int]$BridgeWaitingBeforeDispatch.total_count -ne 0) { throw 'Phase 5 waiting trusted workflow exists before dispatch' }",
        f"$BridgePendingBeforeDispatchJson = {active_read_commands['pending']}",
        "$BridgePendingBeforeDispatchExitCode = $LASTEXITCODE",
        "if ($BridgePendingBeforeDispatchExitCode -ne 0) { throw 'Phase 5 pending-run readback failed before dispatch' }",
        "$BridgePendingBeforeDispatch = $BridgePendingBeforeDispatchJson | ConvertFrom-Json",
        "if ($null -eq $BridgePendingBeforeDispatch.total_count -or [int]$BridgePendingBeforeDispatch.total_count -ne 0) { throw 'Phase 5 pending trusted workflow exists before dispatch' }",
        "",
        f"$BridgeDispatchJson = {dispatch_command}",
        "$BridgeDispatchExitCode = $LASTEXITCODE",
        "if ($BridgeDispatchExitCode -ne 0) { throw 'Phase 5 dispatch request failed; do not retry' }",
        "if (-not $BridgeDispatchJson) { throw 'Phase 5 dispatch response was empty; do not retry' }",
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
