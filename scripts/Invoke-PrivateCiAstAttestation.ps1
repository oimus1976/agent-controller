param(
    [Parameter(Mandatory = $true)]
    [string]$CandidatePath,

    [Parameter(Mandatory = $true)]
    [string]$SpecSha256
)

$ErrorActionPreference = 'Stop'

function Get-NormalizedVariableUserPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPath
    )

    $NormalizedName = $UserPath
    $ColonIndex = $NormalizedName.LastIndexOf(':')
    if ($ColonIndex -ge 0) {
        $NormalizedName = $NormalizedName.Substring($ColonIndex + 1)
    }
    return $NormalizedName.Trim('{}')
}

if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) {
    throw "CandidatePath does not exist: $CandidatePath"
}
if ($SpecSha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'SpecSha256 must be lowercase 64-hex'
}

$CandidateBytes = [System.IO.File]::ReadAllBytes($CandidatePath)
$Sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $CandidateSha256 = ([System.BitConverter]::ToString($Sha256.ComputeHash($CandidateBytes))).Replace('-', '').ToLowerInvariant()
}
finally {
    $Sha256.Dispose()
}

$Tokens = $null
$ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $CandidatePath,
    [ref]$Tokens,
    [ref]$ParseErrors
)

$BindingNames = @(
    'BridgeRepository',
    'BridgePullRequestNumber',
    'BridgeTargetSha',
    'BridgeTargetHostRole',
    'BridgeRequiredIdentity',
    'BridgeEvidenceRoot',
    'BridgeTranscriptFilename',
    'BridgeExpectedSuccessMarker'
)
$Bindings = @{}
$BindingCounts = @{}
$BindingProblems = New-Object System.Collections.Generic.List[string]
foreach ($BindingName in $BindingNames) {
    $BindingCounts[$BindingName] = 0
}
$RootStatements = @()
if ($null -ne $Ast.EndBlock) {
    $RootStatements = @($Ast.EndBlock.Statements)
}

$AssignmentAsts = $Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.AssignmentStatementAst]
}, $true)

foreach ($AssignmentAst in $AssignmentAsts) {
    $LeftVariables = New-Object System.Collections.Generic.List[object]
    if ($AssignmentAst.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $LeftVariables.Add($AssignmentAst.Left)
    }
    else {
        foreach ($VariableNode in $AssignmentAst.Left.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.VariableExpressionAst]
        }, $true)) {
            $LeftVariables.Add($VariableNode)
        }
    }

    foreach ($VariableNode in $LeftVariables) {
        $VariableName = Get-NormalizedVariableUserPath -UserPath $VariableNode.VariablePath.UserPath
        if ($BindingNames -notcontains $VariableName) {
            continue
        }

        $BindingCounts[$VariableName] = [int]$BindingCounts[$VariableName] + 1
        $IsPlainLeft = $AssignmentAst.Left -is [System.Management.Automation.Language.VariableExpressionAst]
        $IsUnscopedLeft = $AssignmentAst.Left.VariablePath.UserPath.IndexOf(':') -lt 0
        $IsTopLevel = $RootStatements -contains $AssignmentAst
        if (-not $IsPlainLeft -or -not $IsUnscopedLeft -or -not $IsTopLevel) {
            $Problem = "NONCANONICAL_BINDING:$VariableName"
            if (-not $BindingProblems.Contains($Problem)) {
                $BindingProblems.Add($Problem)
            }
            continue
        }

        $RightAst = $AssignmentAst.Right
        $Value = $null
        if ($RightAst -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $Value = $RightAst.Value
        }
        elseif ($RightAst -is [System.Management.Automation.Language.ConstantExpressionAst]) {
            $Value = $RightAst.Value
        }
        elseif (
            $RightAst -is [System.Management.Automation.Language.CommandExpressionAst] -and
            $RightAst.Expression -is [System.Management.Automation.Language.ConstantExpressionAst]
        ) {
            $Value = $RightAst.Expression.Value
        }

        if ($null -eq $Value) {
            $Problem = "NONLITERAL_BINDING:$VariableName"
            if (-not $BindingProblems.Contains($Problem)) {
                $BindingProblems.Add($Problem)
            }
            continue
        }
        if (-not $Bindings.ContainsKey($VariableName)) {
            $Bindings[$VariableName] = $Value
        }
    }
}

$ParameterAsts = $Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.ParameterAst]
}, $true)
foreach ($ParameterAst in $ParameterAsts) {
    $ParameterName = Get-NormalizedVariableUserPath -UserPath $ParameterAst.Name.VariablePath.UserPath
    if ($BindingNames -contains $ParameterName) {
        $BindingCounts[$ParameterName] = [int]$BindingCounts[$ParameterName] + 1
        $Problem = "NONCANONICAL_BINDING:$ParameterName"
        if (-not $BindingProblems.Contains($Problem)) {
            $BindingProblems.Add($Problem)
        }
    }
}

$ForEachAsts = $Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.ForEachStatementAst]
}, $true)
foreach ($ForEachAst in $ForEachAsts) {
    if ($null -eq $ForEachAst.Variable) {
        continue
    }
    $ForEachVariableName = Get-NormalizedVariableUserPath -UserPath $ForEachAst.Variable.VariablePath.UserPath
    if ($BindingNames -contains $ForEachVariableName) {
        $BindingCounts[$ForEachVariableName] = [int]$BindingCounts[$ForEachVariableName] + 1
        $Problem = "NONCANONICAL_BINDING:$ForEachVariableName"
        if (-not $BindingProblems.Contains($Problem)) {
            $BindingProblems.Add($Problem)
        }
    }
}

foreach ($BindingName in $BindingNames) {
    if ([int]$BindingCounts[$BindingName] -ne 1) {
        $Problem = "BINDING_COUNT_INVALID:$BindingName"
        if (-not $BindingProblems.Contains($Problem)) {
            $BindingProblems.Add($Problem)
        }
    }
    if (-not $Bindings.ContainsKey($BindingName)) {
        $Problem = "BINDING_VALUE_MISSING:$BindingName"
        if (-not $BindingProblems.Contains($Problem)) {
            $BindingProblems.Add($Problem)
        }
    }
}

$AutomaticVariableNames = @(
    'args', 'input', 'matches', 'error', 'home', 'pid', 'profile',
    'psitem', '_', 'this', 'foreach', 'switch', 'lastexitcode',
    'myinvocation', 'psboundparameters', 'pwd', 'host', 'executioncontext'
)
$AutomaticVariableCollisions = New-Object System.Collections.Generic.List[string]

function Add-AutomaticVariableCollision {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPath
    )

    if ([string]::IsNullOrWhiteSpace($UserPath)) {
        return
    }
    $NormalizedName = (Get-NormalizedVariableUserPath -UserPath $UserPath).ToLowerInvariant()
    if (
        $AutomaticVariableNames -contains $NormalizedName -and
        -not $AutomaticVariableCollisions.Contains($NormalizedName)
    ) {
        $AutomaticVariableCollisions.Add($NormalizedName)
    }
}

foreach ($AssignmentAst in $AssignmentAsts) {
    if ($AssignmentAst.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
        Add-AutomaticVariableCollision -UserPath $AssignmentAst.Left.VariablePath.UserPath
        continue
    }
    foreach ($VariableNode in $AssignmentAst.Left.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.VariableExpressionAst]
    }, $true)) {
        Add-AutomaticVariableCollision -UserPath $VariableNode.VariablePath.UserPath
    }
}
foreach ($ParameterAst in $ParameterAsts) {
    Add-AutomaticVariableCollision -UserPath $ParameterAst.Name.VariablePath.UserPath
}
foreach ($ForEachAst in $ForEachAsts) {
    if ($null -ne $ForEachAst.Variable) {
        Add-AutomaticVariableCollision -UserPath $ForEachAst.Variable.VariablePath.UserPath
    }
}

$ObservedEffects = New-Object System.Collections.Generic.List[string]
$CommandAsts = $Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.CommandAst]
}, $true)
foreach ($CommandAst in $CommandAsts) {
    if ($CommandAst.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown) {
        if (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
        continue
    }

    $CommandName = $CommandAst.GetCommandName()
    if ([string]::IsNullOrWhiteSpace($CommandName)) {
        if (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
        continue
    }

    $LowerName = $CommandName.ToLowerInvariant()
    $LastSlash = $LowerName.LastIndexOf('\')
    if ($LastSlash -ge 0) {
        $LowerName = $LowerName.Substring($LastSlash + 1)
    }

    if ($LowerName -in @(
        'write-output', 'write-host', 'get-date', 'start-sleep',
        'hostname.exe', 'whoami.exe', 'get-localuser', 'get-localgroupmember',
        'test-path', 'get-item', 'get-childitem', 'get-ciminstance',
        'get-scheduledtask', 'get-filehash', 'get-credential', 'get-content',
        'convertfrom-json', 'select-object', 'where-object'
    )) {
        continue
    }
    elseif ($LowerName -eq 'start-process') {
        if (-not $ObservedEffects.Contains('PROCESS_LAUNCH')) {
            $ObservedEffects.Add('PROCESS_LAUNCH')
        }
    }
    elseif ($LowerName -eq 'stop-process') {
        if (-not $ObservedEffects.Contains('PROCESS_CONTROL')) {
            $ObservedEffects.Add('PROCESS_CONTROL')
        }
    }
    elseif ($LowerName -eq 'copy-item') {
        if (-not $ObservedEffects.Contains('FILESYSTEM_WRITE_MUTATION')) {
            $ObservedEffects.Add('FILESYSTEM_WRITE_MUTATION')
        }
    }
    elseif ($LowerName -in @('remove-item', 'del', 'erase', 'rd', 'rmdir')) {
        if (-not $ObservedEffects.Contains('FILESYSTEM_DESTRUCTIVE_MUTATION')) {
            $ObservedEffects.Add('FILESYSTEM_DESTRUCTIVE_MUTATION')
        }
    }
    elseif ($LowerName -in @('set-acl', 'icacls', 'icacls.exe')) {
        if (-not $ObservedEffects.Contains('ACL_MUTATION')) {
            $ObservedEffects.Add('ACL_MUTATION')
        }
    }
    elseif ($LowerName -in @('invoke-restmethod', 'invoke-webrequest', 'curl', 'wget')) {
        if (-not $ObservedEffects.Contains('HTTP_API_ACCESS')) {
            $ObservedEffects.Add('HTTP_API_ACCESS')
        }
    }
    elseif ($LowerName -eq 'gh.exe') {
        $CommandText = $CommandAst.Extent.Text
        $IsWorkflowDispatch = (
            $CommandText -match '(?i)^\s*gh\.exe\s+api\s+--method\s+POST\b' -and
            $CommandText -match '(?i)-H\s+[''"]X-GitHub-Api-Version:\s*2026-03-10[''"]' -and
            $CommandText -match '(?i)repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/workflows/[A-Za-z0-9_.-]+\.ya?ml/dispatches' -and
            $CommandText -match '(?i)-f\s+[''"]ref=main[''"]' -and
            $CommandText -notmatch '(?i)return_run_details'
        )
        if ($IsWorkflowDispatch) {
            if (-not $ObservedEffects.Contains('WORKFLOW_DISPATCH')) {
                $ObservedEffects.Add('WORKFLOW_DISPATCH')
            }
        }
        elseif (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    elseif ($LowerName -in @('config.cmd')) {
        if (-not $ObservedEffects.Contains('RUNNER_REGISTRATION')) {
            $ObservedEffects.Add('RUNNER_REGISTRATION')
        }
    }
    else {
        if (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
}

$RedirectionAsts = $Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.RedirectionAst]
}, $true)
if ($RedirectionAsts.Count -gt 0 -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
    $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
}

$InvokeMemberAsts = $Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
}, $true)
if ($InvokeMemberAsts.Count -gt 0 -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
    $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
}

foreach ($AssignmentAst in $AssignmentAsts) {
    $LeftAst = $AssignmentAst.Left
    if ($LeftAst -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $LeftUserPath = $LeftAst.VariablePath.UserPath
        if ($LeftUserPath.IndexOf(':') -ge 0) {
            if (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
                $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
            }
        }
    }
    elseif ($LeftAst -is [System.Management.Automation.Language.MemberExpressionAst]) {
        if (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    else {
        $MemberTargets = $LeftAst.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.MemberExpressionAst]
        }, $true)
        if ($MemberTargets.Count -gt 0 -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
}

$UnresolvedPlaceholders = New-Object System.Collections.Generic.List[string]
foreach ($BindingProblem in $BindingProblems) {
    $UnresolvedPlaceholders.Add($BindingProblem)
}
$CandidateText = [System.IO.File]::ReadAllText($CandidatePath)
foreach ($Pattern in @('<[^>]+>', '\{\{[^}]+\}\}', '__[A-Z0-9_]+__')) {
    foreach ($Match in [System.Text.RegularExpressions.Regex]::Matches($CandidateText, $Pattern)) {
        if (-not $UnresolvedPlaceholders.Contains($Match.Value)) {
            $UnresolvedPlaceholders.Add($Match.Value)
        }
    }
}

$ForbiddenConveniencePaths = New-Object System.Collections.Generic.List[string]
foreach ($ForbiddenText in @('%TEMP%', '$env:TEMP', '$pwd', 'Get-Location')) {
    if ($CandidateText.IndexOf($ForbiddenText, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $ForbiddenConveniencePaths.Add($ForbiddenText)
    }
}

$ChildProcessAssigned = $false
$ChildExitCodeAssigned = $false
$StartedAtAssigned = $false
foreach ($AssignmentAst in $AssignmentAsts) {
    if (
        $AssignmentAst.Left -isnot [System.Management.Automation.Language.VariableExpressionAst] -or
        ($RootStatements -notcontains $AssignmentAst)
    ) {
        continue
    }

    $LeftName = Get-NormalizedVariableUserPath -UserPath $AssignmentAst.Left.VariablePath.UserPath
    if ($LeftName -ieq 'BridgeChild') {
        $StartProcessCommands = @($AssignmentAst.Right.FindAll({
            param($Node)
            if ($Node -isnot [System.Management.Automation.Language.CommandAst]) {
                return $false
            }
            $Name = $Node.GetCommandName()
            return (-not [string]::IsNullOrWhiteSpace($Name)) -and ($Name -ieq 'Start-Process')
        }, $true))
        if ($StartProcessCommands.Count -eq 1) {
            $HasPassThru = $false
            foreach ($Element in $StartProcessCommands[0].CommandElements) {
                if (
                    $Element -is [System.Management.Automation.Language.CommandParameterAst] -and
                    $Element.ParameterName -ieq 'PassThru'
                ) {
                    $HasPassThru = $true
                }
            }
            if ($HasPassThru) {
                $ChildProcessAssigned = $true
            }
        }
    }
    elseif ($LeftName -ieq 'BridgeStartedAt') {
        $GetDateCommands = @($AssignmentAst.Right.FindAll({
            param($Node)
            if ($Node -isnot [System.Management.Automation.Language.CommandAst]) {
                return $false
            }
            $Name = $Node.GetCommandName()
            return (-not [string]::IsNullOrWhiteSpace($Name)) -and ($Name -ieq 'Get-Date')
        }, $true))
        if ($GetDateCommands.Count -eq 1) {
            $StartedAtAssigned = $true
        }
    }
    elseif ($LeftName -ieq 'BridgeChildExitCode') {
        if ($AssignmentAst.Right.Extent.Text -match '(?i)^\s*\$BridgeChild\.ExitCode\s*$') {
            $ChildExitCodeAssigned = $true
        }
    }
}

$HeartbeatOrProgressProven = $false
if ($ChildProcessAssigned -and $StartedAtAssigned) {
    $WhileAsts = $Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.WhileStatementAst]
    }, $true)
    foreach ($WhileAst in $WhileAsts) {
        $ConditionText = $WhileAst.Condition.Extent.Text
        $BodyText = $WhileAst.Body.Extent.Text
        if ($ConditionText -notmatch '(?i)-not\s+\$BridgeChild\.HasExited') {
            continue
        }
        if (
            $BodyText -notmatch '(?i)heartbeat' -or
            $BodyText -notmatch '(?i)phase=' -or
            $BodyText -notmatch '(?i)elapsed_seconds=' -or
            $BodyText -notmatch '(?i)\$BridgeElapsedSeconds'
        ) {
            continue
        }

        $ElapsedAssignmentProven = $false
        $BodyAssignments = @($WhileAst.Body.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.AssignmentStatementAst]
        }, $true))
        foreach ($BodyAssignment in $BodyAssignments) {
            if ($BodyAssignment.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) {
                continue
            }
            $BodyLeftName = Get-NormalizedVariableUserPath -UserPath $BodyAssignment.Left.VariablePath.UserPath
            if ($BodyLeftName -ine 'BridgeElapsedSeconds') {
                continue
            }
            $RightText = $BodyAssignment.Right.Extent.Text
            if (
                $RightText -match '(?i)Get-Date' -and
                $RightText -match '(?i)\$BridgeStartedAt' -and
                $RightText -match '(?i)\.TotalSeconds'
            ) {
                $ElapsedAssignmentProven = $true
            }
        }
        if (-not $ElapsedAssignmentProven) {
            continue
        }

        $SleepMatch = [regex]::Match(
            $BodyText,
            '(?i)Start-Sleep\s+-Seconds\s+([0-9]+)'
        )
        if (-not $SleepMatch.Success) {
            continue
        }
        $SleepSeconds = [int]$SleepMatch.Groups[1].Value
        if ($SleepSeconds -lt 1 -or $SleepSeconds -gt 60) {
            continue
        }

        $HeartbeatOrProgressProven = $true
        break
    }
}

$ChildExitCodeProven = $ChildProcessAssigned -and $ChildExitCodeAssigned
$FailFastProven = $false
if ($ChildExitCodeProven) {
    $IfAsts = @($Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.IfStatementAst]
    }, $true))
    foreach ($IfAst in $IfAsts) {
        $IfText = $IfAst.Extent.Text
        $ThrowAsts = @($IfAst.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.ThrowStatementAst]
        }, $true))
        if (
            $IfText -match '(?is)^\s*if\s*\(\s*\$BridgeChildExitCode\s*-ne\s*0\s*\)' -and
            $ThrowAsts.Count -gt 0
        ) {
            $FailFastProven = $true
            break
        }
    }
}

$StructuralErrorCount = [int]$ParseErrors.Count + [int]$BindingProblems.Count
$Result = [ordered]@{
    runtime = 'Windows PowerShell 5.1'
    parser = 'System.Management.Automation.Language.Parser'
    candidate_sha256 = $CandidateSha256
    spec_sha256 = $SpecSha256
    parsed = ($StructuralErrorCount -eq 0)
    error_count = $StructuralErrorCount
    repository = [string]$Bindings['BridgeRepository']
    pull_request_number = [int]$Bindings['BridgePullRequestNumber']
    target_sha = [string]$Bindings['BridgeTargetSha']
    target_host_role = [string]$Bindings['BridgeTargetHostRole']
    required_identity = [string]$Bindings['BridgeRequiredIdentity']
    evidence_root = [string]$Bindings['BridgeEvidenceRoot']
    transcript_filename = [string]$Bindings['BridgeTranscriptFilename']
    expected_success_marker = [string]$Bindings['BridgeExpectedSuccessMarker']
    observed_effect_families = @($ObservedEffects)
    automatic_variable_collisions = @($AutomaticVariableCollisions)
    unresolved_placeholders = @($UnresolvedPlaceholders)
    forbidden_convenience_paths = @($ForbiddenConveniencePaths)
    self_declared_gate_authority = ($CandidateText -match '(?im)^\s*(Write-Output|Write-Host)\s+["'']?PASS_TO_OPERATOR["'']?\s*$')
    heartbeat_or_progress_proven = $HeartbeatOrProgressProven
    child_exit_code_proven = $ChildExitCodeProven
    fail_fast_proven = $FailFastProven
}

$Result | ConvertTo-Json -Depth 5 -Compress
