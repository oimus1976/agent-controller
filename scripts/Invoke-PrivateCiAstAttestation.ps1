param(
    [Parameter(Mandatory = $true)]
    [string]$CandidatePath,

    [Parameter(Mandatory = $true)]
    [string]$SpecSha256
)

$ErrorActionPreference = 'Stop'

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
        $VariableName = $VariableNode.VariablePath.UserPath
        if ($BindingNames -notcontains $VariableName) {
            continue
        }

        $BindingCounts[$VariableName] = [int]$BindingCounts[$VariableName] + 1
        $IsPlainLeft = $AssignmentAst.Left -is [System.Management.Automation.Language.VariableExpressionAst]
        $IsTopLevel = $RootStatements -contains $AssignmentAst
        if (-not $IsPlainLeft -or -not $IsTopLevel) {
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
    $ParameterName = $ParameterAst.Name.VariablePath.UserPath
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
    $ForEachVariableName = $ForEachAst.Variable.VariablePath.UserPath
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
$VariableAsts = $Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.VariableExpressionAst]
}, $true)
foreach ($VariableAst in $VariableAsts) {
    $UserPath = $VariableAst.VariablePath.UserPath
    if ([string]::IsNullOrWhiteSpace($UserPath)) {
        continue
    }
    $NormalizedName = $UserPath
    $ColonIndex = $NormalizedName.LastIndexOf(':')
    if ($ColonIndex -ge 0) {
        $NormalizedName = $NormalizedName.Substring($ColonIndex + 1)
    }
    $NormalizedName = $NormalizedName.Trim('{}').ToLowerInvariant()
    if ($AutomaticVariableNames -contains $NormalizedName) {
        if (-not $AutomaticVariableCollisions.Contains($NormalizedName)) {
            $AutomaticVariableCollisions.Add($NormalizedName)
        }
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

    if ($LowerName -in @('write-output', 'write-host')) {
        continue
    }
    elseif ($LowerName -in @('remove-item', 'del', 'erase', 'rd', 'rmdir')) {
        if (-not $ObservedEffects.Contains('FILESYSTEM_DESTRUCTIVE_MUTATION')) {
            $ObservedEffects.Add('FILESYSTEM_DESTRUCTIVE_MUTATION')
        }
    }
    elseif ($LowerName -in @('set-acl', 'icacls')) {
        if (-not $ObservedEffects.Contains('ACL_MUTATION')) {
            $ObservedEffects.Add('ACL_MUTATION')
        }
    }
    elseif ($LowerName -in @('invoke-restmethod', 'invoke-webrequest', 'curl', 'wget')) {
        if (-not $ObservedEffects.Contains('HTTP_API_ACCESS')) {
            $ObservedEffects.Add('HTTP_API_ACCESS')
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
    heartbeat_or_progress_proven = $false
    child_exit_code_proven = $false
    fail_fast_proven = $false
}

$Result | ConvertTo-Json -Depth 5 -Compress