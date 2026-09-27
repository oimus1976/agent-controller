param(
    [Parameter(Mandatory = $true)]
    [string]$CandidatePath,

    [Parameter(Mandatory = $true)]
    [string]$SpecSha256,

    [Parameter(Mandatory = $false)]
    [string]$ExpectedEnvironmentGeneration,

    [Parameter(Mandatory = $false)]
    [string]$ExpectedGenerationRoot
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
$Phase6BindingNames = @(
    'BridgeGenerationRoot',
    'BridgeEnvironmentGeneration'
)
$AllTrackedBindingNames = $BindingNames + $Phase6BindingNames
$Bindings = @{}
$BindingCounts = @{}
$BindingProblems = New-Object System.Collections.Generic.List[string]
foreach ($BindingName in $AllTrackedBindingNames) {
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
        if ($AllTrackedBindingNames -notcontains $VariableName) {
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
    if ($AllTrackedBindingNames -contains $ParameterName) {
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
    if ($AllTrackedBindingNames -contains $ForEachVariableName) {
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

if ($Bindings['BridgeExpectedSuccessMarker'] -eq 'PHASE6_CLEANUP_PASS') {
    foreach ($BindingName in $Phase6BindingNames) {
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
    if ($Bindings.ContainsKey('BridgeEnvironmentGeneration')) {
        $GenEnv = [string]$Bindings['BridgeEnvironmentGeneration']
        if ($GenEnv -notmatch '^ac-pilot-[a-z0-9-]+$') {
            $Problem = "NONCANONICAL_BINDING:BridgeEnvironmentGeneration"
            if (-not $BindingProblems.Contains($Problem)) {
                $BindingProblems.Add($Problem)
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedEnvironmentGeneration) -and $GenEnv -cne $ExpectedEnvironmentGeneration) {
            $Problem = "NONCANONICAL_BINDING:BridgeEnvironmentGeneration"
            if (-not $BindingProblems.Contains($Problem)) {
                $BindingProblems.Add($Problem)
            }
        }
    }
    if ($Bindings.ContainsKey('BridgeGenerationRoot') -and $Bindings.ContainsKey('BridgeEnvironmentGeneration')) {
        $GenRoot = [string]$Bindings['BridgeGenerationRoot']
        $GenEnv = [string]$Bindings['BridgeEnvironmentGeneration']
        $ExpectedGenRootCanonical = "C:\ProgramData\agent-controller\private-ci\$GenEnv"
        if ($GenRoot.TrimEnd('\/') -ne $ExpectedGenRootCanonical) {
            $Problem = "NONCANONICAL_BINDING:BridgeGenerationRoot"
            if (-not $BindingProblems.Contains($Problem)) {
                $BindingProblems.Add($Problem)
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedGenerationRoot) -and $GenRoot.TrimEnd('\/') -ne $ExpectedGenerationRoot.TrimEnd('\/')) {
            $Problem = "NONCANONICAL_BINDING:BridgeGenerationRoot"
            if (-not $BindingProblems.Contains($Problem)) {
                $BindingProblems.Add($Problem)
            }
        }
    }
}
else {
    foreach ($BindingName in $Phase6BindingNames) {
        if ([int]$BindingCounts[$BindingName] -gt 1) {
            $Problem = "BINDING_COUNT_INVALID:$BindingName"
            if (-not $BindingProblems.Contains($Problem)) {
                $BindingProblems.Add($Problem)
            }
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

# #270: fixed target-launch shapes. A non-elevated broker cannot wait on or
# read a child started with Start-Process -Credential, so Phase 4/5 launch the
# target through [System.Diagnostics.Process]::Start with an inline
# ProcessStartInfo and keep the creation handle. Only the exact shapes below
# are classified; any other method invocation stays DYNAMIC_OR_UNKNOWN_COMMAND.
#
# This gate classifies effect families and is defense in depth. It does not
# prove payload or identity integrity: the exact canonical candidate
# comparison in the Python contracts/runtimes owns that (Start-Process with an
# arbitrary FilePath is also only PROCESS_LAUNCH here).
$ProcessLaunchNames = @('BridgeChild', 'BridgeSecurityProbeChild', 'BridgeCredentialCheck')
$ProcessStartInfoKeys = @(
    'FileName', 'Arguments', 'UserName', 'Domain', 'Password', 'LoadUserProfile',
    'UseShellExecute', 'CreateNoWindow', 'WorkingDirectory',
    'RedirectStandardOutput', 'RedirectStandardError'
)
# Each launch name must carry exactly one of the rendered key sets (Codex P1 on
# ea13afd: a subset could drop UserName/Domain/Password and start the child as
# the broker).
$StartInfoCredentialKeys = @(
    'createnowindow', 'domain', 'filename', 'loaduserprofile', 'password',
    'useshellexecute', 'username', 'workingdirectory'
)
$StartInfoRunnerKeys = @($StartInfoCredentialKeys + @('arguments'))
$StartInfoProbeKeys = @($StartInfoRunnerKeys + @('redirectstandarderror', 'redirectstandardoutput'))
# The Phase 5 listener writes its own output files through cmd.exe
# redirection; the paths carry no cmd.exe metacharacter.
$RunnerArgumentsPattern = '^/d /s /c "run\.cmd 1>"[^"%^&|<>!\r\n\t]+" 2>"[^"%^&|<>!\r\n\t]+""$'
# Common parameters that bind a variable by name (about_CommonParameters).
$VariableBindingParameterNames = @('outvariable', 'errorvariable', 'warningvariable', 'informationvariable', 'pipelinevariable')
$VariableBindingParameterAliases = @('ov', 'ev', 'wv', 'iv', 'pv')

function Get-PlainVariableName {
    param($Node)

    if ($Node -isnot [System.Management.Automation.Language.VariableExpressionAst]) {
        return $null
    }
    if ($Node.Splatted) {
        return $null
    }
    $UserPath = $Node.VariablePath.UserPath
    if ($UserPath.IndexOf(':') -ge 0) {
        return $null
    }
    return $UserPath
}

function Get-DirectRootAssignment {
    param($Node)

    $Current = $Node.Parent
    if ($Current -is [System.Management.Automation.Language.CommandExpressionAst]) {
        if (-not [object]::ReferenceEquals($Current.Expression, $Node) -or $Current.Redirections.Count -ne 0) {
            return $null
        }
        $Current = $Current.Parent
    }
    if ($Current -is [System.Management.Automation.Language.PipelineAst]) {
        if ($Current.PipelineElements.Count -ne 1) {
            return $null
        }
        $Current = $Current.Parent
    }
    if ($Current -isnot [System.Management.Automation.Language.AssignmentStatementAst]) {
        return $null
    }
    if ($Current.Operator -ne [System.Management.Automation.Language.TokenKind]::Equals) {
        return $null
    }
    if ($RootStatements -notcontains $Current) {
        return $null
    }
    return $Current
}

function Test-PlainParameterElement {
    param($Element, [string]$Name)

    return (
        $Element -is [System.Management.Automation.Language.CommandParameterAst] -and
        $Element.ParameterName -ieq $Name -and
        $null -eq $Element.Argument
    )
}

# Returns the value expression of one -Property entry, or $null when the value
# is anything but a string constant, a plain variable, or a plain member read.
function Get-ProcessStartInfoValueExpression {
    param($Statement)

    $Element = $Statement
    if ($Element -is [System.Management.Automation.Language.PipelineAst]) {
        if ($Element.PipelineElements.Count -ne 1) {
            return $null
        }
        $Element = $Element.PipelineElements[0]
    }
    if ($Element -isnot [System.Management.Automation.Language.CommandExpressionAst]) {
        return $null
    }
    if ($Element.Redirections.Count -ne 0) {
        return $null
    }
    $Expression = $Element.Expression
    if ($Expression -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
        return $Expression
    }
    if ($Expression -is [System.Management.Automation.Language.VariableExpressionAst]) {
        if ($null -ne (Get-PlainVariableName -Node $Expression)) {
            return $Expression
        }
        return $null
    }
    if (
        $Expression -is [System.Management.Automation.Language.MemberExpressionAst] -and
        $Expression -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        -not $Expression.Static -and
        $Expression.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $null -ne (Get-PlainVariableName -Node $Expression.Expression)
    ) {
        return $Expression
    }
    return $null
}

function Test-BooleanLiteral {
    param($Expression, [bool]$Expected)

    $Name = Get-PlainVariableName -Node $Expression
    if ($Expected) {
        return ($Name -ieq 'true')
    }
    return ($Name -ieq 'false')
}

function Test-NonEmptyStringLiteral {
    param($Expression)

    return (
        $Expression -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        -not [string]::IsNullOrWhiteSpace($Expression.Value)
    )
}

function Test-VariableValue {
    param($Expression, [string]$Name)

    $ObservedName = Get-PlainVariableName -Node $Expression
    return ($null -ne $ObservedName -and $ObservedName -ieq $Name)
}

function Test-StringValue {
    param($Expression, [string]$Value)

    return (
        $Expression -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $Expression.Value -ieq $Value
    )
}

function Test-KeySet {
    param($Values, $ExpectedKeys)

    $Observed = (@($Values.Keys) | Sort-Object) -join ','
    $Expected = (@($ExpectedKeys) | Sort-Object) -join ','
    return ($Observed -ceq $Expected)
}

# The inline New-Object passed as the single argument of Process.Start.
function Get-InlineStartInfoCommand {
    param($InvokeNode)

    if ($null -eq $InvokeNode.Arguments -or $InvokeNode.Arguments.Count -ne 1) {
        return $null
    }
    $Paren = $InvokeNode.Arguments[0]
    if ($Paren -isnot [System.Management.Automation.Language.ParenExpressionAst]) {
        return $null
    }
    $Pipeline = $Paren.Pipeline
    if ($Pipeline -isnot [System.Management.Automation.Language.PipelineAst] -or $Pipeline.PipelineElements.Count -ne 1) {
        return $null
    }
    $Command = $Pipeline.PipelineElements[0]
    if ($Command -isnot [System.Management.Automation.Language.CommandAst] -or $Command.Redirections.Count -ne 0) {
        return $null
    }
    if ($Command.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown) {
        return $null
    }
    if ($Command.GetCommandName() -ine 'New-Object') {
        return $null
    }
    return $Command
}

function Test-ProcessStartInfoShape {
    param($CommandAst, [string]$LaunchName)

    $Elements = $CommandAst.CommandElements
    if ($Elements.Count -ne 5) {
        return $false
    }
    if (-not (Test-PlainParameterElement -Element $Elements[1] -Name 'TypeName')) {
        return $false
    }
    if (
        $Elements[2] -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $Elements[2].Value -ine 'System.Diagnostics.ProcessStartInfo'
    ) {
        return $false
    }
    if (-not (Test-PlainParameterElement -Element $Elements[3] -Name 'Property')) {
        return $false
    }
    if ($Elements[4] -isnot [System.Management.Automation.Language.HashtableAst]) {
        return $false
    }
    $Values = @{}
    foreach ($Pair in $Elements[4].KeyValuePairs) {
        $Key = $Pair.Item1
        if ($Key -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
            return $false
        }
        if ($ProcessStartInfoKeys -notcontains $Key.Value) {
            return $false
        }
        $KeyId = $Key.Value.ToLowerInvariant()
        if ($Values.ContainsKey($KeyId)) {
            return $false
        }
        $ValueExpression = Get-ProcessStartInfoValueExpression -Statement $Pair.Item2
        if ($null -eq $ValueExpression) {
            return $false
        }
        $Values[$KeyId] = $ValueExpression
    }

    # Per launch name and shape: exact key set and exact launch values.
    if ($LaunchName -ieq 'BridgeCredentialCheck') {
        if (-not (Test-KeySet -Values $Values -ExpectedKeys $StartInfoCredentialKeys)) {
            return $false
        }
        $ExpectedProfile = $false
        $ShapeValuesOk = (
            (Test-VariableValue -Expression $Values['filename'] -Name 'BridgeCredentialCheckPath') -and
            (Test-VariableValue -Expression $Values['workingdirectory'] -Name 'BridgeCredentialCheckDirectory')
        )
    }
    elseif ($LaunchName -ieq 'BridgeSecurityProbeChild') {
        if (-not (Test-KeySet -Values $Values -ExpectedKeys $StartInfoProbeKeys)) {
            return $false
        }
        $ExpectedProfile = $true
        $ShapeValuesOk = (
            (Test-StringValue -Expression $Values['filename'] -Value 'powershell.exe') -and
            (Test-VariableValue -Expression $Values['arguments'] -Name 'BridgeSecurityProbeArguments') -and
            (Test-VariableValue -Expression $Values['workingdirectory'] -Name 'BridgeRunnerRoot')
        )
    }
    elseif ($LaunchName -ieq 'BridgeChild') {
        $ExpectedProfile = $true
        if (Test-KeySet -Values $Values -ExpectedKeys $StartInfoProbeKeys) {
            $ShapeValuesOk = (
                (Test-StringValue -Expression $Values['filename'] -Value 'powershell.exe') -and
                (Test-VariableValue -Expression $Values['arguments'] -Name 'BridgeTargetProbeArguments') -and
                (Test-VariableValue -Expression $Values['workingdirectory'] -Name 'BridgeRunnerRoot')
            )
        }
        elseif (Test-KeySet -Values $Values -ExpectedKeys $StartInfoRunnerKeys) {
            $RunnerArguments = $Values['arguments']
            $ShapeValuesOk = (
                (Test-StringValue -Expression $Values['filename'] -Value 'cmd.exe') -and
                $RunnerArguments -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $RunnerArguments.Value -cmatch $RunnerArgumentsPattern -and
                (Test-VariableValue -Expression $Values['workingdirectory'] -Name 'BridgeRunnerRoot')
            )
        }
        else {
            return $false
        }
    }
    else {
        return $false
    }
    if (-not $ShapeValuesOk) {
        return $false
    }

    if (-not (Test-NonEmptyStringLiteral -Expression $Values['username'])) {
        return $false
    }
    if (-not (Test-NonEmptyStringLiteral -Expression $Values['domain'])) {
        return $false
    }
    $PasswordExpression = $Values['password']
    if (
        $PasswordExpression -isnot [System.Management.Automation.Language.MemberExpressionAst] -or
        $PasswordExpression.Member.Value -ine 'Password' -or
        -not (Test-VariableValue -Expression $PasswordExpression.Expression -Name 'BridgeTargetCredential')
    ) {
        return $false
    }
    if (-not (Test-BooleanLiteral -Expression $Values['useshellexecute'] -Expected $false)) {
        return $false
    }
    if (-not (Test-BooleanLiteral -Expression $Values['createnowindow'] -Expected $true)) {
        return $false
    }
    if (-not (Test-BooleanLiteral -Expression $Values['loaduserprofile'] -Expected $ExpectedProfile)) {
        return $false
    }
    foreach ($RedirectKey in @('redirectstandardoutput', 'redirectstandarderror')) {
        if ($Values.ContainsKey($RedirectKey) -and -not (Test-BooleanLiteral -Expression $Values[$RedirectKey] -Expected $true)) {
            return $false
        }
    }
    return $true
}

# Returns PROCESS_LAUNCH, PROCESS_CONTROL, READ, or $null for anything else.
function Get-AllowedInvokeMemberEffect {
    param($Node)

    if ($Node.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        return $null
    }
    $MemberName = $Node.Member.Value
    $ArgumentCount = 0
    if ($null -ne $Node.Arguments) {
        $ArgumentCount = $Node.Arguments.Count
    }

    if ($Node.Static) {
        if ($Node.Expression -isnot [System.Management.Automation.Language.TypeExpressionAst]) {
            return $null
        }
        if ($Node.Expression.TypeName.FullName -ine 'System.Diagnostics.Process') {
            return $null
        }
        if ($MemberName -ine 'Start' -or $ArgumentCount -ne 1) {
            return $null
        }
        $Assignment = Get-DirectRootAssignment -Node $Node
        if ($null -eq $Assignment) {
            return $null
        }
        $LeftName = Get-PlainVariableName -Node $Assignment.Left
        if ($null -eq $LeftName -or $ProcessLaunchNames -notcontains $LeftName) {
            return $null
        }
        $StartInfoCommand = Get-InlineStartInfoCommand -InvokeNode $Node
        if ($null -eq $StartInfoCommand) {
            return $null
        }
        if (-not (Test-ProcessStartInfoShape -CommandAst $StartInfoCommand -LaunchName $LeftName)) {
            return $null
        }
        return 'PROCESS_LAUNCH'
    }

    if ($ArgumentCount -ne 0) {
        return $null
    }
    $Target = $Node.Expression
    if ($MemberName -ieq 'ReadToEndAsync') {
        if (
            $Target -isnot [System.Management.Automation.Language.MemberExpressionAst] -or
            $Target -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
            $Target.Static -or
            $Target.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or
            @('StandardOutput', 'StandardError') -notcontains $Target.Member.Value
        ) {
            return $null
        }
        $Target = $Target.Expression
        $Effect = 'READ'
    }
    elseif ($MemberName -ieq 'WaitForExit') {
        $Effect = 'READ'
    }
    elseif ($MemberName -ieq 'Kill') {
        $Effect = 'PROCESS_CONTROL'
    }
    else {
        return $null
    }
    $TargetName = Get-PlainVariableName -Node $Target
    if ($null -eq $TargetName -or $ProcessLaunchNames -notcontains $TargetName) {
        return $null
    }
    return $Effect
}

# A New-Object is classified only as the inline start info of an allowed launch.
function Test-InlineStartInfoPosition {
    param($CommandAst)

    $Pipeline = $CommandAst.Parent
    if ($Pipeline -isnot [System.Management.Automation.Language.PipelineAst]) {
        return $false
    }
    $Paren = $Pipeline.Parent
    if ($Paren -isnot [System.Management.Automation.Language.ParenExpressionAst]) {
        return $false
    }
    $Invoke = $Paren.Parent
    if ($Invoke -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
        return $false
    }
    if ((Get-AllowedInvokeMemberEffect -Node $Invoke) -ne 'PROCESS_LAUNCH') {
        return $false
    }
    return [object]::ReferenceEquals((Get-InlineStartInfoCommand -InvokeNode $Invoke), $CommandAst)
}

# Broker-written target output (option A): a narrow family so Phase 5 need not
# allow FILESYSTEM_WRITE_MUTATION (which also covers Copy-Item).
function Test-OutputCaptureWriteShape {
    param($CommandAst)

    $Elements = $CommandAst.CommandElements
    if ($Elements.Count -ne 7 -or $CommandAst.Redirections.Count -ne 0) {
        return $false
    }
    if (
        $CommandAst.Parent -isnot [System.Management.Automation.Language.PipelineAst] -or
        $CommandAst.Parent.PipelineElements.Count -ne 1
    ) {
        return $false
    }
    $PathName = Get-PlainVariableName -Node $Elements[2]
    $ValueName = Get-PlainVariableName -Node $Elements[4]
    return (
        (Test-PlainParameterElement -Element $Elements[1] -Name 'LiteralPath') -and
        $null -ne $PathName -and
        $PathName -cmatch '^Bridge[A-Za-z]*Std(out|err)Path$' -and
        (Test-PlainParameterElement -Element $Elements[3] -Name 'Value') -and
        $null -ne $ValueName -and
        $ValueName -cmatch '^Bridge[A-Za-z]*Std(out|err)Text$' -and
        (Test-PlainParameterElement -Element $Elements[5] -Name 'Encoding') -and
        $Elements[6] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $Elements[6].Value -ieq 'UTF8'
    )
}

function Test-VariableBindingParameter {
    param($Element)

    if ($Element -isnot [System.Management.Automation.Language.CommandParameterAst]) {
        return $false
    }
    $ParameterName = $Element.ParameterName.ToLowerInvariant()
    if ($ParameterName.Length -eq 0) {
        return $false
    }
    if ($VariableBindingParameterAliases -contains $ParameterName) {
        return $true
    }
    foreach ($FullName in $VariableBindingParameterNames) {
        if ($FullName.StartsWith($ParameterName)) {
            return $true
        }
    }
    return $false
}

function Test-StartProcessCredential {
    param($CommandAst)

    foreach ($Element in $CommandAst.CommandElements) {
        if ($Element -is [System.Management.Automation.Language.VariableExpressionAst] -and $Element.Splatted) {
            return $true
        }
        if ($Element -is [System.Management.Automation.Language.CommandParameterAst]) {
            $ParameterName = $Element.ParameterName.ToLowerInvariant()
            if ($ParameterName -eq 'runas') {
                return $true
            }
            if ($ParameterName.Length -gt 0 -and 'credential'.StartsWith($ParameterName)) {
                return $true
            }
        }
    }
    return $false
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
        'convertfrom-json', 'select-object', 'where-object', 'get-acl'
    )) {
        continue
    }
    elseif ($LowerName -eq 'invoke-privatecigenerationretirement') {
        if (-not $ObservedEffects.Contains('GENERATION_RETIREMENT')) {
            $ObservedEffects.Add('GENERATION_RETIREMENT')
        }
    }
    elseif ($LowerName -eq 'python.exe') {
        $CommandText = $CommandAst.Extent.Text
        $IsGenerationRetirement = (
            $CommandText -match '(?i)^\s*python\.exe\s+[''"]C:\\Users\\c-admin\\[A-Za-z0-9_.-]+\\scripts\\retire_private_ci_generation\.py[''"]\s+--generation-root\s+\$BridgeGenerationRoot\s+--expected-generation\s+\$BridgeEnvironmentGeneration\s*$'
        )
        if ($IsGenerationRetirement) {
            if (-not $ObservedEffects.Contains('GENERATION_RETIREMENT')) {
                $ObservedEffects.Add('GENERATION_RETIREMENT')
            }
        }
        elseif (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    elseif ($LowerName -eq 'start-process') {
        if (-not $ObservedEffects.Contains('PROCESS_LAUNCH')) {
            $ObservedEffects.Add('PROCESS_LAUNCH')
        }
        if ((Test-StartProcessCredential -CommandAst $CommandAst) -and -not $ObservedEffects.Contains('START_PROCESS_CREDENTIAL_REJECTED')) {
            $ObservedEffects.Add('START_PROCESS_CREDENTIAL_REJECTED')
        }
    }
    elseif ($LowerName -eq 'new-object') {
        if (-not (Test-InlineStartInfoPosition -CommandAst $CommandAst) -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    elseif ($LowerName -eq 'set-content') {
        if (Test-OutputCaptureWriteShape -CommandAst $CommandAst) {
            if (-not $ObservedEffects.Contains('EVIDENCE_OUTPUT_WRITE')) {
                $ObservedEffects.Add('EVIDENCE_OUTPUT_WRITE')
            }
        }
        elseif (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
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
    elseif ($LowerName -eq 'invoke-cimmethod') {
        $CommandText = $CommandAst.Extent.Text
        if ($CommandText -notmatch '(?i)-MethodName\s+GetOwner\b') {
            if (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
                $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
            }
        }
    }
    elseif ($LowerName -in @('invoke-restmethod', 'invoke-webrequest', 'curl', 'wget')) {
        if (-not $ObservedEffects.Contains('HTTP_API_ACCESS')) {
            $ObservedEffects.Add('HTTP_API_ACCESS')
        }
    }
    elseif ($LowerName -eq 'gh.exe') {
        $CommandText = $CommandAst.Extent.Text
        $IsWorkflowDispatchRead = (
            $CommandText -match '(?i)^\s*gh\.exe\s+api\b' -and
            $CommandText -notmatch '(?i)--method\b' -and
            $CommandText -match '(?i)-H\s+[''"]X-GitHub-Api-Version:\s*2026-03-10[''"]' -and
            $CommandText -match '(?i)repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/workflows/[A-Za-z0-9_.-]+\.ya?ml/runs\?event=workflow_dispatch&branch=main&status=(queued|in_progress|requested|waiting|pending)&per_page=100'
        )
        $IsRunnerInventoryRead = (
            $CommandText -match '(?i)^\s*gh\.exe\s+api\b' -and
            $CommandText -notmatch '(?i)--method\b' -and
            $CommandText -match '(?i)-H\s+[''"]X-GitHub-Api-Version:\s*2026-03-10[''"]' -and
            $CommandText -match '(?i)repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runners\?per_page=100'
        )
        $IsPullRequestRead = (
            $CommandText -match '(?i)^\s*gh\.exe\s+api\b' -and
            $CommandText -notmatch '(?i)--method\b' -and
            $CommandText -match '(?i)-H\s+[''"]X-GitHub-Api-Version:\s*2026-03-10[''"]' -and
            $CommandText -match '(?i)repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pulls/[1-9][0-9]*[''"]?\s*$'
        )
        $IsMainRefRead = (
            $CommandText -match '(?i)^\s*gh\.exe\s+api\b' -and
            $CommandText -notmatch '(?i)--method\b' -and
            $CommandText -match '(?i)-H\s+[''"]X-GitHub-Api-Version:\s*2026-03-10[''"]' -and
            $CommandText -match '(?i)repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/git/ref/heads/main[''"]?\s*$'
        )
        $IsRunnerDeregistration = (
            $CommandText -match '(?i)^\s*gh\.exe\s+api\s+--method\s+DELETE\b' -and
            $CommandText -match '(?i)-H\s+[''"]X-GitHub-Api-Version:\s*2026-03-10[''"]' -and
            $CommandText -match '(?i)repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runners/[1-9][0-9]*[''"]?\s*$'
        )
        $IsWorkflowDispatch = (
            $CommandText -match '(?i)^\s*gh\.exe\s+api\s+--method\s+POST\b' -and
            $CommandText -match '(?i)-H\s+[''"]X-GitHub-Api-Version:\s*2026-03-10[''"]' -and
            $CommandText -match '(?i)repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/workflows/[A-Za-z0-9_.-]+\.ya?ml/dispatches' -and
            $CommandText -match '(?i)-f\s+[''"]ref=main[''"]' -and
            $CommandText -notmatch '(?i)return_run_details'
        )
        if (
            $IsWorkflowDispatchRead -or
            $IsRunnerInventoryRead -or
            $IsPullRequestRead -or
            $IsMainRefRead
        ) {
            if (-not $ObservedEffects.Contains('HTTP_API_ACCESS')) {
                $ObservedEffects.Add('HTTP_API_ACCESS')
            }
        }
        elseif ($IsRunnerDeregistration) {
            if (-not $ObservedEffects.Contains('RUNNER_DEREGISTRATION')) {
                $ObservedEffects.Add('RUNNER_DEREGISTRATION')
            }
        }
        elseif ($IsWorkflowDispatch) {
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
$UsedLaunchNames = New-Object System.Collections.Generic.List[string]
foreach ($InvokeMemberAst in $InvokeMemberAsts) {
    $InvokeEffect = Get-AllowedInvokeMemberEffect -Node $InvokeMemberAst
    if ($null -eq $InvokeEffect) {
        if (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
        continue
    }
    if ($InvokeEffect -ne 'READ' -and -not $ObservedEffects.Contains($InvokeEffect)) {
        $ObservedEffects.Add($InvokeEffect)
    }
    if ($InvokeMemberAst.Static) {
        $UsedLaunchName = Get-PlainVariableName -Node (Get-DirectRootAssignment -Node $InvokeMemberAst).Left
    }
    elseif ($InvokeMemberAst.Member.Value -ieq 'ReadToEndAsync') {
        $UsedLaunchName = Get-PlainVariableName -Node $InvokeMemberAst.Expression.Expression
    }
    else {
        $UsedLaunchName = Get-PlainVariableName -Node $InvokeMemberAst.Expression
    }
    foreach ($LaunchName in $ProcessLaunchNames) {
        if ($LaunchName -ieq $UsedLaunchName -and -not $UsedLaunchNames.Contains($LaunchName)) {
            $UsedLaunchNames.Add($LaunchName)
        }
    }
}

# A launch name that receives a classified method call must be bound exactly
# once, by the validated root Process.Start. Any other binding (assignment,
# scoped assignment, param, foreach, or a variable-binding common parameter,
# whose value may even be computed) is unknown. Rebinding through the
# Variable provider (Copy-Item/New-Item on variable:) is not detectable here;
# the canonical candidate comparison owns that.
if ($UsedLaunchNames.Count -gt 0) {
    $LaunchBindingCounts = @{}
    foreach ($LaunchName in $UsedLaunchNames) {
        $LaunchBindingCounts[$LaunchName] = 0
    }
    foreach ($AssignmentAst in $AssignmentAsts) {
        $AssignedNames = @($AssignmentAst.Left.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.VariableExpressionAst]
        }, $true) | ForEach-Object { Get-NormalizedVariableUserPath -UserPath $_.VariablePath.UserPath })
        if ($AssignmentAst.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $AssignedNames += Get-NormalizedVariableUserPath -UserPath $AssignmentAst.Left.VariablePath.UserPath
        }
        $TouchedLaunchName = $null
        foreach ($AssignedName in $AssignedNames) {
            foreach ($LaunchName in $UsedLaunchNames) {
                if ($AssignedName -ieq $LaunchName) {
                    $TouchedLaunchName = $LaunchName
                }
            }
        }
        if ($null -eq $TouchedLaunchName) {
            continue
        }
        $LeftName = Get-PlainVariableName -Node $AssignmentAst.Left
        $RightNode = $AssignmentAst.Right
        if ($RightNode -is [System.Management.Automation.Language.PipelineAst] -and $RightNode.PipelineElements.Count -eq 1) {
            $RightNode = $RightNode.PipelineElements[0]
        }
        if ($RightNode -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $RightNode = $RightNode.Expression
        }
        if (
            $null -ne $LeftName -and
            $LeftName -ieq $TouchedLaunchName -and
            $RightNode -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            (Get-AllowedInvokeMemberEffect -Node $RightNode) -eq 'PROCESS_LAUNCH'
        ) {
            $LaunchBindingCounts[$TouchedLaunchName] = [int]$LaunchBindingCounts[$TouchedLaunchName] + 1
        }
        elseif (-not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    foreach ($LaunchName in $UsedLaunchNames) {
        if ([int]$LaunchBindingCounts[$LaunchName] -ne 1 -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    foreach ($ForEachAst in $ForEachAsts) {
        if ($null -eq $ForEachAst.Variable) {
            continue
        }
        $ForEachName = Get-NormalizedVariableUserPath -UserPath $ForEachAst.Variable.VariablePath.UserPath
        if ($UsedLaunchNames -contains $ForEachName -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    foreach ($ParameterAst in $ParameterAsts) {
        $ParameterVariableName = Get-NormalizedVariableUserPath -UserPath $ParameterAst.Name.VariablePath.UserPath
        if ($UsedLaunchNames -contains $ParameterVariableName -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
            $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
        }
    }
    foreach ($CommandAst in $CommandAsts) {
        foreach ($Element in $CommandAst.CommandElements) {
            if ((Test-VariableBindingParameter -Element $Element) -and -not $ObservedEffects.Contains('DYNAMIC_OR_UNKNOWN_COMMAND')) {
                $ObservedEffects.Add('DYNAMIC_OR_UNKNOWN_COMMAND')
            }
        }
    }
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
        $ProcessStartRight = $AssignmentAst.Right
        if ($ProcessStartRight -is [System.Management.Automation.Language.PipelineAst] -and $ProcessStartRight.PipelineElements.Count -eq 1) {
            $ProcessStartRight = $ProcessStartRight.PipelineElements[0]
        }
        if ($ProcessStartRight -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $ProcessStartRight = $ProcessStartRight.Expression
        }
        if (
            $ProcessStartRight -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            (Get-AllowedInvokeMemberEffect -Node $ProcessStartRight) -eq 'PROCESS_LAUNCH'
        ) {
            $ChildProcessAssigned = $true
        }
        elseif ($StartProcessCommands.Count -eq 1) {
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
$AllIfAsts = @($Ast.FindAll({
    param($Node)
    $Node -is [System.Management.Automation.Language.IfStatementAst]
}, $true))

$ChildFailFastProven = $false
if ($ChildExitCodeProven) {
    foreach ($IfAst in $AllIfAsts) {
        $IfText = $IfAst.Extent.Text
        $ThrowAsts = @($IfAst.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.ThrowStatementAst]
        }, $true))
        if (
            $IfText -match '(?is)^\s*if\s*\(\s*\$BridgeChildExitCode\s*-ne\s*0\s*\)' -and
            $ThrowAsts.Count -gt 0
        ) {
            $ChildFailFastProven = $true
            break
        }
    }
}

$ErrorActionPreferenceStopAssigned = $false
foreach ($AssignmentAst in $AssignmentAsts) {
    if (
        $AssignmentAst.Left -isnot [System.Management.Automation.Language.VariableExpressionAst] -or
        ($RootStatements -notcontains $AssignmentAst)
    ) {
        continue
    }
    $LeftName = Get-NormalizedVariableUserPath -UserPath $AssignmentAst.Left.VariablePath.UserPath
    if ($LeftName -ine 'ErrorActionPreference') {
        continue
    }
    $RightText = $AssignmentAst.Right.Extent.Text.Trim()
    if ($RightText -match '(?i)^[''"]Stop[''"]$') {
        $ErrorActionPreferenceStopAssigned = $true
    }
}

function Get-EnclosingStatementContainer {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Node
    )

    $Current = $Node.Parent
    while ($null -ne $Current) {
        if (
            $Current -is [System.Management.Automation.Language.StatementBlockAst] -or
            $Current -is [System.Management.Automation.Language.NamedBlockAst]
        ) {
            return $Current
        }
        $Current = $Current.Parent
    }
    return $null
}

$NativeGuardRequiredCommands = New-Object System.Collections.Generic.List[object]
foreach ($CommandAst in $CommandAsts) {
    if ($CommandAst.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown) {
        continue
    }
    $NativeName = $CommandAst.GetCommandName()
    if ([string]::IsNullOrWhiteSpace($NativeName)) {
        continue
    }
    $NativeLowerName = $NativeName.ToLowerInvariant()
    $NativeLastSlash = $NativeLowerName.LastIndexOf('\')
    if ($NativeLastSlash -ge 0) {
        $NativeLowerName = $NativeLowerName.Substring($NativeLastSlash + 1)
    }
    if ($NativeLowerName -in @('gh.exe', 'icacls', 'icacls.exe', 'python.exe')) {
        $NativeGuardRequiredCommands.Add($CommandAst)
    }
}

$AllNativeCommandsGuarded = $true
foreach ($NativeCommandAst in $NativeGuardRequiredCommands) {
    $NativeContainer = Get-EnclosingStatementContainer -Node $NativeCommandAst
    if ($null -eq $NativeContainer) {
        $AllNativeCommandsGuarded = $false
        break
    }

    $NextNativeStart = [int]::MaxValue
    foreach ($OtherNativeCommandAst in $NativeGuardRequiredCommands) {
        if ($OtherNativeCommandAst -eq $NativeCommandAst) {
            continue
        }
        $OtherContainer = Get-EnclosingStatementContainer -Node $OtherNativeCommandAst
        if (-not [object]::ReferenceEquals($NativeContainer, $OtherContainer)) {
            continue
        }
        if (
            $OtherNativeCommandAst.Extent.StartOffset -gt $NativeCommandAst.Extent.StartOffset -and
            $OtherNativeCommandAst.Extent.StartOffset -lt $NextNativeStart
        ) {
            $NextNativeStart = $OtherNativeCommandAst.Extent.StartOffset
        }
    }

    $ExitAssignment = $null
    foreach ($AssignmentAst in $AssignmentAsts) {
        if ($AssignmentAst.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) {
            continue
        }
        $AssignmentContainer = Get-EnclosingStatementContainer -Node $AssignmentAst
        if (-not [object]::ReferenceEquals($NativeContainer, $AssignmentContainer)) {
            continue
        }
        if (
            $AssignmentAst.Extent.StartOffset -lt $NativeCommandAst.Extent.EndOffset -or
            $AssignmentAst.Extent.StartOffset -ge $NextNativeStart
        ) {
            continue
        }
        if ($AssignmentAst.Right.Extent.Text -notmatch '(?i)^\s*\$LASTEXITCODE\s*$') {
            continue
        }
        if (
            $null -eq $ExitAssignment -or
            $AssignmentAst.Extent.StartOffset -lt $ExitAssignment.Extent.StartOffset
        ) {
            $ExitAssignment = $AssignmentAst
        }
    }
    if ($null -eq $ExitAssignment) {
        $AllNativeCommandsGuarded = $false
        break
    }

    $ExitVariableName = Get-NormalizedVariableUserPath -UserPath $ExitAssignment.Left.VariablePath.UserPath
    if ($ExitVariableName -notmatch '(?i)^Bridge[A-Za-z0-9]*ExitCode$') {
        $AllNativeCommandsGuarded = $false
        break
    }
    $EscapedExitVariableName = [regex]::Escape($ExitVariableName)

    $GuardIf = $null
    foreach ($IfAst in $AllIfAsts) {
        $IfContainer = Get-EnclosingStatementContainer -Node $IfAst
        if (-not [object]::ReferenceEquals($NativeContainer, $IfContainer)) {
            continue
        }
        if (
            $IfAst.Extent.StartOffset -lt $ExitAssignment.Extent.EndOffset -or
            $IfAst.Extent.StartOffset -ge $NextNativeStart
        ) {
            continue
        }
        $IfText = $IfAst.Extent.Text
        $ThrowAsts = @($IfAst.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.ThrowStatementAst]
        }, $true))
        if (
            $IfText -match ("(?is)^\s*if\s*\(\s*\$" + $EscapedExitVariableName + "\s*-ne\s*0\s*\)") -and
            $ThrowAsts.Count -gt 0
        ) {
            if (
                $null -eq $GuardIf -or
                $IfAst.Extent.StartOffset -lt $GuardIf.Extent.StartOffset
            ) {
                $GuardIf = $IfAst
            }
        }
    }
    if ($null -eq $GuardIf) {
        $AllNativeCommandsGuarded = $false
        break
    }
}

$SynchronousFailFastProven = (
    -not $ChildProcessAssigned -and
    $ErrorActionPreferenceStopAssigned -and
    $NativeGuardRequiredCommands.Count -gt 0 -and
    $AllNativeCommandsGuarded
)
$FailFastProven = $ChildFailFastProven -or $SynchronousFailFastProven

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
    environment_generation = if ($Bindings.ContainsKey('BridgeEnvironmentGeneration')) { [string]$Bindings['BridgeEnvironmentGeneration'] } else { $null }
    generation_root = if ($Bindings.ContainsKey('BridgeGenerationRoot')) { [string]$Bindings['BridgeGenerationRoot'] } else { $null }
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
