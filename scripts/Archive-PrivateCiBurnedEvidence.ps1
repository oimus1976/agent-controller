#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExpectedPlanSha256 = '__EXPECTED_PLAN_SHA256__'
$PlanEnvironmentName = 'AGENT_CONTROLLER_ARCHIVE_PLAN_BASE64'
$ExpectedHost = 'WOBBUFFET'
$ExpectedIdentity = 'WOBBUFFET\c-admin'
$ExpectedSourcePaths = @(
    'scripts/Archive-PrivateCiBurnedEvidence.ps1',
    'scripts/archive_private_ci_burned_evidence.py',
    'agent_controller/__init__.py',
    'agent_controller/private_ci_burned_evidence_archive.py',
    'agent_controller/private_ci_windows_atomic_archive.py'
)

function Get-StreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)
    $OriginalPosition = $Stream.Position
    $Stream.Position = 0
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Hasher.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $Hasher.Dispose()
        $Stream.Position = $OriginalPosition
    }
}

function Set-PrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $AdministratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $SystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $Acl = New-Object Security.AccessControl.DirectorySecurity
    $Acl.SetAccessRuleProtection($true, $false)
    $Acl.SetOwner($AdministratorsSid)
    $Inheritance = ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $Propagation = [Security.AccessControl.PropagationFlags]::None
    $Allow = [Security.AccessControl.AccessControlType]::Allow
    $Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($AdministratorsSid,[Security.AccessControl.FileSystemRights]::FullControl,$Inheritance,$Propagation,$Allow)))
    $Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SystemSid,[Security.AccessControl.FileSystemRights]::FullControl,$Inheritance,$Propagation,$Allow)))
    Set-Acl -LiteralPath $LiteralPath -AclObject $Acl
}

function Assert-PlainDirectory {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $Item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if (-not $Item.PSIsContainer) { throw "Expected directory: $LiteralPath" }
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Directory is a reparse point: $LiteralPath" }
}

$ObservedHost = [Environment]::MachineName
$ObservedIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($ObservedHost -ine $ExpectedHost) { throw "Burned evidence archive host mismatch: expected=$ExpectedHost actual=$ObservedHost" }
if ($ObservedIdentity -ine $ExpectedIdentity) { throw "Burned evidence archive identity mismatch: expected=$ExpectedIdentity actual=$ObservedIdentity" }
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Burned evidence archive bootstrap is not elevated.' }

$ExpectedPlanBase64 = [Environment]::GetEnvironmentVariable($PlanEnvironmentName,[EnvironmentVariableTarget]::Process)
if ([string]::IsNullOrWhiteSpace($ExpectedPlanBase64)) { throw 'Reviewed archive plan environment payload is missing.' }
[Environment]::SetEnvironmentVariable($PlanEnvironmentName,$null,[EnvironmentVariableTarget]::Process)

try { $PlanBytes = [Convert]::FromBase64String($ExpectedPlanBase64) } catch { throw 'Reviewed archive plan base64 is invalid.' }
$PlanStream = New-Object IO.MemoryStream(,$PlanBytes)
try { $ObservedPlanSha256 = Get-StreamSha256 -Stream $PlanStream } finally { $PlanStream.Dispose() }
if ($ObservedPlanSha256 -cne $ExpectedPlanSha256) { throw 'Reviewed archive plan SHA-256 mismatch before snapshot.' }
try { $PlanJson = [Text.Encoding]::UTF8.GetString($PlanBytes); $Plan = $PlanJson | ConvertFrom-Json -ErrorAction Stop } catch { throw 'Reviewed archive plan JSON is invalid.' }

$PythonPath = [string]$Plan.python_executable
$PythonSha256 = [string]$Plan.python_sha256
$ControllerRoot = [string]$Plan.controller_tree
$PlanSources = @($Plan.controller_sources)
if ([string]::IsNullOrWhiteSpace($PythonPath) -or -not [IO.Path]::IsPathRooted($PythonPath)) { throw 'Reviewed archive Python path is not absolute.' }
if ($PythonSha256 -notmatch '^[0-9a-f]{64}$') { throw 'Reviewed archive Python SHA-256 is invalid.' }
if ([string]::IsNullOrWhiteSpace($ControllerRoot) -or -not [IO.Path]::IsPathRooted($ControllerRoot)) { throw 'Reviewed controller root is not absolute.' }
Assert-PlainDirectory -LiteralPath $ControllerRoot
if ($PlanSources.Count -ne $ExpectedSourcePaths.Count) { throw 'Reviewed controller source count mismatch.' }

$PythonItem = Get-Item -LiteralPath $PythonPath -Force -ErrorAction Stop
if ($PythonItem.PSIsContainer) { throw 'Reviewed archive Python path is not a file.' }
if (($PythonItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reviewed archive Python path is a reparse point.' }

$SourceLocks = New-Object Collections.Generic.List[IO.FileStream]
$SnapshotLocks = New-Object Collections.Generic.List[IO.FileStream]
$PythonLock = $null
$SnapshotRoot = $null

try {
    $PythonLock = New-Object IO.FileStream($PythonPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if ((Get-StreamSha256 -Stream $PythonLock) -cne $PythonSha256) { throw 'Reviewed archive Python executable SHA-256 mismatch.' }

    $CommonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($CommonData)) { throw 'Common application data path is unavailable.' }
    $BootstrapParent = Join-Path $CommonData 'agent-controller-private-ci-archive-bootstrap'
    if (-not (Test-Path -LiteralPath $BootstrapParent)) { [IO.Directory]::CreateDirectory($BootstrapParent) | Out-Null }
    Assert-PlainDirectory -LiteralPath $BootstrapParent
    Set-PrivateDirectoryAcl -LiteralPath $BootstrapParent

    $SnapshotName = 'snapshot-' + $ExpectedPlanSha256.Substring(0,16) + '-' + [Guid]::NewGuid().ToString('N')
    $SnapshotRoot = Join-Path $BootstrapParent $SnapshotName
    [IO.Directory]::CreateDirectory($SnapshotRoot) | Out-Null
    Assert-PlainDirectory -LiteralPath $SnapshotRoot
    Set-PrivateDirectoryAcl -LiteralPath $SnapshotRoot

    for ($Index = 0; $Index -lt $ExpectedSourcePaths.Count; $Index++) {
        $ExpectedRelative = $ExpectedSourcePaths[$Index]
        $Binding = $PlanSources[$Index]
        $ObservedRelative = [string]$Binding.relative_path
        if ($ObservedRelative -cne $ExpectedRelative) { throw "Reviewed controller source path mismatch: $ObservedRelative" }
        $ExpectedSourceSha = [string]$Binding.sha256
        $ExpectedSourceSize = [Int64]$Binding.size
        if ($ExpectedSourceSha -notmatch '^[0-9a-f]{64}$') { throw "Reviewed controller source SHA invalid: $ExpectedRelative" }
        if ($ExpectedSourceSize -lt 0) { throw "Reviewed controller source size invalid: $ExpectedRelative" }

        $SourcePath = Join-Path $ControllerRoot ($ExpectedRelative -replace '/', '\')
        $SourceItem = Get-Item -LiteralPath $SourcePath -Force -ErrorAction Stop
        if ($SourceItem.PSIsContainer) { throw "Reviewed controller source is directory: $ExpectedRelative" }
        if (($SourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reviewed controller source is reparse point: $ExpectedRelative" }
        if ([Int64]$SourceItem.Length -ne $ExpectedSourceSize) { throw "Reviewed controller source size mismatch: $ExpectedRelative" }
        $SourceLock = New-Object IO.FileStream($SourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $SourceLocks.Add($SourceLock)
        if ((Get-StreamSha256 -Stream $SourceLock) -cne $ExpectedSourceSha) { throw "Reviewed controller source SHA mismatch: $ExpectedRelative" }

        if ($ExpectedRelative -eq 'scripts/Archive-PrivateCiBurnedEvidence.ps1') { continue }
        $DestinationPath = Join-Path $SnapshotRoot ($ExpectedRelative -replace '/', '\')
        $DestinationParent = Split-Path -Parent $DestinationPath
        [IO.Directory]::CreateDirectory($DestinationParent) | Out-Null
        Assert-PlainDirectory -LiteralPath $DestinationParent
        $DestinationLock = New-Object IO.FileStream($DestinationPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
        $SnapshotLocks.Add($DestinationLock)
        $SourceLock.Position = 0
        $DestinationLock.Position = 0
        $SourceLock.CopyTo($DestinationLock)
        $DestinationLock.Flush($true)
        if ($DestinationLock.Length -ne $ExpectedSourceSize) { throw "Snapshot source size mismatch: $ExpectedRelative" }
        if ((Get-StreamSha256 -Stream $DestinationLock) -cne $ExpectedSourceSha) { throw "Snapshot source SHA mismatch: $ExpectedRelative" }
    }

    $Loader = 'import runpy,sys; root=sys.argv.pop(1); sys.path.insert(0,root); runpy.run_path(root + r"\scripts\archive_private_ci_burned_evidence.py", run_name="__main__")'
    & $PythonPath -I -S -B -c $Loader $SnapshotRoot apply-internal --expected-plan-sha256 $ExpectedPlanSha256 --expected-plan-base64 $ExpectedPlanBase64
    $ChildExitCode = $LASTEXITCODE
    if ($ChildExitCode -ne 0) { throw "Burned evidence archive apply failed with exit=$ChildExitCode" }
}
finally {
    for ($Index = $SnapshotLocks.Count - 1; $Index -ge 0; $Index--) { $SnapshotLocks[$Index].Dispose() }
    for ($Index = $SourceLocks.Count - 1; $Index -ge 0; $Index--) { $SourceLocks[$Index].Dispose() }
    if ($null -ne $PythonLock) { $PythonLock.Dispose() }
    if ($null -ne $SnapshotRoot -and (Test-Path -LiteralPath $SnapshotRoot)) { Remove-Item -LiteralPath $SnapshotRoot -Recurse -Force }
}

Write-Output 'BURNED_CANONICAL_ARCHIVE_UAC_BRIDGE_PASS'
