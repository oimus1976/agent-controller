#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedPlanSha256,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedPlanBase64
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExpectedHost = 'WOBBUFFET'
$ExpectedIdentity = 'WOBBUFFET\c-admin'
$ObservedHost = $env:COMPUTERNAME
$ObservedIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

if ($ObservedHost -ine $ExpectedHost) {
    throw "Burned evidence archive host mismatch: expected=$ExpectedHost actual=$ObservedHost"
}
if ($ObservedIdentity -ine $ExpectedIdentity) {
    throw "Burned evidence archive identity mismatch: expected=$ExpectedIdentity actual=$ObservedIdentity"
}

try {
    $PlanBytes = [Convert]::FromBase64String($ExpectedPlanBase64)
}
catch {
    throw 'Reviewed archive plan base64 is invalid.'
}
$Hasher = [Security.Cryptography.SHA256]::Create()
try {
    $ObservedPlanSha256 = ([BitConverter]::ToString($Hasher.ComputeHash($PlanBytes))).Replace('-', '').ToLowerInvariant()
}
finally {
    $Hasher.Dispose()
}
if ($ObservedPlanSha256 -cne $ExpectedPlanSha256) {
    throw 'Reviewed archive plan SHA-256 mismatch before Python launch.'
}

try {
    $PlanJson = [Text.Encoding]::UTF8.GetString($PlanBytes)
    $Plan = $PlanJson | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw 'Reviewed archive plan JSON is invalid.'
}
$PythonPath = [string]$Plan.python_executable
$PythonSha256 = [string]$Plan.python_sha256
if ([string]::IsNullOrWhiteSpace($PythonPath) -or -not [IO.Path]::IsPathRooted($PythonPath)) {
    throw 'Reviewed archive Python path is not absolute.'
}
if ($PythonSha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Reviewed archive Python SHA-256 is invalid.'
}
$PythonItem = Get-Item -LiteralPath $PythonPath -Force -ErrorAction Stop
if ($PythonItem.PSIsContainer) {
    throw 'Reviewed archive Python path is not a file.'
}
if (($PythonItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Reviewed archive Python path is a reparse point.'
}

$ControllerRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $ControllerRoot -PathType Container)) {
    throw "Controller root missing: $ControllerRoot"
}

$PythonLock = New-Object IO.FileStream(
    $PythonPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read
)
try {
    $PythonHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $ObservedPythonSha256 = ([BitConverter]::ToString($PythonHasher.ComputeHash($PythonLock))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $PythonHasher.Dispose()
    }
    if ($ObservedPythonSha256 -cne $PythonSha256) {
        throw 'Reviewed archive Python executable SHA-256 mismatch.'
    }

    Push-Location $ControllerRoot
    try {
        & $PythonPath -m scripts.archive_private_ci_burned_evidence apply-internal --expected-plan-sha256 $ExpectedPlanSha256 --expected-plan-base64 $ExpectedPlanBase64
        $ChildExitCode = $LASTEXITCODE
        if ($ChildExitCode -ne 0) {
            throw "Burned evidence archive apply failed with exit=$ChildExitCode"
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    $PythonLock.Dispose()
}

Write-Output 'BURNED_CANONICAL_ARCHIVE_UAC_BRIDGE_PASS'
