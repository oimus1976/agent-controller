#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedPlanSha256
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

$ControllerRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $ControllerRoot -PathType Container)) {
    throw "Controller root missing: $ControllerRoot"
}

Push-Location $ControllerRoot
try {
    & python.exe -m scripts.archive_private_ci_burned_evidence apply-internal --expected-plan-sha256 $ExpectedPlanSha256
    $ChildExitCode = $LASTEXITCODE
    if ($ChildExitCode -ne 0) {
        throw "Burned evidence archive apply failed with exit=$ChildExitCode"
    }
}
finally {
    Pop-Location
}

Write-Output 'BURNED_CANONICAL_ARCHIVE_UAC_BRIDGE_PASS'
