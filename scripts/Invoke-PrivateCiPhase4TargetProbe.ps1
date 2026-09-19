#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHost,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedIdentity,

    [Parameter(Mandatory = $true)]
    [string]$AuthorityMarkerPath,

    [Parameter(Mandatory = $true)]
    [string]$ResultPath,

    [Parameter(Mandatory = $true)]
    [string]$TrustedGhPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ObservedHost = [string](hostname.exe)
$ObservedIdentity = [string](whoami.exe)
if ($ObservedHost.Trim() -ine $ExpectedHost) {
    throw "target probe host mismatch: $ObservedHost"
}
if ($ObservedIdentity.Trim() -ine $ExpectedIdentity) {
    throw "target probe identity mismatch: $ObservedIdentity"
}

$GroupText = (& whoami.exe /groups /fo csv /nh | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw 'target probe group readback failed'
}
if ($GroupText -match 'S-1-5-32-544') {
    throw 'target identity carries local Administrators SID'
}
if ($GroupText -match 'S-1-16-12288') {
    throw 'target identity unexpectedly has high integrity'
}

$ForbiddenEnvironment = @(
    Get-ChildItem Env: |
        Where-Object {
            $_.Name -match '^(GH_TOKEN|GITHUB_TOKEN|ACTIONS_RUNNER_INPUT_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY)$' -or
            $_.Name -match '^(AGENT_CONTROLLER|PRIVATE_CI).*(HMAC|KEY|SECRET|TOKEN|AUTH)'
        }
)
if ($ForbiddenEnvironment.Count -ne 0) {
    $Names = ($ForbiddenEnvironment | Select-Object -ExpandProperty Name) -join ','
    throw "target environment contains forbidden authority variables: $Names"
}

$BrokerCredentialRoots = @(
    'C:\Users\c-admin\.ssh',
    'C:\Users\c-admin\.aws',
    'C:\Users\c-admin\.azure',
    'C:\Users\c-admin\.gemini',
    'C:\Users\c-admin\.codex',
    'C:\Users\c-admin\.config\gh',
    'C:\Users\c-admin\AppData\Roaming\GitHub CLI'
)
foreach ($CredentialRoot in $BrokerCredentialRoots) {
    try {
        Get-ChildItem -LiteralPath $CredentialRoot -Force -ErrorAction Stop | Out-Null
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        continue
    }
    catch [System.UnauthorizedAccessException] {
        continue
    }
    throw "target identity can enumerate broker credential root: $CredentialRoot"
}

if (-not (Test-Path -LiteralPath $TrustedGhPath -PathType Leaf)) {
    throw "trusted gh executable missing: $TrustedGhPath"
}
& $TrustedGhPath auth status --hostname github.com *> $null
if ($LASTEXITCODE -eq 0) {
    throw 'target identity unexpectedly has usable gh authentication'
}

if (-not (Test-Path -LiteralPath $AuthorityMarkerPath -PathType Leaf)) {
    throw "protected authority marker missing: $AuthorityMarkerPath"
}
$AuthorityWriteDenied = $false
$Stream = $null
try {
    $Stream = [System.IO.File]::Open(
        $AuthorityMarkerPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
}
catch [System.UnauthorizedAccessException] {
    $AuthorityWriteDenied = $true
}
finally {
    if ($null -ne $Stream) {
        $Stream.Dispose()
    }
}
if (-not $AuthorityWriteDenied) {
    throw 'target identity can acquire write access to protected authority marker'
}

$ResultDirectory = Split-Path -Parent $ResultPath
if (-not (Test-Path -LiteralPath $ResultDirectory -PathType Container)) {
    throw "target probe result directory missing: $ResultDirectory"
}

$Payload = [ordered]@{
    schema = 'agent-controller.private-ci-phase4-target-probe.v1'
    status = 'TARGET_PROBE_PASS'
    host = $ObservedHost.Trim()
    identity = $ObservedIdentity.Trim()
    admin_sid_present = $false
    high_integrity_present = $false
    forbidden_environment_count = 0
    broker_credential_roots_readable = 0
    gh_authenticated = $false
    authority_marker_write_denied = $true
}
$Json = ($Payload | ConvertTo-Json -Compress) + "`n"
$Utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
[System.IO.File]::WriteAllText($ResultPath, $Json, $Utf8NoBom)

Write-Output 'TARGET_PROBE_PASS'
