#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedHandoffSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedHost = 'WOBBUFFET'
$ExpectedIdentity = 'WOBBUFFET\c-admin'
$EvidenceRoot = 'C:\Users\Public\Documents\agent-controller-handoff'
$PendingPath = Join-Path $EvidenceRoot 'issue225-registration-handoff.pending.json'
$CanonicalPath = Join-Path $EvidenceRoot 'issue225-registration-handoff.json'

function Assert-NotReparsePoint {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        throw "Path is missing before reparse validation: $LiteralPath"
    }
    $Item = Get-Item -LiteralPath $LiteralPath -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse point is not allowed at registration handoff publication boundary: $LiteralPath"
    }
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $Identity
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Registration handoff publisher must run elevated through the Windows UAC boundary.'
}

$ObservedHost = (hostname.exe).Trim()
$ObservedIdentity = (whoami.exe).Trim()
if ($ObservedHost -ine $ExpectedHost) {
    throw "Registration handoff publisher host mismatch: $ObservedHost"
}
if ($ObservedIdentity -ine $ExpectedIdentity) {
    throw "Registration handoff publisher identity mismatch: $ObservedIdentity"
}

if (-not (Test-Path -LiteralPath $PendingPath -PathType Leaf)) {
    throw "Pending registration handoff is missing: $PendingPath"
}
Assert-NotReparsePoint -LiteralPath $PendingPath
if (Test-Path -LiteralPath $CanonicalPath) {
    throw "Canonical registration handoff already exists: $CanonicalPath"
}

$ObservedSha = (Get-FileHash -LiteralPath $PendingPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ObservedSha -cne $ExpectedHandoffSha256) {
    throw "Pending registration handoff SHA-256 mismatch."
}

$Bytes = [System.IO.File]::ReadAllBytes($PendingPath)
$Stream = [System.IO.File]::Open(
    $CanonicalPath,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
)
try {
    $Stream.Write($Bytes, 0, $Bytes.Length)
    $Stream.Flush($true)
}
finally {
    $Stream.Dispose()
}

Assert-NotReparsePoint -LiteralPath $CanonicalPath

$SystemSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
$AdministratorsSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
$UsersSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-545'
$Acl = New-Object -TypeName Security.AccessControl.FileSecurity
$Acl.SetAccessRuleProtection($true, $false)
$Acl.SetOwner($AdministratorsSid)
$NoneInheritance = [Security.AccessControl.InheritanceFlags]::None
$NonePropagation = [Security.AccessControl.PropagationFlags]::None
$Allow = [Security.AccessControl.AccessControlType]::Allow
$Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $SystemSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)))
$Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $AdministratorsSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)))
$Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $UsersSid,
    [Security.AccessControl.FileSystemRights]::ReadAndExecute,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)))
Set-Acl -LiteralPath $CanonicalPath -AclObject $Acl

$PersistedSha = (Get-FileHash -LiteralPath $CanonicalPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($PersistedSha -cne $ExpectedHandoffSha256) {
    throw 'Canonical registration handoff changed during protected publication.'
}
$PersistedAcl = Get-Acl -LiteralPath $CanonicalPath
if (-not $PersistedAcl.AreAccessRulesProtected) {
    throw 'Canonical registration handoff ACL inheritance protection failed.'
}

Write-Output 'REGISTRATION_HANDOFF_PROTECTED'
Write-Output ("handoff_path={0}" -f $CanonicalPath)
Write-Output ("handoff_sha256={0}" -f $PersistedSha)
