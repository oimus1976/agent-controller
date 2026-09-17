#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedPlanSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedHost = 'WOBBUFFET'
$ExpectedIdentity = 'WOBBUFFET\c-admin'
$EvidenceRoot = 'C:\Users\Public\Documents\agent-controller-handoff'
$PlanPath = Join-Path $EvidenceRoot 'issue217-live-registration-plan.json'
$ApprovalPath = Join-Path $EvidenceRoot ("issue216-live-registration-approval-{0}.json" -f $ExpectedPlanSha256)
$ApprovalSchema = 'agent-controller.private-ci-human-approval.v1'

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $CurrentIdentity
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Human approval issuer must run elevated through the Windows UAC boundary.'
}

$ObservedHost = (hostname.exe).Trim()
$ObservedIdentity = (whoami.exe).Trim()
if ($ObservedHost -ine $ExpectedHost) {
    throw "Approval issuer host mismatch: $ObservedHost"
}
if ($ObservedIdentity -ine $ExpectedIdentity) {
    throw "Approval issuer identity mismatch: $ObservedIdentity"
}
if (-not (Test-Path -LiteralPath $PlanPath -PathType Leaf)) {
    throw "Reviewed plan is missing: $PlanPath"
}
if (Test-Path -LiteralPath $ApprovalPath) {
    throw "Approval artifact already exists: $ApprovalPath"
}

$ActualPlanSha256 = (Get-FileHash -LiteralPath $PlanPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ActualPlanSha256 -cne $ExpectedPlanSha256) {
    throw "Reviewed plan SHA-256 mismatch: expected=$ExpectedPlanSha256 actual=$ActualPlanSha256"
}

Add-Type -AssemblyName PresentationFramework
$Message = @"
Authorize exactly one #216 live runner-registration apply for this reviewed plan?

Plan SHA-256:
$ExpectedPlanSha256

This approval does not dispatch a workflow or execute target repository code.
Select Yes only if you reviewed this exact digest.
"@
$Decision = [System.Windows.MessageBox]::Show(
    $Message,
    '#216 Private-CI Human Authorization',
    [System.Windows.MessageBoxButton]::YesNo,
    [System.Windows.MessageBoxImage]::Warning,
    [System.Windows.MessageBoxResult]::No
)
if ($Decision -ne [System.Windows.MessageBoxResult]::Yes) {
    throw 'Human approval was not granted.'
}

$Payload = [ordered]@{
    schema = $ApprovalSchema
    plan_sha256 = $ExpectedPlanSha256
    host = $ExpectedHost
    approver_identity = $ExpectedIdentity
    approved_at = (Get-Date).ToUniversalTime().ToString('o')
}
$Json = ($Payload | ConvertTo-Json -Compress) + "`n"
$Utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$Bytes = $Utf8NoBom.GetBytes($Json)

$Stream = [System.IO.File]::Open(
    $ApprovalPath,
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

$SystemSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
$AdministratorsSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
$UsersSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-545'
$Acl = New-Object -TypeName Security.AccessControl.FileSecurity
$Acl.SetAccessRuleProtection($true, $false)
$Acl.SetOwner($AdministratorsSid)
$NoneInheritance = [Security.AccessControl.InheritanceFlags]::None
$NonePropagation = [Security.AccessControl.PropagationFlags]::None
$Allow = [Security.AccessControl.AccessControlType]::Allow
$SystemRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $SystemSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)
$AdministratorsRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $AdministratorsSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)
$UsersRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $UsersSid,
    [Security.AccessControl.FileSystemRights]::ReadAndExecute,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)
$Acl.AddAccessRule($SystemRule)
$Acl.AddAccessRule($AdministratorsRule)
$Acl.AddAccessRule($UsersRule)
Set-Acl -LiteralPath $ApprovalPath -AclObject $Acl

$Persisted = [System.IO.File]::ReadAllBytes($ApprovalPath)
$ExpectedHasher = New-Object -TypeName Security.Cryptography.SHA256Managed
$PersistedHasher = New-Object -TypeName Security.Cryptography.SHA256Managed
try {
    $ExpectedHash = [BitConverter]::ToString($ExpectedHasher.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    $PersistedHash = [BitConverter]::ToString($PersistedHasher.ComputeHash($Persisted)).Replace('-', '').ToLowerInvariant()
}
finally {
    $ExpectedHasher.Dispose()
    $PersistedHasher.Dispose()
}
if ($PersistedHash -cne $ExpectedHash) {
    throw 'Approval artifact changed during protected publication.'
}

$PersistedAcl = Get-Acl -LiteralPath $ApprovalPath
if (-not $PersistedAcl.AreAccessRulesProtected) {
    throw 'Approval artifact ACL inheritance protection failed.'
}

Write-Output 'HUMAN_APPROVAL_ISSUED'
Write-Output ("plan_sha256={0}" -f $ExpectedPlanSha256)
Write-Output ("approval_path={0}" -f $ApprovalPath)
Write-Output ("approval_sha256={0}" -f $PersistedHash)
