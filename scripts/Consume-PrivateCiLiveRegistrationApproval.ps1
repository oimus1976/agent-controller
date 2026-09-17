#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$PlanSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$Phase0Sha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ApprovalSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedHost = 'WOBBUFFET'
$ExpectedIdentity = 'WOBBUFFET\c-admin'
$EvidenceRoot = 'C:\Users\Public\Documents\agent-controller-handoff'
$AuthorityRoot = 'C:\ProgramData\agent-controller-private-ci-authority'
$PlanPath = Join-Path $EvidenceRoot 'issue217-live-registration-plan.json'
$Phase0Path = Join-Path $EvidenceRoot 'issue216-phase0-canonical.json'
$ApprovalPath = Join-Path $EvidenceRoot ("issue216-live-registration-approval-{0}.json" -f $PlanSha256)
$MarkerPath = Join-Path $AuthorityRoot ("issue217-live-registration-{0}.consumed.json" -f $PlanSha256)
$MarkerSchema = 'agent-controller.private-ci-live-registration-consumed.v2'

$SystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$AdministratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$UsersSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
$TrustedMutatingSids = @($SystemSid.Value, $AdministratorsSid.Value)
$MutationMask = (
    [Security.AccessControl.FileSystemRights]::WriteData -bor
    [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
    [Security.AccessControl.FileSystemRights]::Modify -bor
    [Security.AccessControl.FileSystemRights]::FullControl
)

function Test-ProtectedAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $Acl = Get-Acl -LiteralPath $LiteralPath
    if (-not $Acl.AreAccessRulesProtected) {
        throw "ACL inheritance is not protected: $LiteralPath"
    }

    $Owner = New-Object Security.Principal.NTAccount($Acl.Owner)
    $OwnerSid = $Owner.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($TrustedMutatingSids -notcontains $OwnerSid) {
        throw "ACL owner is not trusted: $LiteralPath owner=$OwnerSid"
    }

    $ObservedTrustedMutators = @{}
    foreach ($Rule in $Acl.Access) {
        if ($Rule.IsInherited) {
            throw "ACL contains inherited rule: $LiteralPath"
        }
        $RuleSid = $Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $CanMutate = (($Rule.FileSystemRights -band $MutationMask) -ne 0)
        if (
            $Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $CanMutate
        ) {
            if ($TrustedMutatingSids -notcontains $RuleSid) {
                throw "ACL grants mutation to untrusted principal: $LiteralPath sid=$RuleSid"
            }
            $ObservedTrustedMutators[$RuleSid] = $true
        }
    }

    foreach ($RequiredSid in $TrustedMutatingSids) {
        if (-not $ObservedTrustedMutators.ContainsKey($RequiredSid)) {
            throw "ACL missing trusted mutating principal: $LiteralPath sid=$RequiredSid"
        }
    }
}

function New-ProtectedAuthorityDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    if (Test-Path -LiteralPath $LiteralPath) {
        if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
            throw "Authority path exists but is not a directory: $LiteralPath"
        }
        Test-ProtectedAcl -LiteralPath $LiteralPath
        return
    }

    $Parent = Split-Path -Parent $LiteralPath
    if (-not (Test-Path -LiteralPath $Parent -PathType Container)) {
        throw "Authority parent is missing: $Parent"
    }

    $DirectoryAcl = New-Object Security.AccessControl.DirectorySecurity
    $DirectoryAcl.SetAccessRuleProtection($true, $false)
    $DirectoryAcl.SetOwner($AdministratorsSid)
    $ContainerInherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit
    $ObjectInherit = [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $InheritFlags = $ContainerInherit -bor $ObjectInherit
    $NonePropagation = [Security.AccessControl.PropagationFlags]::None
    $Allow = [Security.AccessControl.AccessControlType]::Allow
    $DirectoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $SystemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $InheritFlags,
        $NonePropagation,
        $Allow
    )))
    $DirectoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $AdministratorsSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $InheritFlags,
        $NonePropagation,
        $Allow
    )))
    $DirectoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $UsersSid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $InheritFlags,
        $NonePropagation,
        $Allow
    )))

    New-Item -ItemType Directory -Path $LiteralPath | Out-Null
    Set-Acl -LiteralPath $LiteralPath -AclObject $DirectoryAcl
    Test-ProtectedAcl -LiteralPath $LiteralPath
}

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Consumption helper must run elevated through the Windows UAC boundary.'
}

$ObservedHost = (hostname.exe).Trim()
$ObservedIdentity = (whoami.exe).Trim()
if ($ObservedHost -ine $ExpectedHost) {
    throw "Consumption helper host mismatch: $ObservedHost"
}
if ($ObservedIdentity -ine $ExpectedIdentity) {
    throw "Consumption helper identity mismatch: $ObservedIdentity"
}

foreach ($RequiredPath in @($PlanPath, $Phase0Path, $ApprovalPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Required authority artifact is missing: $RequiredPath"
    }
}

$ObservedPlanSha = (Get-FileHash -LiteralPath $PlanPath -Algorithm SHA256).Hash.ToLowerInvariant()
$ObservedPhase0Sha = (Get-FileHash -LiteralPath $Phase0Path -Algorithm SHA256).Hash.ToLowerInvariant()
$ObservedApprovalSha = (Get-FileHash -LiteralPath $ApprovalPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ObservedPlanSha -cne $PlanSha256) {
    throw 'Consumption plan SHA-256 mismatch.'
}
if ($ObservedPhase0Sha -cne $Phase0Sha256) {
    throw 'Consumption Phase 0 SHA-256 mismatch.'
}
if ($ObservedApprovalSha -cne $ApprovalSha256) {
    throw 'Consumption approval SHA-256 mismatch.'
}

$Approval = Get-Content -LiteralPath $ApprovalPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Approval.schema -cne 'agent-controller.private-ci-human-approval.v1') {
    throw 'Consumption approval schema mismatch.'
}
if ($Approval.plan_sha256 -cne $PlanSha256) {
    throw 'Consumption approval plan mismatch.'
}
if ($Approval.host -cne $ExpectedHost) {
    throw 'Consumption approval host mismatch.'
}
if ($Approval.approver_identity -cne $ExpectedIdentity) {
    throw 'Consumption approval identity mismatch.'
}
$ApprovedAt = [DateTimeOffset]::Parse($Approval.approved_at)
$Now = [DateTimeOffset]::UtcNow
$AgeSeconds = ($Now - $ApprovedAt.ToUniversalTime()).TotalSeconds
if ($AgeSeconds -lt -30 -or $AgeSeconds -gt 900) {
    throw 'Consumption approval freshness invalid.'
}
Test-ProtectedAcl -LiteralPath $ApprovalPath

New-ProtectedAuthorityDirectory -LiteralPath $AuthorityRoot
if (Test-Path -LiteralPath $MarkerPath) {
    throw 'Live registration approval has already been consumed.'
}

$Payload = [ordered]@{
    schema = $MarkerSchema
    plan_sha256 = $PlanSha256
    phase0_evidence_sha256 = $Phase0Sha256
    human_approval_sha256 = $ApprovalSha256
    consumed_at = (Get-Date).ToUniversalTime().ToString('o')
}
$Json = ($Payload | ConvertTo-Json -Compress) + "`n"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$Bytes = $Utf8NoBom.GetBytes($Json)

$Stream = [System.IO.File]::Open(
    $MarkerPath,
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

$FileAcl = New-Object Security.AccessControl.FileSecurity
$FileAcl.SetAccessRuleProtection($true, $false)
$FileAcl.SetOwner($AdministratorsSid)
$NoneInheritance = [Security.AccessControl.InheritanceFlags]::None
$NonePropagation = [Security.AccessControl.PropagationFlags]::None
$Allow = [Security.AccessControl.AccessControlType]::Allow
$FileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $SystemSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)))
$FileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $AdministratorsSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)))
$FileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $UsersSid,
    [Security.AccessControl.FileSystemRights]::ReadAndExecute,
    $NoneInheritance,
    $NonePropagation,
    $Allow
)))
Set-Acl -LiteralPath $MarkerPath -AclObject $FileAcl

Test-ProtectedAcl -LiteralPath $AuthorityRoot
Test-ProtectedAcl -LiteralPath $MarkerPath

$Persisted = [System.IO.File]::ReadAllBytes($MarkerPath)
$Hasher = New-Object Security.Cryptography.SHA256Managed
try {
    $ExpectedMarkerHash = [BitConverter]::ToString($Hasher.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
}
finally {
    $Hasher.Dispose()
}
$Hasher2 = New-Object Security.Cryptography.SHA256Managed
try {
    $PersistedMarkerHash = [BitConverter]::ToString($Hasher2.ComputeHash($Persisted)).Replace('-', '').ToLowerInvariant()
}
finally {
    $Hasher2.Dispose()
}
if ($PersistedMarkerHash -cne $ExpectedMarkerHash) {
    throw 'Consumption marker changed during protected publication.'
}

Write-Output 'PROTECTED_CONSUMPTION_PASS'
Write-Output ("marker_path={0}" -f $MarkerPath)
Write-Output ("marker_sha256={0}" -f $PersistedMarkerHash)
