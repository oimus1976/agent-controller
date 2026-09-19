#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$PlanSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$RegistrationHandoffSha256,

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
$PlanPath = Join-Path $EvidenceRoot 'issue225-phase4-plan.json'
$HandoffPath = Join-Path $EvidenceRoot 'issue225-registration-handoff.json'
$ApprovalPath = Join-Path $EvidenceRoot ("issue225-phase4-approval-{0}.json" -f $PlanSha256)
$MarkerPath = Join-Path $AuthorityRoot ("issue225-phase4-handoff-{0}.consumed.json" -f $RegistrationHandoffSha256)
$MarkerSchema = 'agent-controller.private-ci-phase4-consumed.v1'

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
    [Security.AccessControl.FileSystemRights]::TakeOwnership
)

function Assert-NotReparsePoint {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        throw "Path is missing before reparse validation: $LiteralPath"
    }
    $Item = Get-Item -LiteralPath $LiteralPath -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse point is not allowed at Phase 4 authority boundary: $LiteralPath"
    }
}

function Test-ProtectedAcl {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
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
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    if (Test-Path -LiteralPath $LiteralPath) {
        Assert-NotReparsePoint -LiteralPath $LiteralPath
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
    Assert-NotReparsePoint -LiteralPath $Parent

    $DirectoryAcl = New-Object Security.AccessControl.DirectorySecurity
    $DirectoryAcl.SetAccessRuleProtection($true, $false)
    $DirectoryAcl.SetOwner($AdministratorsSid)
    $InheritFlags = (
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $NonePropagation = [Security.AccessControl.PropagationFlags]::None
    $Allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($Entry in @(
        @($SystemSid, [Security.AccessControl.FileSystemRights]::FullControl),
        @($AdministratorsSid, [Security.AccessControl.FileSystemRights]::FullControl),
        @($UsersSid, [Security.AccessControl.FileSystemRights]::ReadAndExecute)
    )) {
        $DirectoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $Entry[0], $Entry[1], $InheritFlags, $NonePropagation, $Allow
        )))
    }

    New-Item -ItemType Directory -Path $LiteralPath | Out-Null
    Assert-NotReparsePoint -LiteralPath $LiteralPath
    Set-Acl -LiteralPath $LiteralPath -AclObject $DirectoryAcl
    Test-ProtectedAcl -LiteralPath $LiteralPath
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $Identity
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Phase 4 consumption helper must run elevated through the Windows UAC boundary.'
}
$ObservedHost = (hostname.exe).Trim()
$ObservedIdentity = (whoami.exe).Trim()
if ($ObservedHost -ine $ExpectedHost) {
    throw "Phase 4 consumption host mismatch: $ObservedHost"
}
if ($ObservedIdentity -ine $ExpectedIdentity) {
    throw "Phase 4 consumption identity mismatch: $ObservedIdentity"
}

foreach ($RequiredPath in @($PlanPath, $HandoffPath, $ApprovalPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Required Phase 4 authority artifact is missing: $RequiredPath"
    }
    Assert-NotReparsePoint -LiteralPath $RequiredPath
}

$ObservedPlanSha = (Get-FileHash -LiteralPath $PlanPath -Algorithm SHA256).Hash.ToLowerInvariant()
$ObservedHandoffSha = (Get-FileHash -LiteralPath $HandoffPath -Algorithm SHA256).Hash.ToLowerInvariant()
$ObservedApprovalSha = (Get-FileHash -LiteralPath $ApprovalPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ObservedPlanSha -cne $PlanSha256) {
    throw 'Phase 4 plan SHA-256 mismatch.'
}
if ($ObservedHandoffSha -cne $RegistrationHandoffSha256) {
    throw 'Phase 4 registration handoff SHA-256 mismatch.'
}
if ($ObservedApprovalSha -cne $ApprovalSha256) {
    throw 'Phase 4 approval SHA-256 mismatch.'
}

$Approval = Get-Content -LiteralPath $ApprovalPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Approval.schema -cne 'agent-controller.private-ci-human-approval.v1') {
    throw 'Phase 4 approval schema mismatch.'
}
if ($Approval.plan_sha256 -cne $PlanSha256) {
    throw 'Phase 4 approval plan mismatch.'
}
if ($Approval.host -cne $ExpectedHost) {
    throw 'Phase 4 approval host mismatch.'
}
if ($Approval.approver_identity -cne $ExpectedIdentity) {
    throw 'Phase 4 approval identity mismatch.'
}
$ApprovedAt = [DateTimeOffset]::Parse($Approval.approved_at)
$Now = [DateTimeOffset]::UtcNow
$AgeSeconds = ($Now - $ApprovedAt.ToUniversalTime()).TotalSeconds
if ($AgeSeconds -lt -30 -or $AgeSeconds -gt 900) {
    throw 'Phase 4 approval freshness invalid.'
}
Test-ProtectedAcl -LiteralPath $ApprovalPath

New-ProtectedAuthorityDirectory -LiteralPath $AuthorityRoot
if (Test-Path -LiteralPath $MarkerPath) {
    throw 'Registration handoff has already been consumed by Phase 4.'
}

$Payload = [ordered]@{
    schema = $MarkerSchema
    phase4_plan_sha256 = $PlanSha256
    registration_handoff_sha256 = $RegistrationHandoffSha256
    human_approval_sha256 = $ApprovalSha256
    consumed_at = (Get-Date).ToUniversalTime().ToString('o')
}
$Json = ($Payload | ConvertTo-Json -Compress) + "`n"
$Utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
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

Assert-NotReparsePoint -LiteralPath $MarkerPath
$FileAcl = New-Object Security.AccessControl.FileSecurity
$FileAcl.SetAccessRuleProtection($true, $false)
$FileAcl.SetOwner($AdministratorsSid)
$NoneInheritance = [Security.AccessControl.InheritanceFlags]::None
$NonePropagation = [Security.AccessControl.PropagationFlags]::None
$Allow = [Security.AccessControl.AccessControlType]::Allow
foreach ($Entry in @(
    @($SystemSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($AdministratorsSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($UsersSid, [Security.AccessControl.FileSystemRights]::ReadAndExecute)
)) {
    $FileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $Entry[0], $Entry[1], $NoneInheritance, $NonePropagation, $Allow
    )))
}
Set-Acl -LiteralPath $MarkerPath -AclObject $FileAcl

Test-ProtectedAcl -LiteralPath $AuthorityRoot
Test-ProtectedAcl -LiteralPath $MarkerPath

Write-Output 'PHASE4_AUTHORITY_CONSUMED'
Write-Output ("plan_sha256={0}" -f $PlanSha256)
Write-Output ("registration_handoff_sha256={0}" -f $RegistrationHandoffSha256)
Write-Output ("approval_sha256={0}" -f $ApprovalSha256)
Write-Output ("marker_path={0}" -f $MarkerPath)
