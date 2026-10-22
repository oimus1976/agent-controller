# Narrow owner-present #305 handoff. No target operation in PREPARED_FOR_OWNER_B.
[CmdletBinding()]
param([ValidateSet('PREPARED_FOR_OWNER_B','EXECUTE_EXACT_OWNER_B','INDEPENDENT_POSTREAD')][string]$Stage,
      [string]$PacketPath, [string]$ExpectedPacketSha256, [long]$BCommentId, [int]$ObservedPid)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Get-Issue310Hash([byte[]]$Raw) {
    $H=[Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($H.ComputeHash($Raw))).Replace('-','').ToLowerInvariant() } finally { $H.Dispose() }
}

function Read-Issue310Pin($Pin) {
    if (@($Pin.PSObject.Properties).Count -ne 3 -or $Pin.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Pin.bytes -le 0) { throw 'PIN_SHAPE' }
    Assert-Issue310Path $Pin.path
    $Raw=[IO.File]::ReadAllBytes($Pin.path)
    if ($Raw.Length -ne $Pin.bytes -or (Get-Issue310Hash $Raw) -cne $Pin.sha256) { throw 'RAW_PIN_DRIFT' }
    return ,$Raw
}

function Assert-Issue310Path([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path -cne [IO.Path]::GetFullPath($Path) -or $Path -match '[\x00-\x1f\x27\x22]' -or $Path.StartsWith('\\')) { throw 'PATH_BINDING' }
    $Current=$Path
    while ($Current) {
        $Item=Get-Item -LiteralPath $Current -Force
        if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE' }
        $Current=[IO.Path]::GetDirectoryName($Current)
    }
}

function ConvertFrom-Issue310Json([byte[]]$Raw) {
    # Preparation emits ASCII JSON, LF, trailing LF. Reject alternate encodings.
    if ($Raw.Length -eq 0 -or $Raw[-1] -ne 10 -or @($Raw | Where-Object { $_ -gt 127 -or $_ -eq 13 -or $_ -eq 0 }).Count -ne 0) { throw 'ENCODING' }
    return ([Text.Encoding]::ASCII.GetString($Raw) | ConvertFrom-Json)
}

function Assert-Issue310Equal($Expected, $Actual) {
    if ($null -eq $Expected -or $null -eq $Actual) {
        if ($null -ne $Expected -or $null -ne $Actual) { throw 'FACT_UNKNOWN' }; return
    }
    if ($Expected -is [System.Array]) {
        if ($Actual -isnot [System.Array] -or $Expected.Count -ne $Actual.Count) { throw 'FACT_DRIFT' }
        for ($I=0;$I -lt $Expected.Count;$I++) { Assert-Issue310Equal $Expected[$I] $Actual[$I] }; return
    }
    if ($Expected -is [pscustomobject]) {
        if ($Actual -isnot [pscustomobject]) { throw 'FACT_SHAPE' }
        $Names=@($Expected.PSObject.Properties.Name | Sort-Object)
        if (($Names -join '|') -cne (@($Actual.PSObject.Properties.Name | Sort-Object) -join '|')) { throw 'FACT_SHAPE' }
        foreach ($Name in $Names) { Assert-Issue310Equal $Expected.$Name $Actual.$Name }; return
    }
    if (($Expected -is [int] -or $Expected -is [long]) -and ($Actual -is [int] -or $Actual -is [long])) {
        if ([long]$Expected -ne [long]$Actual) { throw 'FACT_DRIFT' }; return
    }
    if ($Expected.GetType() -ne $Actual.GetType() -or $Expected -cne $Actual) { throw 'FACT_DRIFT' }
}

function Assert-Issue310Window($Plan, [int]$ReserveSeconds) {
    foreach ($Time in @($Plan.not_before_utc,$Plan.expires_utc)) {
        if ($Time -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { throw 'WINDOW_FORMAT' }
    }
    $Start=[DateTimeOffset]::ParseExact($Plan.not_before_utc,'yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
    $End=[DateTimeOffset]::ParseExact($Plan.expires_utc,'yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
    $Now=[DateTimeOffset]::UtcNow
    if (($End-$Start).TotalSeconds -gt 600 -or ($End-$Start).TotalSeconds -lt 240 -or $Now -lt $Start -or $Now.AddSeconds($ReserveSeconds) -ge $End) { throw 'INSUFFICIENT_WINDOW' }
}

function Get-Issue310ApprovalText($Packet, $Plan, [string]$Hash, [int]$Size) {
    return (@('ISSUE310 EXECUTE_EXACT_OWNER_B',
        "operation_id=$($Packet.operation_id)","packet_sha256=$Hash","packet_bytes=$Size",
        "plan_sha256=$($Packet.plan.sha256)","entry_sha256=$($Packet.entry.sha256)",
        "not_before_utc=$($Plan.not_before_utc)","expires_utc=$($Plan.expires_utc)",
        'I authorize exactly one diagnostic with the pinned invocation, normal profile-load writes and residual delayed-logon risk; no retry, repair, Phase0, runner or dispatch.') -join "`n")
}

function Read-Issue310GitHub([string]$Suffix) {
    # Fixed public repository, GET only. Never load a token or accept an arbitrary URL.
    Invoke-RestMethod -Uri ('https://api.github.com/repos/oimus1976/agent-controller/'+$Suffix) -Method Get -TimeoutSec 10 -Headers @{
        Accept='application/vnd.github+json'; 'Cache-Control'='no-cache'; 'User-Agent'='issue310-owner-handoff'
    }
}

function Assert-Issue310Authority($Packet, $Plan, [long]$DecisionId, [string]$Hash, [int]$Size) {
    if ($DecisionId -le 6251090806) { throw 'NO_FRESH_OWNER_B' }
    foreach ($Pair in @(@(6104605714,$Packet.authority.a_body_sha256),@(6244245123,$Packet.authority.delta_body_sha256))) {
        $Comment=Read-Issue310GitHub "issues/comments/$($Pair[0])"
        if ($Comment.id -ne $Pair[0] -or $Comment.user.id -ne 22843471 -or
            (Get-Issue310Hash ([Text.Encoding]::UTF8.GetBytes($Comment.body))) -cne $Pair[1]) { throw 'A_OR_DELTA_EVIDENCE_DRIFT' }
    }
    $B=Read-Issue310GitHub "issues/comments/$DecisionId"
    # Historic records may have been relayed. NEW B must be directly human-posted
    # via GitHub Web, plus the deliberate local hash confirmation below.
    if ($B.id -ne $DecisionId -or $B.user.id -ne 22843471 -or $B.user.login -cne 'oimus1976' -or
        $B.user.type -cne 'User' -or $B.author_association -cne 'OWNER' -or $null -ne $B.performed_via_github_app -or
        $B.issue_url -cne 'https://api.github.com/repos/oimus1976/agent-controller/issues/305' -or
        $B.created_at -cne $B.updated_at -or $B.body -cne (Get-Issue310ApprovalText $Packet $Plan $Hash $Size)) { throw 'NO_EXACT_DIRECT_HUMAN_B' }
    $Created=[DateTimeOffset]::Parse($B.created_at)
    if ($Created -lt [DateTimeOffset]::Parse($Plan.not_before_utc) -or $Created -gt [DateTimeOffset]::UtcNow) { throw 'B_TIME' }
    if ((Read-Issue310GitHub 'git/ref/heads/main').object.sha -cne $Packet.authority.main_sha) { throw 'MAIN_DRIFT' }
    # Ascending single last-page read is avoided: request issue metadata first,
    # then the final comment page. Count/read/count detects concurrent changes.
    foreach ($Pair in @(@(305,$DecisionId),@(216,$Packet.authority.latest216),@(195,$Packet.authority.latest195))) {
        $Before=Read-Issue310GitHub "issues/$($Pair[0])"
        if ($Before.comments -le 0) { throw 'AUTHORITY_UNAVAILABLE' }
        $Page=[int][Math]::Ceiling($Before.comments/100.0)
        $Comments=@(Read-Issue310GitHub "issues/$($Pair[0])/comments?per_page=100&page=$Page")
        $After=Read-Issue310GitHub "issues/$($Pair[0])"
        if ($Before.comments -ne $After.comments -or $Before.updated_at -cne $After.updated_at -or $Comments.Count -eq 0 -or $Comments[-1].id -ne $Pair[1]) { throw 'LATEST_AUTHORITY_DRIFT' }
    }
}

function Get-Issue310Metadata([string]$Path, [switch]$Content) {
    Assert-Issue310Path $Path
    $Item=Get-Item -LiteralPath $Path -Force; $Acl=Get-Acl -LiteralPath $Path
    $M=[ordered]@{path=$Path;owner=$Acl.Owner;dacl=$Acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access);attributes=[int]$Item.Attributes}
    if ($Content) {
        $M.bytes=[long]$Item.Length; $M.last_write_utc=$Item.LastWriteTimeUtc.ToString('o')
        $M.sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return [pscustomobject]$M
}

function Get-Issue310DirectoryMetadata([string]$Path) {
    $Root=Get-Issue310Metadata $Path
    $Items=@(Get-ChildItem -LiteralPath $Path -Force | Sort-Object Name | ForEach-Object {
        # Metadata only. Never read consumed-credential/authority file contents.
        [pscustomobject]@{name=$_.Name;attributes=[int]$_.Attributes;modified=$_.LastWriteTimeUtc.ToString('o');size=$(if($_.PSIsContainer){[long]-1}else{[long]$_.Length})}
    })
    return [pscustomobject]@{root=$Root;items=$Items}
}

function Assert-Issue310Runtime($Exe, $Signature) {
    if ($Exe.sha256 -cne '60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f' -or $Exe.bytes -ne 495616 -or $Exe.owner -cne 'NT SERVICE\TrustedInstaller' -or
        $Exe.last_write_utc -cne '2026-10-13T18:08:40.7318476Z' -or $Signature.Status -ne 'Valid' -or
        $Signature.SignerCertificate.Thumbprint -cne '667BBA1E1F478221AA65DE4F75187A751B03A453' -or
        $Signature.SignerCertificate.Subject -cne 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US') { throw 'MICROSOFT_RUNTIME_DRIFT' }
}

function Assert-Issue310ProcessOwner($Owner, [string]$Name, [string]$TargetSid) {
    if ($Owner.ReturnValue -ne 0 -or $Owner.Sid -isnot [string] -or $Owner.Sid -cnotmatch '^S-1-[0-9]+(?:-[0-9]+)+$') { throw 'PROCESS_OWNER_UNKNOWN' }
    if ($Owner.Sid -ceq $TargetSid -or $Name -match 'runner|actions') { throw 'TARGET_OR_RUNNER_PROCESS' }
}

function Get-Issue310ProcessObservation($Packet, $Plan, $Target, [int]$OperationPid) {
    # These independent target facts are prerequisites, not inferred from process owners.
    if ($Target.sid -cne $Plan.target_sid -or $Target.profile_path -cne $Plan.profile_path -or
        $Target.profile_list_path -cne $Plan.profile_path -or $Target.loaded -isnot [bool] -or $Target.loaded -or
        $Target.hku_absent -isnot [bool] -or -not $Target.hku_absent -or
        $Target.hku_classes_absent -isnot [bool] -or -not $Target.hku_classes_absent -or
        $Target.sessions -isnot [int] -or $Target.sessions -ne 0) { throw 'TARGET_STATE_UNKNOWN_OR_ACTIVE' }
    # No command lines, arguments, environment, or ambient owner-SID inventory.
    $Processes=@(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,SessionId,Name,ExecutablePath -OperationTimeoutSec 2 | Select-Object -First 4097)
    if ($Processes.Count -eq 0 -or $Processes.Count -gt 4096) { throw 'PROCESS_METADATA_LIMIT' }
    $Related=@{};$Seen=@{};$Images=@{}
    $Roots=@($Plan.profile_path,[IO.Path]::GetDirectoryName($Packet.candidate.path),[IO.Path]::GetDirectoryName($Packet.entry.path),[IO.Path]::GetDirectoryName($Packet.claim_path))
    foreach ($Process in $Processes) {
        foreach ($Name in @('ProcessId','ParentProcessId','SessionId')) {
            if (($Process.$Name -isnot [int] -and $Process.$Name -isnot [uint32] -and $Process.$Name -isnot [long]) -or
                $Process.$Name -lt 0 -or $Process.$Name -gt [uint32]::MaxValue) { throw 'PROCESS_METADATA_UNKNOWN' }
        }
        $Key=[long]$Process.ProcessId
        if ($Seen.ContainsKey($Key) -or [string]::IsNullOrWhiteSpace($Process.Name)) { throw 'PROCESS_METADATA_UNKNOWN' }
        $Seen[$Key]=$true
        # PID 0 is the non-executable idle accounting record, not an owner exemption.
        if ($Key -eq 0) {
            if ($Process.Name -cne 'System Idle Process' -or $Process.ParentProcessId -ne 0 -or $Process.SessionId -ne 0) { throw 'PROCESS_METADATA_UNKNOWN' }
            continue
        }
        $Image=$Process.ExecutablePath
        if ($Image -isnot [string] -or $Image -notmatch '^[a-zA-Z]:\\' -or $Image -ine [IO.Path]::GetFullPath($Image) -or
            [IO.Path]::GetFileName($Image) -ine $Process.Name) { throw 'PROCESS_RELEVANCE_UNKNOWN' }
        $Images[$Key]=$Image
        if (($Process.Name+' '+$Image) -match 'runner|actions') { throw 'TARGET_OR_RUNNER_PROCESS' }
        $Candidate=($Key -eq $OperationPid -and $OperationPid -gt 0) -or
            $Process.Name -match '^(powershell|powershell_ise|pwsh|cmd|wscript|cscript|mshta|conhost|OpenConsole)\.exe$'
        foreach ($Root in $Roots) {
            if ($Image.StartsWith($Root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { $Candidate=$true }
        }
        if ($Candidate) { $Related[$Key]=$true }
    }
    # Include descendants even when their names and paths are otherwise ordinary.
    do {
        $Changed=$false
        foreach ($Process in $Processes) {
            $Key=[long]$Process.ProcessId
            if ($Key -gt 0 -and -not $Related.ContainsKey($Key) -and
                ($Related.ContainsKey([long]$Process.ParentProcessId) -or ($OperationPid -gt 0 -and $Process.ParentProcessId -eq $OperationPid))) {
                $Related[$Key]=$true;$Changed=$true
            }
        }
    } while ($Changed)
    $Unverified=0;$Checked=0
    foreach ($Process in $Processes) {
        $Key=[long]$Process.ProcessId
        if ($Key -eq 0) { continue }
        if ($Related.ContainsKey($Key)) {
            $Owner=Invoke-CimMethod -InputObject $Process -MethodName GetOwnerSid -OperationTimeoutSec 2
            Assert-Issue310ProcessOwner $Owner $Process.Name $Plan.target_sid
            $Checked++
        } else {
            # A complete canonical installed-system image, no operation path/host/
            # lineage match, plus the independent target prerequisites above.
            # This is scoped non-association, NEVER proof of its owner or safety.
            if ($Images[$Key] -notmatch '^C:\\(?:Windows|Program Files|Program Files \(x86\))\\') { throw 'PROCESS_RELEVANCE_UNKNOWN' }
            $Unverified++
        }
    }
    return [pscustomobject]@{scope='EXACT_OPERATION_METADATA_ONLY';ownership_complete=$false;
        limitation='UNVERIFIED_UNRELATED_PROCESS_OWNER';unverified_unrelated_owner_count=$Unverified;
        related_owner_checked_count=$Checked;metadata_count=$Processes.Count}
}

function Assert-Issue310StaticFacts($Expected, $Actual) {
    # Only the explicitly dynamic observation is projected out. All original
    # identity/account/profile/source/ACL/authority fields still compare exactly.
    $Before=$Expected | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $After=$Actual | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $Before.PSObject.Properties.Remove('process_observation')
    $After.PSObject.Properties.Remove('process_observation')
    Assert-Issue310Equal $Before $After
}

function Get-Issue310NativeFacts($Packet, $Plan, [switch]$Post, [int]$OperationPid) {
    $Identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal=New-Object Security.Principal.WindowsPrincipal($Identity)
    if ($env:COMPUTERNAME -cne 'WOBBUFFET' -or $Identity.Name -cne 'WOBBUFFET\c-admin' -or $Identity.User.Value -cne $Packet.broker_sid -or
        $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not [Environment]::Is64BitProcess -or
        $PSVersionTable.PSVersion.ToString() -cne '5.1.26100.9711' -or [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -cne $Plan.executable -or
        (Get-Location).ProviderPath -cne $Plan.working_directory) { throw 'NORMAL_EXACT_BROKER_REQUIRED' }
    # Start the entry in the reviewed fresh -NoProfile -File process. Block
    # automatic transcription/module pipeline logging before handling secrets.
    foreach ($Hive in @('HKEY_LOCAL_MACHINE','HKEY_CURRENT_USER')) {
        foreach ($Policy in @(@('Transcription','EnableTranscripting'),@('ModuleLogging','EnableModuleLogging'))) {
            $LoggingPath="Registry::$Hive\SOFTWARE\Policies\Microsoft\Windows\PowerShell\$($Policy[0])"
            if (Test-Path -LiteralPath $LoggingPath) {
                $Logging=Get-ItemProperty -LiteralPath $LoggingPath
                if ($Logging.PSObject.Properties.Name -contains $Policy[1] -and $Logging.($Policy[1]) -ne 0) { throw 'SECRET_LOGGING_POLICY' }
            }
        }
    }
    $Exe=Get-Issue310Metadata $Plan.executable -Content
    $Signature=Get-AuthenticodeSignature -LiteralPath $Plan.executable
    Assert-Issue310Runtime $Exe $Signature
    $User=Get-LocalUser -Name 'ac-runner'
    $Profiles=@(Get-CimInstance Win32_UserProfile -Filter "SID='$($Plan.target_sid)'" -OperationTimeoutSec 2)
    $List=Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($Plan.target_sid)"
    $Admins=@(Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name | ForEach-Object {$_.SID.Value})
    if ($User.SID.Value -cne $Plan.target_sid -or $User.Enabled -isnot [bool] -or -not $User.Enabled -or $Admins -contains $Plan.target_sid -or
        $Profiles.Count -ne 1 -or $Profiles[0].Loaded -isnot [bool] -or $Profiles[0].Loaded -or $Profiles[0].Special -or $Profiles[0].Status -ne 0 -or
        $Profiles[0].LocalPath -cne $Plan.profile_path -or [Environment]::ExpandEnvironmentVariables($List.ProfileImagePath) -cne $Plan.profile_path) { throw 'TARGET_PROFILE_DRIFT' }
    foreach ($Sid in @($Plan.target_sid,($Plan.target_sid+'_Classes'))) {
        $Key=[Microsoft.Win32.Registry]::Users.OpenSubKey($Sid,$false)
        if ($null -ne $Key) { $Key.Dispose(); throw 'HKU_NOT_ABSENT' }
    }
    $Accounts=@(Get-CimInstance Win32_UserAccount -Filter "SID='$($Plan.target_sid)'" -OperationTimeoutSec 2)
    if ($Accounts.Count -ne 1) { throw 'ACCOUNT_UNKNOWN' }
    $Sessions=@(Get-CimAssociatedInstance -InputObject $Accounts[0] -Association Win32_LoggedOnUser -OperationTimeoutSec 2).Count
    if ($Sessions -ne 0) { throw 'TARGET_SESSION' }
    $Target=[pscustomobject]@{sid=$User.SID.Value;profile_path=$Profiles[0].LocalPath;
        profile_list_path=[Environment]::ExpandEnvironmentVariables($List.ProfileImagePath);loaded=$Profiles[0].Loaded;
        hku_absent=$true;hku_classes_absent=$true;sessions=$Sessions}
    $Observation=Get-Issue310ProcessObservation $Packet $Plan $Target $OperationPid
    $TargetNames=@($Plan.target_sid,'ac-runner','.\ac-runner','WOBBUFFET\ac-runner')
    if (@(Get-CimInstance Win32_Service -OperationTimeoutSec 2 | Where-Object {$_.Name -match 'runner|actions' -or $_.DisplayName -match 'runner|actions' -or $_.StartName -in $TargetNames}).Count -ne 0 -or
        @(Get-ScheduledTask | Where-Object {$_.TaskName -match 'runner|actions' -or $_.TaskPath -match 'runner|actions' -or $_.Principal.UserId -in $TargetNames}).Count -ne 0) { throw 'RUNNER_OR_TARGET_ACTIVITY' }
    $Root='C:\Users\Public\Documents\agent-controller-handoff'
    $Slots=@('issue216-pilot-identity-freeze.json','issue216-phase0-canonical.json','issue225-registration-handoff.json',
        'issue225-phase4-target-environment-candidate.ps1','issue225-phase4-plan.json','issue225-phase4-result.json','issue225-phase4-target-environment.log',
        'issue225-phase5-candidate.ps1','issue225-phase5-plan.json','issue225-phase5-result.json','issue225-phase5-exactly-one-job.log',
        'issue225-phase5-runner-stdout.log','issue225-phase5-runner-stderr.log','issue225-phase5-security-probe-result.json','issue225-phase5-security-probe-stdout.log','issue225-phase5-security-probe-stderr.log')
    foreach ($Name in $Slots) { if (Test-Path -LiteralPath (Join-Path $Root $Name)) { throw 'CANONICAL_SLOT_PRESENT' } }
    foreach ($Item in @(Get-ChildItem -LiteralPath $Root -Filter 'issue305*' -Force)) {
        if ($Item.FullName -cne $Packet.claim_path) { throw 'DIAGNOSTIC_SLOT_PRESENT' }
    }
    $Source=Get-Issue310Metadata (Join-Path $Plan.profile_path 'NTUSER.DAT') -Content:(-not $Post)
    return [pscustomobject][ordered]@{
        broker_sid=$Identity.User.Value;runtime=$Exe
        file_version=(Get-Item -LiteralPath $Plan.executable).VersionInfo.FileVersion
        working_directory=(Get-Issue310Metadata $Plan.working_directory)
        profile=(Get-Issue310Metadata $Plan.profile_path);source=$Source
        target_description=$User.Description;profile_status=[int]$Profiles[0].Status
        output_root=(Get-Issue310Metadata $Root)
        authority=(Get-Issue310DirectoryMetadata 'C:\ProgramData\agent-controller-private-ci-authority')
        generations=(Get-Issue310DirectoryMetadata 'C:\ProgramData\agent-controller\private-ci')
        process_observation=$Observation
    }
}

function Assert-Issue310Packet($Packet, $Plan, [string]$Entry, [string]$PacketFile) {
    $Operation='issue305-target-context-diagnostic-20261011-01'
    $Root='C:\Users\Public\Documents\agent-controller-handoff'
    if ($Packet.schema -cne 'issue310.prospective-handoff.v1' -or $Packet.authority_granted -isnot [bool] -or $Packet.authority_granted -ne $false -or
        $Packet.operation_id -cne $Operation -or $Packet.packet_path -cne $PacketFile -or $Packet.entry.path -cne $Entry -or
        $Packet.claim_path -cne "$Root\$Operation.claim" -or $Packet.result_path -cne "$Root\$Operation.handoff-result.json" -or
        $Packet.broker_sid -cne 'S-1-5-21-3783647055-311371106-158726857-1002') { throw 'PACKET_BINDING' }
    $Invocation="& '<powershell>' -NoProfile -ExecutionPolicy Bypass -File '<entry>' -Stage EXECUTE_EXACT_OWNER_B -PacketPath '<packet>' -ExpectedPacketSha256 <packet_sha256> -BCommentId <new_human_web_comment_id>"
    if ($Packet.invocation -cne $Invocation -or $Packet.authority.main_sha -cnotmatch '^[0-9a-f]{40}$' -or
        $Packet.authority.a_body_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Packet.authority.delta_body_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'PROCEDURE_BINDING' }
    $Proposal=ConvertFrom-Issue310Json (Read-Issue310Pin $Packet.proposal)
    if ($Proposal.schema -cne 'issue305.decision-b-plan.NON_EXECUTABLE.v2' -or $Proposal.operation_id -cne $Operation -or
        $Proposal.repository -cne 'oimus1976/agent-controller' -or $Proposal.decision_a_status -cne 'APPROVED_UNUSED' -or $Proposal.a_binding_delta -cne 'APPROVED' -or
        $Proposal.decision_b -isnot [bool] -or $Proposal.decision_b -or $Proposal.execution_authorized -isnot [bool] -or $Proposal.execution_authorized -or $null -ne $Proposal.live_binding) { throw 'SOURCE_NOT_AUTHORITY' }
    $Binding=$Proposal.prospective_operation_binding
    if ($Plan.schema -cne 'issue305.target-context-live.v1' -or @($Plan.PSObject.Properties).Count -ne 14 -or
        $Plan.decision_a -isnot [bool] -or -not $Plan.decision_a -or $Plan.decision_b -isnot [bool] -or -not $Plan.decision_b -or
        $Plan.host -cne 'WOBBUFFET' -or $Plan.broker_identity -cne 'WOBBUFFET\c-admin' -or
        $Plan.target_sid -cne 'S-1-5-21-3783647055-311371106-158726857-1007' -or $Plan.profile_path -cne 'C:\Users\ac-runner' -or
        $Plan.executable -cne 'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe' -or $Plan.working_directory -cne 'C:\WINDOWS\System32\WindowsPowerShell\v1.0' -or
        $Plan.executable_sha256 -cne '60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f' -or
        $Plan.candidate_sha256 -cne 'c135d9357f0ed82cf07fd41a6a68b3a71eeebea51899a0f51c852a543b2ec571' -or $Plan.candidate_size -ne 32421 -or
        $Packet.candidate.sha256 -cne $Plan.candidate_sha256 -or $Packet.candidate.bytes -ne $Plan.candidate_size -or
        $Binding.candidate_path -cne $Packet.candidate.path -or $Binding.executable.path -cne $Plan.executable -or $Binding.executable.sha256 -cne $Plan.executable_sha256) { throw 'LIVE_BINDING' }
    foreach ($Name in @('host','broker_identity','target_sid','profile_path','working_directory','candidate_sha256','candidate_size','not_before_utc','expires_utc')) {
        Assert-Issue310Equal $Binding.$Name $Plan.$Name
    }
    Assert-Issue310Equal (ConvertFrom-Issue310Json (Read-Issue310Pin $Packet.baseline)) $Packet.expected_facts
    Assert-Issue310ApprovedScope $Packet $Packet.expected_facts
}

function Assert-Issue310ApprovedScope($Packet, $Facts, [switch]$Post) {
    # These bytes project unchanged original A + only the four approved delta
    # fields. A later B/baseline cannot silently approve a different ACL/source.
    $Raw=Read-Issue310Pin $Packet.approved_scope
    $Text=[Text.Encoding]::UTF8.GetString($Raw).Replace("`r`n","`n")
    if ((Get-Issue310Hash ([Text.Encoding]::UTF8.GetBytes($Text))) -cne '121ce884b3f6994cc6d87fff9d7a8899b63d8af9ec5bca680c48a008cd081a3d') { throw 'APPROVED_SCOPE_DIGEST' }
    $Scope=ConvertFrom-Issue310Json ([Text.Encoding]::UTF8.GetBytes($Text))
    foreach ($Name in $Scope.approved_facts.PSObject.Properties.Name) {
        $Expected=$Scope.approved_facts.$Name
        if ($Post -and $Name -ceq 'source') {
            foreach ($Variable in @('bytes','last_write_utc','sha256')) { $Expected.PSObject.Properties.Remove($Variable) }
        }
        Assert-Issue310Equal $Expected $Facts.$Name
    }
}

function New-Issue310Claim([string]$Path, [string]$PacketHash) {
    # Fixed operation key, not B/window/packet key. Zero-byte/partial file is burned.
    # No exists-then-create race, delete, expiry reset or retry path.
    $File=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        $Raw=[Text.Encoding]::ASCII.GetBytes("ISSUE310_RESERVED_NO_RETRY`n$PacketHash`n")
        $File.Write($Raw,0,$Raw.Length); $File.Flush($true)
        return $File
    } catch { $File.Dispose(); throw }
}

function Assert-Issue310Result($Result) {
    foreach ($Name in @('startup_confirmed','policy_observed','broker_exit_confirmed','independent_poststate','independent_process_exit')) {
        if ($Result.$Name -isnot [bool] -or -not $Result.$Name) { throw 'STOP_PARTIAL_PROFILE_STATE' }
    }
    if ($null -eq $Result.worker -or $Result.worker.owned_exit_confirmed -isnot [bool] -or $Result.worker.release_confirmed -isnot [bool] -or
        ($Result.worker.target_pid -isnot [int] -and $Result.worker.target_pid -isnot [long]) -or
        ($Result.worker.target_exit_code -isnot [int] -and $Result.worker.target_exit_code -isnot [long])) { throw 'STOP_PARTIAL_PROFILE_STATE' }
    if ($Result.status -cne 'DIAGNOSTIC_POLICY_OBSERVED' -or $Result.startup_confirmed -ne $true -or $Result.policy_observed -ne $true -or
        $Result.broker_exit_confirmed -ne $true -or $Result.independent_poststate -ne $true -or $Result.independent_process_exit -ne $true -or
        $null -eq $Result.worker -or $Result.worker.status -cne 'TARGET_CONTEXT_RELEASED' -or $Result.worker.owned_exit_confirmed -ne $true -or
        $Result.worker.release_confirmed -ne $true -or $Result.worker.target_exit_code -ne 0 -or $Result.worker.target_pid -le 0) { throw 'STOP_PARTIAL_PROFILE_STATE' }
}

function Start-Issue310Postread($Packet, $Plan, [string]$Hash, [int]$PidToObserve) {
    return [Diagnostics.Process]::Start((New-Object Diagnostics.ProcessStartInfo -Property @{
        FileName=$Plan.executable
        Arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$($Packet.entry.path)`" -Stage INDEPENDENT_POSTREAD -PacketPath `"$($Packet.packet_path)`" -ExpectedPacketSha256 $Hash -ObservedPid $PidToObserve"
        UseShellExecute=$false;CreateNoWindow=$true;WorkingDirectory=$Plan.working_directory
        RedirectStandardOutput=$true;RedirectStandardError=$true
    }))
}

function Wait-Issue310Read($Task, [int]$Milliseconds) {
    $Clock=[Diagnostics.Stopwatch]::StartNew()
    while (-not $Task.IsCompleted) {
        if ($Clock.ElapsedMilliseconds -ge $Milliseconds) { throw 'POSTREAD_DEADLINE' }
        Write-Host "issue310 independent postread: $($Clock.ElapsedMilliseconds)ms" -InformationAction Continue
        Start-Sleep -Milliseconds 250
    }
    if ($Task.IsFaulted -or $Task.IsCanceled) { throw 'POSTREAD_CHANNEL' }
    return $Task.Result
}

function Invoke-Issue310Postread($Packet, $Plan, [string]$Hash, [int]$PidToObserve) {
    $Process=$null
    $Readback=[pscustomobject]@{available=$false;facts=$null;owned_pid_absent=$false;owned_exit_confirmed=$false;reason='POSTREAD_UNAVAILABLE_OR_DEADLINE'}
    try {
        $Process=Start-Issue310Postread $Packet $Plan $Hash $PidToObserve
        $Out=$Process.StandardOutput.ReadToEndAsync();$Err=$Process.StandardError.ReadToEndAsync()
        $Text=Wait-Issue310Read $Out 8000
        $Errors=Wait-Issue310Read $Err 1000
        if (-not $Process.WaitForExit(1000) -or $Process.ExitCode -ne 0 -or $Errors.Length -ne 0 -or $Text.Length -gt 131072) { throw 'POSTREAD_INVALID' }
        $Parsed=$Text | ConvertFrom-Json
        if ($Parsed.owned_pid_absent -isnot [bool]) { throw 'POSTREAD_UNKNOWN' }
        $Readback.facts=$Parsed.facts;$Readback.owned_pid_absent=$Parsed.owned_pid_absent
        $Readback.available=$true;$Readback.reason='OBSERVED'
    } catch { $Readback.available=$false }
    finally {
        if ($null -ne $Process) {
            try {
                if (-not $Process.HasExited) { $Process.Kill();$null=$Process.WaitForExit(5000) }
                $Readback.owned_exit_confirmed=$Process.HasExited
            } catch { $Readback.owned_exit_confirmed=$false }
            $Process.Dispose()
        }
    }
    return $Readback
}

function Invoke-Issue310Execution($Packet, $Plan, [string]$Hash, [int]$Size, [long]$DecisionId) {
    $Credential=$null; $Claim=$null; $Invoked=$false
    $CandidateValid=$false
    $Outcome=[pscustomobject]@{status='STOP_PARTIAL_PROFILE_STATE';candidate=$null;postread=$null;preflight_observations=@();phase0_readiness='BLOCKED'}
    $Locks=New-Object 'System.Collections.Generic.List[System.IDisposable]'
    try {
        # Deny replacement/write/delete of every approved input through cleanup.
        foreach ($Path in @($Packet.entry.path,$Packet.candidate.path,$Packet.plan.path,$Packet.proposal.path,$Packet.baseline.path,$Packet.approved_scope.path,$Packet.packet_path,$Plan.executable)) {
            $Locks.Add([IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))
        }
        $Outcome.preflight_observations+=@(Assert-Issue310PreEffect $Packet $Plan $Hash $Size $DecisionId 240)
        $Claim=New-Issue310Claim $Packet.claim_path $Hash
        # Trusted interactive human step; no credential arguments/files/env/logs.
        # An arbitrarily slow/cancelled dialog cannot start a target: full recheck follows.
        $Confirm=Read-Host 'Human owner: confirm the exact approved packet SHA-256'
        if ($Confirm -cne $Hash) { throw 'HUMAN_CONFIRMATION_REQUIRED' }
        $Outcome.preflight_observations+=@(Assert-Issue310PreEffect $Packet $Plan $Hash $Size $DecisionId 240 -Claimed)
        $Credential=Get-Credential -UserName 'WOBBUFFET\ac-runner' -Message 'Human only: one exact #305 diagnostic. Cancel to STOP; claim is never reusable.'
        if ($null -eq $Credential -or $Credential.UserName -cne 'WOBBUFFET\ac-runner') { throw 'HUMAN_CREDENTIAL_CANCELLED' }
        $Outcome.preflight_observations+=@(Assert-Issue310PreEffect $Packet $Plan $Hash $Size $DecisionId 180 -Claimed)
        Assert-Issue310Window $Plan 180
        $Invoked=$true
        # PSCredential stays in this process. & is script invocation, not a native
        # command line; only the unchanged candidate's private stdin envelope is used.
        $Report=& $Packet.candidate.path -PlanPath $Packet.plan.path -ExpectedPlanSha256 $Packet.plan.sha256 -Credential $Credential
        $Result=$Report | ConvertFrom-Json
        $Outcome.candidate=$Result
        Assert-Issue310Result $Result
        $CandidateValid=$true
    } catch {
        if (-not $Invoked) { throw }
    } finally {
        if ($Invoked) {
            # Always attempt a bounded independent read, including malformed report,
            # throw/timeout and unknown startup. Empty poststate NEVER clears STOP.
            $Outcome.postread=[pscustomobject]@{available=$false;reason='POSTREAD_EXCEPTION';owned_exit_confirmed=$false}
            try {
                $PidToObserve=0
                if ($CandidateValid) { $PidToObserve=$Outcome.candidate.worker.target_pid }
                $Outcome.postread=Invoke-Issue310Postread $Packet $Plan $Hash $PidToObserve
                if ($CandidateValid -and $Outcome.postread.available -eq $true -and $Outcome.postread.owned_exit_confirmed -eq $true -and $Outcome.postread.owned_pid_absent -eq $true) {
                    $After=$Outcome.postread.facts
                    Assert-Issue310ApprovedScope $Packet $After -Post
                    $Before=$Packet.expected_facts | ConvertTo-Json -Depth 20 | ConvertFrom-Json
                    foreach ($Name in @('bytes','last_write_utc','sha256')) { $Before.source.PSObject.Properties.Remove($Name) }
                    Assert-Issue310StaticFacts $Before $After
                    Assert-Issue310Window $Plan 0
                    $Outcome.status='DIAGNOSTIC_POLICY_OBSERVED'
                }
            } catch { $Outcome.status='STOP_PARTIAL_PROFILE_STATE' }
        }
        if ($null -ne $Credential) { $Credential.Password.Dispose(); $Credential=$null }
        if ($null -ne $Claim) { $Claim.Dispose() }
        foreach ($Lock in $Locks) { $Lock.Dispose() }
        # Claim always survives cancellation, uncertainty, partial write and success.
    }
    return $Outcome
}

function Assert-Issue310PreEffect($Packet, $Plan, [string]$Hash, [int]$Size, [long]$DecisionId, [int]$Reserve, [switch]$Claimed) {
    Assert-Issue310Window $Plan $Reserve
    foreach ($Pin in @($Packet.entry,$Packet.candidate,$Packet.plan,$Packet.proposal,$Packet.baseline,$Packet.approved_scope)) { $null=Read-Issue310Pin $Pin }
    $Raw=[IO.File]::ReadAllBytes($Packet.packet_path)
    if ($Raw.Length -ne $Size -or (Get-Issue310Hash $Raw) -cne $Hash) { throw 'PACKET_DRIFT' }
    Assert-Issue310Authority $Packet $Plan $DecisionId $Hash $Size
    $Facts=Get-Issue310NativeFacts $Packet $Plan
    Assert-Issue310ApprovedScope $Packet $Facts
    Assert-Issue310StaticFacts $Packet.expected_facts $Facts
    if ($Claimed) {
        $Claim=[IO.File]::ReadAllText($Packet.claim_path,[Text.Encoding]::ASCII)
        if ($Claim -cne "ISSUE310_RESERVED_NO_RETRY`n$Hash`n") { throw 'CLAIM_UNCERTAIN' }
    } elseif (Test-Path -LiteralPath $Packet.claim_path) { throw 'CLAIM_EXISTS_NO_RETRY' }
    if (Test-Path -LiteralPath $Packet.result_path) { throw 'OUTPUT_CONFLICT' }
    Assert-Issue310Window $Plan $Reserve
    Write-Host "issue310 UNVERIFIED_UNRELATED_PROCESS_OWNER: $($Facts.process_observation.unverified_unrelated_owner_count); ownership visibility is non-exhaustive"
    return $Facts.process_observation
}

# Tests extract functions from the AST; never dot-source this entry.
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'RUNTIME' }
if ($ExpectedPacketSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'NO_PINNED_PACKET' }
Assert-Issue310Path $PacketPath
$PacketRaw=[IO.File]::ReadAllBytes($PacketPath)
if ((Get-Issue310Hash $PacketRaw) -cne $ExpectedPacketSha256) { throw 'PACKET_DIGEST' }
$Packet=ConvertFrom-Issue310Json $PacketRaw
$Plan=ConvertFrom-Issue310Json (Read-Issue310Pin $Packet.plan)
Assert-Issue310Packet $Packet $Plan $PSCommandPath $PacketPath
foreach ($Pin in @($Packet.entry,$Packet.candidate)) { $null=Read-Issue310Pin $Pin }
if ($Stage -ceq 'INDEPENDENT_POSTREAD') {
    # Read-only child, no B/credential/target launch, also usable after expiry.
    $Facts=Get-Issue310NativeFacts $Packet $Plan -Post -OperationPid $ObservedPid
    $Absent=$false
    if ($ObservedPid -gt 0) { $Absent=@(Get-CimInstance Win32_Process -Filter "ProcessId=$ObservedPid" -OperationTimeoutSec 2).Count -eq 0 }
    [pscustomobject]@{facts=$Facts;owned_pid_absent=$Absent} | ConvertTo-Json -Depth 20 -Compress
    exit 0
}
if ($Stage -ceq 'PREPARED_FOR_OWNER_B') {
    # No OS/target/credential/claim operation; no live readiness or B window renewal.
    'PREPARED_FOR_OWNER_B: prospective pins only; NOT live readiness or authority'
    Get-Issue310ApprovalText $Packet $Plan $ExpectedPacketSha256 $PacketRaw.Length
    exit 0
}
if ($Stage -cne 'EXECUTE_EXACT_OWNER_B') { throw 'EXPLICIT_STAGE_REQUIRED' }
# Require the exact fresh interactive invocation, rather than an already running
# shell that may have a manual transcript, a profile, redirected input or injected code.
$ExpectedArgs=@([Environment]::GetCommandLineArgs()[0],'-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Stage','EXECUTE_EXACT_OWNER_B',
    '-PacketPath',$PacketPath,'-ExpectedPacketSha256',$ExpectedPacketSha256,'-BCommentId',$BCommentId.ToString())
if (([Environment]::GetCommandLineArgs() -join "`n") -cne ($ExpectedArgs -join "`n") -or
    [Console]::IsInputRedirected -or [Console]::IsOutputRedirected -or -not [Environment]::UserInteractive -or $Host.Name -cne 'ConsoleHost') { throw 'FRESH_INTERACTIVE_HUMAN_ENTRY_REQUIRED' }
$Result=Invoke-Issue310Execution $Packet $Plan $ExpectedPacketSha256 $PacketRaw.Length $BCommentId
$Output=[Text.Encoding]::UTF8.GetBytes(($Result | ConvertTo-Json -Depth 12 -Compress)+"`n")
$File=[IO.File]::Open($Packet.result_path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $File.Write($Output,0,$Output.Length); $File.Flush($true) } finally { $File.Dispose() }
$Result.status
if ($Result.status -cne 'DIAGNOSTIC_POLICY_OBSERVED') { exit 1 }
