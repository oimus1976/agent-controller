# REVIEW CANDIDATE ONLY. No command handoff until separate owner Decision A/B.
[CmdletBinding()]
param([string]$PlanPath, [string]$ExpectedPlanSha256,
      [System.Management.Automation.PSCredential]$Credential, [switch]$Worker)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Wait-Issue305Task($Task, [int]$Milliseconds, [string]$Phase) {
    $Clock = [Diagnostics.Stopwatch]::StartNew()
    while (-not $Task.IsCompleted) {
        if ($Clock.ElapsedMilliseconds -ge $Milliseconds) { throw 'DEADLINE' }
        if ($script:Worker) { [Console]::Error.WriteLine("ISSUE305_HEARTBEAT:${Phase}:$($Clock.ElapsedMilliseconds)") }
        else { Write-Host "issue305 heartbeat: $Phase $($Clock.ElapsedMilliseconds)ms" -InformationAction Continue }
        Start-Sleep -Milliseconds 100
    }
    if ($Task.IsFaulted -or $Task.IsCanceled) { throw 'CHANNEL_ERROR' }
    return $Task.Result
}

function Stop-Issue305Owned($Process) {
    if ($null -eq $Process) { return $true }
    try {
        if (-not $Process.HasExited) {
            # Only a retained creation handle, never lookup/kill by an ambient PID.
            $Process.Kill()
            if (-not $Process.WaitForExit(5000)) { return $false }
        }
        return $Process.HasExited
    } catch { return $false }
}

function Read-Issue305State($Plan, [int]$OwnedPid=0) {
    $User = Get-LocalUser -Name 'ac-runner'
    if ($User.SID.Value -cne $Plan.target_sid) { throw 'SID_DRIFT' }
    $Profiles = @(Get-CimInstance Win32_UserProfile -Filter "SID='$($Plan.target_sid)'" -OperationTimeoutSec 2)
    if ($Profiles.Count -ne 1 -or $Profiles[0].LocalPath -cne $Plan.profile_path -or $Profiles[0].Special) { throw 'PROFILE_BINDING' }
    if ($User.Enabled -isnot [bool] -or $Profiles[0].Loaded -isnot [bool] -or $null -eq $Profiles[0].Status) { throw 'PROFILE_STATE_UNKNOWN' }
    $ProfileList = Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($Plan.target_sid)"
    if ([Environment]::ExpandEnvironmentVariables($ProfileList.ProfileImagePath) -cne $Plan.profile_path) { throw 'PROFILE_BINDING' }
    $Mount = [Microsoft.Win32.Registry]::Users.OpenSubKey($Plan.target_sid, $false)
    $Mounted = $null -ne $Mount
    if ($null -ne $Mount) { $Mount.Dispose() }
    $Admin = Get-LocalGroup -SID 'S-1-5-32-544'
    $AdminSids = @(Get-LocalGroupMember -Group $Admin.Name | ForEach-Object { $_.SID.Value })
    $Account = Get-CimInstance Win32_UserAccount -Filter "SID='$($Plan.target_sid)'" -OperationTimeoutSec 2
    if ($null -eq $Account) { throw 'ACCOUNT_UNKNOWN' }
    $Sessions = @(Get-CimAssociatedInstance -InputObject $Account -Association Win32_LoggedOnUser -OperationTimeoutSec 2)
    $Hive = Join-Path $Plan.profile_path 'NTUSER.DAT'
    foreach ($Path in @($Plan.profile_path, $Hive)) {
        if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE' }
    }
    $PidAbsent=$null
    if ($OwnedPid -gt 0) { $PidAbsent=@(Get-CimInstance Win32_Process -Filter "ProcessId=$OwnedPid" -OperationTimeoutSec 2).Count -eq 0 }
    [ordered]@{ sid=$User.SID.Value; enabled=[bool]$User.Enabled; admin=($AdminSids -contains $User.SID.Value)
        mounted=$Mounted; loaded=[bool]$Profiles[0].Loaded; sessions=$Sessions.Count
        profile=$Profiles[0].LocalPath; profile_status=$Profiles[0].Status
        account_description=$User.Description
        profile_acl=(Get-Acl -LiteralPath $Plan.profile_path).Sddl
        source_acl=(Get-Acl -LiteralPath $Hive).Sddl; owned_pid_absent=$PidAbsent }
}

function Assert-Issue305Idle($State) {
    if ($State.mounted -isnot [bool] -or $State.loaded -isnot [bool] -or $State.enabled -isnot [bool] -or $State.admin -isnot [bool] -or
        $State.mounted -or $State.loaded -or $State.sessions -ne 0 -or -not $State.enabled -or $State.admin) { throw 'TARGET_NOT_IDLE' }
}

function Start-Issue305Broker($Plan, [string]$Encoded) {
    return [Diagnostics.Process]::Start((New-Object Diagnostics.ProcessStartInfo -Property @{
        FileName=$Plan.executable; Arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $Encoded"
        UseShellExecute=$false; CreateNoWindow=$true; WorkingDirectory=$Plan.working_directory
        RedirectStandardOutput=$true; RedirectStandardError=$true
    }))
}

function Invoke-Issue305BrokerCommand($Plan, [string]$Encoded, [int]$TimeoutMs) {
    $Probe = $null
    try {
        $Probe = Start-Issue305Broker $Plan $Encoded
        $Out = $Probe.StandardOutput.ReadToEndAsync()
        $Err = $Probe.StandardError.ReadToEndAsync()
        $Text = Wait-Issue305Task $Out $TimeoutMs 'broker-read'
        $Errors = Wait-Issue305Task $Err 1000 'broker-stderr'
        if (-not $Probe.WaitForExit(1000) -or $Probe.ExitCode -ne 0 -or $Errors.Length -ne 0 -or $Text.Length -gt 16384) { throw 'BROKER_PROBE_FAILED' }
        return ($Text | ConvertFrom-Json)
    } finally {
        $Stopped=Stop-Issue305Owned $Probe
        if ($null -ne $Probe) { $Probe.Dispose() }
        if (-not $Stopped) { throw 'OWNED_PROBE_EXIT_UNKNOWN' }
    }
}

function Get-Issue305StateCommand($Plan, [int]$OwnedPid=0) {
    $Literal = ($Plan | ConvertTo-Json -Compress).Replace("'", "''")
    $Source = '$ErrorActionPreference=''Stop''; Set-StrictMode -Version Latest;' +
        'function Read-Issue305State {' + ${function:Read-Issue305State}.ToString() + '};' +
        'Read-Issue305State (''' + $Literal + ''' | ConvertFrom-Json) ' + $OwnedPid + ' | ConvertTo-Json -Compress'
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Source))
}

function Assert-Issue305Policy($Policy, $Plan) {
    if ($Policy.host -cne $Plan.host -or $Policy.broker_identity -cne $Plan.broker_identity -or
        $Policy.execution_policy_target_identity -cne 'ac-runner' -or $Policy.execution_policy_target_sid -cne $Plan.target_sid -or
        -not $Policy.target_identity_enabled -or $Policy.target_identity_admin -or $Policy.powershell_version -notlike '5.1.*') { throw 'POLICY_SUBJECT' }
    $Known = @('Undefined','Restricted','AllSigned','RemoteSigned','Unrestricted','Bypass')
    if ($Known -cnotcontains $Policy.machine_policy -or $Known -cnotcontains $Policy.target_user_policy) { throw 'POLICY_UNKNOWN' }
    $Effective = 'Bypass'
    if ($Policy.machine_policy -cne 'Undefined') { $Effective = $Policy.machine_policy }
    elseif ($Policy.target_user_policy -cne 'Undefined') { $Effective = $Policy.target_user_policy }
    if ($Effective -cne 'Bypass' -or $Policy.effective_policy_with_process_bypass -cne $Effective) { throw 'POLICY_PRECEDENCE' }
}

function Assert-Issue305Plan($Plan) {
    $Names=@('schema','host','broker_identity','target_sid','profile_path','executable','executable_sha256','working_directory','candidate_sha256','candidate_size','decision_a','decision_b','not_before_utc','expires_utc')
    if (@($Plan.PSObject.Properties).Count -ne $Names.Count) { throw 'PLAN_SHAPE' }
    foreach ($Property in $Plan.PSObject.Properties) { if ($Names -cnotcontains $Property.Name) { throw 'PLAN_SHAPE' } }
    if ($Plan.schema -cne 'issue305.target-context-live.v1' -or $Plan.decision_a -isnot [bool] -or $Plan.decision_b -isnot [bool] -or
        $Plan.decision_a -ne $true -or $Plan.decision_b -ne $true) { throw 'NO_OWNER_DECISIONS' }
    if ($Plan.host -cnotmatch '^[A-Za-z0-9-]+$' -or $Plan.broker_identity -cne "$($Plan.host)\c-admin" -or
        $Plan.target_sid -cnotmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$' -or
        $Plan.candidate_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Plan.executable_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        ($Plan.candidate_size -isnot [long] -and $Plan.candidate_size -isnot [int]) -or $Plan.candidate_size -le 0) { throw 'BINDING_FORMAT' }
    foreach ($Time in @($Plan.not_before_utc,$Plan.expires_utc)) { if ($Time -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { throw 'WINDOW_FORMAT' } }
    $Now=[DateTime]::UtcNow
    $Start=[DateTime]::Parse($Plan.not_before_utc).ToUniversalTime(); $End=[DateTime]::Parse($Plan.expires_utc).ToUniversalTime()
    if ($Now -lt $Start -or $Now.AddSeconds(60) -ge $End -or ($End-$Start).TotalSeconds -gt 600) { throw 'WINDOW' }
}

function Start-Issue305Target($Plan, [Security.SecureString]$Password) {
    $TargetSource = '$ErrorActionPreference=''Stop'';$i=[Security.Principal.WindowsIdentity]::GetCurrent();$p=[Security.Principal.WindowsPrincipal]::new($i);if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 3};[Console]::Out.WriteLine((''{0}|{1}|{2}|{3}''-f $PID,$i.User.Value,$i.Name,$PSVersionTable.PSVersion));$s=[IO.StreamReader]::new([Console]::OpenStandardInput());$r=$s.ReadLineAsync();if(!$r.Wait(60000)){exit 4};if($r.Result-ne''RELEASE''){exit 5};exit 0'
    $TargetArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + $TargetSource + '"'
    if (($Plan.executable.Length + $TargetArguments.Length + 3) -gt 1024) { throw 'TARGET_ARGUMENT_LIMIT' }
    $Target = [System.Diagnostics.Process]::Start((New-Object -TypeName System.Diagnostics.ProcessStartInfo -Property @{
    FileName = $Plan.executable; Arguments = $TargetArguments
    UserName = 'ac-runner'; Domain = $Plan.host
    Password = $Password; LoadUserProfile = $true
    UseShellExecute = $false; CreateNoWindow = $true; WorkingDirectory = $Plan.working_directory
    RedirectStandardInput = $true; RedirectStandardOutput = $true; RedirectStandardError = $true
}))
    return $Target
}

function Invoke-Issue305Worker($Plan, [Security.SecureString]$Password, $ReleaseReader) {
    $Target = $null
    $Clean = $false
    $Exit = $null
    $Observed = $false
    $TargetError = $null
    $TargetPid = $null
    $Reason = 'TARGET_CONTEXT_PROBE_BLOCKED'
    try {
        # Recheck immediately inside the supervised launcher, including direct
        # worker entry; a prior parent snapshot alone is not current state.
        Assert-Issue305Idle (Read-Issue305State $Plan)
        $Target = Start-Issue305Target $Plan $Password
        if ($null -eq $Target) { throw 'TARGET_START_FAILED' }
        $TargetPid = $Target.Id
        $TargetError = $Target.StandardError.ReadToEndAsync()
        $ReadyLine = Wait-Issue305Task ($Target.StandardOutput.ReadLineAsync()) 8000 'target-ready'
        if ($null -eq $ReadyLine -or $ReadyLine.Length -gt 2048) { throw 'TARGET_READY_INVALID' }
        $Ready = $ReadyLine -split '\|'
        if ($Ready.Count -ne 4 -or $Ready[0] -cnotmatch '^[0-9]+$' -or [int]$Ready[0] -ne $Target.Id -or
            $Ready[1] -cne $Plan.target_sid -or $Ready[2] -cne "$($Plan.host)\ac-runner" -or $Ready[3] -notlike '5.1.*') { throw 'TARGET_IDENTITY' }
        $Native = Get-CimInstance Win32_Process -Filter "ProcessId=$($Target.Id)" -OperationTimeoutSec 2
        $Owner = Invoke-CimMethod -InputObject $Native -MethodName GetOwnerSid -OperationTimeoutSec 2
        if ($Owner.ReturnValue -ne 0 -or $Owner.Sid -cne $Plan.target_sid -or $Native.ExecutablePath -cne $Plan.executable) { throw 'TARGET_OWNER_UNKNOWN' }
        [Console]::Out.WriteLine('TARGET_READY')
        # The supervisor owns the collector process handle. This launcher only
        # holds the target until that caller signals release, EOF or deadline.
        $Release=Wait-Issue305Task ($ReleaseReader.ReadLineAsync()) 25000 'release-signal'
        if ($Release -cne 'RELEASE') { throw 'RELEASE_UNCONFIRMED' }
        $Observed = $true
        $Reason = 'TARGET_CONTEXT_RELEASED'
    } catch { $Reason = 'TARGET_CONTEXT_PROBE_BLOCKED' }
    finally {
        if ($null -ne $Target) {
            try {
                if (-not $Target.HasExited) { $Target.StandardInput.WriteLine('RELEASE'); $Target.StandardInput.Close() }
                if (-not $Target.WaitForExit(5000)) { [void](Stop-Issue305Owned $Target) }
                $Clean = $Target.HasExited
                if ($Clean) { $Exit = $Target.ExitCode }
                if ($null -eq $TargetError -or (Wait-Issue305Task $TargetError 1000 'target-stderr').Length -ne 0 -or
                    (Wait-Issue305Task ($Target.StandardOutput.ReadToEndAsync()) 1000 'target-tail').Length -ne 0) { $Observed = $false }
            } catch { $Clean = $false }
            $Target.Dispose()
        }
        $Password.Dispose()
    }
    if (-not $Clean) { $Reason='STOP_PARTIAL_PROFILE_STATE' }
    elseif ($Exit -ne 0 -or -not $Observed) { $Reason='TARGET_CONTEXT_PROBE_BLOCKED' }
    return [ordered]@{status=$Reason; owned_exit_confirmed=$Clean; target_exit_code=$Exit; release_confirmed=$Observed; target_pid=$TargetPid}
}

function Start-Issue305Launcher($Plan, [string]$CandidatePath) {
        return [Diagnostics.Process]::Start((New-Object Diagnostics.ProcessStartInfo -Property @{
            FileName=$Plan.executable
            Arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$CandidatePath`" -Worker -PlanPath `"$PlanPath`" -ExpectedPlanSha256 $ExpectedPlanSha256"
            WorkingDirectory=$Plan.working_directory; UseShellExecute=$false; CreateNoWindow=$true
            RedirectStandardInput=$true; RedirectStandardOutput=$true; RedirectStandardError=$true
        }))
}

function Invoke-Issue305Supervisor($Plan, $Credential, [string]$CandidatePath) {
    $Launcher = $null
    $Before = Invoke-Issue305BrokerCommand $Plan (Get-Issue305StateCommand $Plan) 8000
    Assert-Issue305Idle $Before
    $Result = [ordered]@{status='STOP_PARTIAL_PROFILE_STATE'; startup_confirmed=$false; independent_poststate=$false; independent_process_exit=$false; broker_exit_confirmed=$true; policy_observed=$false; policy=$null; worker=$null}
    try {
        $Launcher = Start-Issue305Launcher $Plan $CandidatePath
        $Cipher = ConvertFrom-SecureString $Credential.Password
        if ($Cipher.Length -gt 3000) { throw 'CREDENTIAL_ENVELOPE_TOO_LARGE' }
        $Launcher.StandardInput.WriteLine($Cipher)
        $Cipher = $null
        $LauncherErrors = $Launcher.StandardError.ReadToEndAsync()
        $First = Wait-Issue305Task ($Launcher.StandardOutput.ReadLineAsync()) 10000 'target-startup'
        if ($First -cne 'TARGET_READY') { throw 'STARTUP_UNCONFIRMED' }
        $Result.startup_confirmed=$true
        try {
            $Policy=Invoke-Issue305BrokerCommand $Plan 'ZgB1AG4AYwB0AGkAbwBuACAAUgBlAGEAZAAtAFAAaABhAHMAZQAwAEcAcgBvAHUAcABQAG8AbABpAGMAeQAgAHsACgAgACAAIAAgAHAAYQByAGEAbQAoACQASABpAHYAZQAsACAAWwBzAHQAcgBpAG4AZwBdACQAUwBjAG8AcABlACkACgAgACAAIAAgACQAUABvAGwAaQBjAHkAIAA9ACAAJABuAHUAbABsAAoAIAAgACAAIAB0AHIAeQAgAHsACgAgACAAIAAgACAAIAAgACAAJABQAG8AbABpAGMAeQAgAD0AIAAkAEgAaQB2AGUALgBPAHAAZQBuAFMAdQBiAEsAZQB5ACgAJwBTAG8AZgB0AHcAYQByAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsACcALAAgACQAZgBhAGwAcwBlACkACgAgACAAIAAgACAAIAAgACAAaQBmACAAKAAkAG4AdQBsAGwAIAAtAGUAcQAgACQAUABvAGwAaQBjAHkAKQAgAHsAIAByAGUAdAB1AHIAbgAgACcAVQBuAGQAZQBmAGkAbgBlAGQAJwAgAH0ACgAgACAAIAAgACAAIAAgACAAaQBmACAAKABAACgAJABQAG8AbABpAGMAeQAuAEcAZQB0AFYAYQBsAHUAZQBOAGEAbQBlAHMAKAApACkAIAAtAG4AbwB0AGMAbwBuAHQAYQBpAG4AcwAgACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAcwAnACkAIAB7ACAAcgBlAHQAdQByAG4AIAAnAFUAbgBkAGUAZgBpAG4AZQBkACcAIAB9AAoAIAAgACAAIAAgACAAIAAgAGkAZgAgACgAJABQAG8AbABpAGMAeQAuAEcAZQB0AFYAYQBsAHUAZQBLAGkAbgBkACgAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABzACcAKQAgAC0AbgBlACAAWwBNAGkAYwByAG8AcwBvAGYAdAAuAFcAaQBuADMAMgAuAFIAZQBnAGkAcwB0AHIAeQBWAGEAbAB1AGUASwBpAG4AZABdADoAOgBEAFcAbwByAGQAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB0AGgAcgBvAHcAIAAiACQAewBTAGMAbwBwAGUAfQAgAHUAbgBrAG4AbwB3AG4AOgAgAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AHMAIABpAHMAIABuAG8AdAAgAEQAVwBPAFIARAAiAAoAIAAgACAAIAAgACAAIAAgAH0ACgAgACAAIAAgACAAIAAgACAAJABFAG4AYQBiAGwAZQBkACAAPQAgACQAUABvAGwAaQBjAHkALgBHAGUAdABWAGEAbAB1AGUAKAAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AHMAJwApAAoAIAAgACAAIAAgACAAIAAgAGkAZgAgACgAJABFAG4AYQBiAGwAZQBkACAALQBlAHEAIAAwACkAIAB7ACAAcgBlAHQAdQByAG4AIAAnAFIAZQBzAHQAcgBpAGMAdABlAGQAJwAgAH0ACgAgACAAIAAgACAAIAAgACAAaQBmACAAKAAkAEUAbgBhAGIAbABlAGQAIAAtAG4AZQAgADEAKQAgAHsAIAB0AGgAcgBvAHcAIAAiACQAewBTAGMAbwBwAGUAfQAgAHUAbgBrAG4AbwB3AG4AOgAgAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AHMAIABpAHMAIABuAG8AdAAgADAAIABvAHIAIAAxACIAIAB9AAoAIAAgACAAIAAgACAAIAAgAGkAZgAgACgAQAAoACQAUABvAGwAaQBjAHkALgBHAGUAdABWAGEAbAB1AGUATgBhAG0AZQBzACgAKQApACAALQBuAG8AdABjAG8AbgB0AGEAaQBuAHMAIAAnAEUAeABlAGMAdQB0AGkAbwBuAFAAbwBsAGkAYwB5ACcAIAAtAG8AcgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAUABvAGwAaQBjAHkALgBHAGUAdABWAGEAbAB1AGUASwBpAG4AZAAoACcARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAJwApACAALQBuAGUAIABbAE0AaQBjAHIAbwBzAG8AZgB0AC4AVwBpAG4AMwAyAC4AUgBlAGcAaQBzAHQAcgB5AFYAYQBsAHUAZQBLAGkAbgBkAF0AOgA6AFMAdAByAGkAbgBnACkAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAdABoAHIAbwB3ACAAIgAkAHsAUwBjAG8AcABlAH0AIAB1AG4AawBuAG8AdwBuADoAIABlAG4AYQBiAGwAZQBkACAAcABvAGwAaQBjAHkAIABoAGEAcwAgAG4AbwAgAHIAZQBhAGQAYQBiAGwAZQAgAHMAdAByAGkAbgBnACAARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIgAKACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIAAgACAAIAAgACQAVgBhAGwAdQBlACAAPQAgACQAUABvAGwAaQBjAHkALgBHAGUAdABWAGEAbAB1AGUAKAAnAEUAeABlAGMAdQB0AGkAbwBuAFAAbwBsAGkAYwB5ACcAKQAKACAAIAAgACAAIAAgACAAIABmAG8AcgBlAGEAYwBoACAAKAAkAEsAbgBvAHcAbgAgAGkAbgAgAEAAKAAnAFIAZQBzAHQAcgBpAGMAdABlAGQAJwAsACAAJwBBAGwAbABTAGkAZwBuAGUAZAAnACwAIAAnAFIAZQBtAG8AdABlAFMAaQBnAG4AZQBkACcALAAgACcAVQBuAHIAZQBzAHQAcgBpAGMAdABlAGQAJwAsACAAJwBCAHkAcABhAHMAcwAnACkAKQAgAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABpAGYAIAAoACQAVgBhAGwAdQBlACAALQBpAGUAcQAgACQASwBuAG8AdwBuACkAIAB7ACAAcgBlAHQAdQByAG4AIAAkAEsAbgBvAHcAbgAgAH0ACgAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAAgACAAIAB0AGgAcgBvAHcAIAAiACQAewBTAGMAbwBwAGUAfQAgAHUAbgBrAG4AbwB3AG4AOgAgAHUAbgByAGUAYwBvAGcAbgBpAHoAZQBkACAARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIgAKACAAIAAgACAAfQAgAGMAYQB0AGMAaAAgAHsACgAgACAAIAAgACAAIAAgACAAdABoAHIAbwB3ACAAKAAiACQAewBTAGMAbwBwAGUAfQAgAHUAbgByAGUAYQBkAGEAYgBsAGUALwB1AG4AawBuAG8AdwBuADoAIAAiACAAKwAgACQAXwAuAEUAeABjAGUAcAB0AGkAbwBuAC4ATQBlAHMAcwBhAGcAZQApAAoAIAAgACAAIAB9ACAAZgBpAG4AYQBsAGwAeQAgAHsACgAgACAAIAAgACAAIAAgACAAaQBmACAAKAAkAG4AdQBsAGwAIAAtAG4AZQAgACQAUABvAGwAaQBjAHkAKQAgAHsAIAAkAFAAbwBsAGkAYwB5AC4ARABpAHMAcABvAHMAZQAoACkAIAB9AAoAIAAgACAAIAB9AAoAfQAKAGYAdQBuAGMAdABpAG8AbgAgAFIAZQBhAGQALQBQAGgAYQBzAGUAMABUAGEAcgBnAGUAdABVAHMAZQByAFAAbwBsAGkAYwB5ACAAewAKACAAIAAgACAAcABhAHIAYQBtACgAJABVAHMAZQByAHMALAAgAFsAcwB0AHIAaQBuAGcAXQAkAFQAYQByAGcAZQB0AFMAaQBkACkACgAgACAAIAAgACQASABpAHYAZQAgAD0AIAAkAG4AdQBsAGwACgAgACAAIAAgAHQAcgB5ACAAewAKACAAIAAgACAAIAAgACAAIAAkAEgAaQB2AGUAIAA9ACAAJABVAHMAZQByAHMALgBPAHAAZQBuAFMAdQBiAEsAZQB5ACgAJABUAGEAcgBnAGUAdABTAGkAZAAsACAAJABmAGEAbABzAGUAKQAKACAAIAAgACAAIAAgACAAIABpAGYAIAAoACQAbgB1AGwAbAAgAC0AZQBxACAAJABIAGkAdgBlACkAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAdABoAHIAbwB3ACAAJwB0AGEAcgBnAGUAdAAgAFUAcwBlAHIAUABvAGwAaQBjAHkAIAB1AG4AcgBlAGEAZABhAGIAbABlADoAIAB0AGEAcgBnAGUAdAAgAFMASQBEACAAaABpAHYAZQAgAGkAcwAgAG4AbwB0ACAAbABvAGEAZABlAGQAOwAgAG4AbwAgAGgAaQB2AGUALwBwAHIAbwBmAGkAbABlACAAbQB1AHQAYQB0AGkAbwBuACAAcABlAHIAbQBpAHQAdABlAGQAJwAKACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIAAgACAAIAAgAHIAZQB0AHUAcgBuACAAUgBlAGEAZAAtAFAAaABhAHMAZQAwAEcAcgBvAHUAcABQAG8AbABpAGMAeQAgAC0ASABpAHYAZQAgACQASABpAHYAZQAgAC0AUwBjAG8AcABlACAAJwB0AGEAcgBnAGUAdAAgAFUAcwBlAHIAUABvAGwAaQBjAHkAJwAKACAAIAAgACAAfQAgAGMAYQB0AGMAaAAgAHsACgAgACAAIAAgACAAIAAgACAAdABoAHIAbwB3ACAAKAAnAHQAYQByAGcAZQB0ACAAVQBzAGUAcgBQAG8AbABpAGMAeQAgAHUAbgByAGUAYQBkAGEAYgBsAGUALwB1AG4AawBuAG8AdwBuADoAIAAnACAAKwAgACQAXwAuAEUAeABjAGUAcAB0AGkAbwBuAC4ATQBlAHMAcwBhAGcAZQApAAoAIAAgACAAIAB9ACAAZgBpAG4AYQBsAGwAeQAgAHsACgAgACAAIAAgACAAIAAgACAAaQBmACAAKAAkAG4AdQBsAGwAIAAtAG4AZQAgACQASABpAHYAZQApACAAewAgACQASABpAHYAZQAuAEQAaQBzAHAAbwBzAGUAKAApACAAfQAKACAAIAAgACAAfQAKAH0ACgAkAEUAcgByAG8AcgBBAGMAdABpAG8AbgBQAHIAZQBmAGUAcgBlAG4AYwBlACAAPQAgACcAUwB0AG8AcAAnAAoAaQBmACAAKAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuAC4ATQBhAGoAbwByACAALQBuAGUAIAA1ACAALQBvAHIAIAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuAC4ATQBpAG4AbwByACAALQBuAGUAIAAxACAALQBvAHIACgAgACAAIAAgAC0AbgBvAHQAIABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBJAHMANgA0AEIAaQB0AFAAcgBvAGMAZQBzAHMAKQAgAHsACgAgACAAIAAgAHQAaAByAG8AdwAgACcAZQB4AGUAYwB1AHQAaQBvAG4AIABwAG8AbABpAGMAeQAgAHAAcgBvAGIAZQAgAHIAZQBxAHUAaQByAGUAcwAgADYANAAtAGIAaQB0ACAAVwBpAG4AZABvAHcAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAA1AC4AMQAnAAoAfQAKACQAVABhAHIAZwBlAHQATgBhAG0AZQAgAD0AIAAnAGEAYwAtAHIAdQBuAG4AZQByACcACgAkAFQAYQByAGcAZQB0ACAAPQAgAEcAZQB0AC0ATABvAGMAYQBsAFUAcwBlAHIAIAAtAE4AYQBtAGUAIAAkAFQAYQByAGcAZQB0AE4AYQBtAGUAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgAkAFQAYQByAGcAZQB0AEUAbgBhAGIAbABlAGQAIAA9ACAAJABmAGEAbABzAGUACgAkAFQAYQByAGcAZQB0AEEAZABtAGkAbgAgAD0AIAAkAGYAYQBsAHMAZQAKAGkAZgAgACgAJABuAHUAbABsACAALQBuAGUAIAAkAFQAYQByAGcAZQB0ACkAIAB7AAoAIAAgACAAIAAkAFQAYQByAGcAZQB0AEUAbgBhAGIAbABlAGQAIAA9ACAAWwBiAG8AbwBsAF0AJABUAGEAcgBnAGUAdAAuAEUAbgBhAGIAbABlAGQACgAgACAAIAAgACQAQQBkAG0AaQBuAFMAaQBkACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AUwBlAGMAdQByAGkAdAB5AEkAZABlAG4AdABpAGYAaQBlAHIAKAAnAFMALQAxAC0ANQAtADMAMgAtADUANAA0ACcAKQAKACAAIAAgACAAJABBAGQAbQBpAG4ARwByAG8AdQBwACAAPQAgAEcAZQB0AC0ATABvAGMAYQBsAEcAcgBvAHUAcAAgAC0AUwBJAEQAIAAkAEEAZABtAGkAbgBTAGkAZAAKACAAIAAgACAAJABRAHUAYQBsAGkAZgBpAGUAZAAgAD0AIAAiACQAZQBuAHYAOgBDAE8ATQBQAFUAVABFAFIATgBBAE0ARQBcACQAVABhAHIAZwBlAHQATgBhAG0AZQAiAAoAIAAgACAAIAAkAE0AZQBtAGIAZQByAHMAIAA9ACAAQAAoAEcAZQB0AC0ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgAgAC0ARwByAG8AdQBwACAAJABBAGQAbQBpAG4ARwByAG8AdQBwAC4ATgBhAG0AZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAApAAoAIAAgACAAIAAkAFQAYQByAGcAZQB0AEEAZABtAGkAbgAgAD0AIAAkAG4AdQBsAGwAIAAtAG4AZQAgACgAJABNAGUAbQBiAGUAcgBzACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAKACAAIAAgACAAIAAgACAAIAAkAF8ALgBOAGEAbQBlACAALQBpAGUAcQAgACQAUQB1AGEAbABpAGYAaQBlAGQAIAAtAG8AcgAgACQAXwAuAE4AYQBtAGUAIAAtAGkAZQBxACAAJABUAGEAcgBnAGUAdABOAGEAbQBlAAoAIAAgACAAIAB9ACkACgB9AAoAaQBmACAAKAAkAG4AdQBsAGwAIAAtAGUAcQAgACQAVABhAHIAZwBlAHQAKQAgAHsAIAB0AGgAcgBvAHcAIAAnAHQAYQByAGcAZQB0ACAAVQBzAGUAcgBQAG8AbABpAGMAeQAgAHUAbgByAGUAYQBkAGEAYgBsAGUAOgAgAHQAYQByAGcAZQB0ACAAYQBjAGMAbwB1AG4AdAAgAG4AbwB0ACAAZgBvAHUAbgBkACcAIAB9AAoAJABUAGEAcgBnAGUAdABTAGkAZAAgAD0AIAAkAFQAYQByAGcAZQB0AC4AUwBJAEQALgBWAGEAbAB1AGUACgAkAE0AYQBjAGgAaQBuAGUAUABvAGwAaQBjAHkAIAA9ACAAUgBlAGEAZAAtAFAAaABhAHMAZQAwAEcAcgBvAHUAcABQAG8AbABpAGMAeQAgAC0ASABpAHYAZQAgACgAWwBNAGkAYwByAG8AcwBvAGYAdAAuAFcAaQBuADMAMgAuAFIAZQBnAGkAcwB0AHIAeQBdADoAOgBMAG8AYwBhAGwATQBhAGMAaABpAG4AZQApACAALQBTAGMAbwBwAGUAIAAnAE0AYQBjAGgAaQBuAGUAUABvAGwAaQBjAHkAJwAKACQAVABhAHIAZwBlAHQAVQBzAGUAcgBQAG8AbABpAGMAeQAgAD0AIABSAGUAYQBkAC0AUABoAGEAcwBlADAAVABhAHIAZwBlAHQAVQBzAGUAcgBQAG8AbABpAGMAeQAgAC0AVQBzAGUAcgBzACAAKABbAE0AaQBjAHIAbwBzAG8AZgB0AC4AVwBpAG4AMwAyAC4AUgBlAGcAaQBzAHQAcgB5AF0AOgA6AFUAcwBlAHIAcwApACAALQBUAGEAcgBnAGUAdABTAGkAZAAgACQAVABhAHIAZwBlAHQAUwBpAGQACgAkAEUAZgBmAGUAYwB0AGkAdgBlAFAAbwBsAGkAYwB5ACAAPQAgACcAQgB5AHAAYQBzAHMAJwAKAGkAZgAgACgAJABNAGEAYwBoAGkAbgBlAFAAbwBsAGkAYwB5ACAALQBuAGUAIAAnAFUAbgBkAGUAZgBpAG4AZQBkACcAKQAgAHsAIAAkAEUAZgBmAGUAYwB0AGkAdgBlAFAAbwBsAGkAYwB5ACAAPQAgACQATQBhAGMAaABpAG4AZQBQAG8AbABpAGMAeQAgAH0ACgBlAGwAcwBlAGkAZgAgACgAJABUAGEAcgBnAGUAdABVAHMAZQByAFAAbwBsAGkAYwB5ACAALQBuAGUAIAAnAFUAbgBkAGUAZgBpAG4AZQBkACcAKQAgAHsAIAAkAEUAZgBmAGUAYwB0AGkAdgBlAFAAbwBsAGkAYwB5ACAAPQAgACQAVABhAHIAZwBlAHQAVQBzAGUAcgBQAG8AbABpAGMAeQAgAH0ACgAkAFIAdQBuAG4AZQByAFAAcgBvAGMAZQBzAHMAZQBzACAAPQAgAEAAKAAKACAAIAAgACAARwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBQAHIAbwBjAGUAcwBzACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAHQAbwBwACAAfAAKACAAIAAgACAAIAAgACAAIABXAGgAZQByAGUALQBPAGIAagBlAGMAdAAgAHsAIAAkAF8ALgBOAGEAbQBlACAALQBtAGEAdABjAGgAIAAnAFIAdQBuAG4AZQByAHwAYQBjAHQAaQBvAG4AcwAnACAAfQAKACkACgAkAFIAdQBuAG4AZQByAFMAZQByAHYAaQBjAGUAcwAgAD0AIABAACgACgAgACAAIAAgAEcAZQB0AC0AQwBpAG0ASQBuAHMAdABhAG4AYwBlACAAVwBpAG4AMwAyAF8AUwBlAHIAdgBpAGMAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAAgAHwACgAgACAAIAAgACAAIAAgACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABfAC4ATgBhAG0AZQAgAC0AbQBhAHQAYwBoACAAJwByAHUAbgBuAGUAcgB8AGEAYwB0AGkAbwBuAHMAJwAgAC0AbwByAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABfAC4ARABpAHMAcABsAGEAeQBOAGEAbQBlACAALQBtAGEAdABjAGgAIAAnAHIAdQBuAG4AZQByAHwAYQBjAHQAaQBvAG4AcwAnAAoAIAAgACAAIAAgACAAIAAgAH0ACgApAAoAJABSAHUAbgBuAGUAcgBUAGEAcwBrAHMAIAA9ACAAQAAoAAoAIAAgACAAIABHAGUAdAAtAFMAYwBoAGUAZAB1AGwAZQBkAFQAYQBzAGsAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAdABvAHAAIAB8AAoAIAAgACAAIAAgACAAIAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAXwAuAFQAYQBzAGsATgBhAG0AZQAgAC0AbQBhAHQAYwBoACAAJwByAHUAbgBuAGUAcgB8AGEAYwB0AGkAbwBuAHMAJwAgAC0AbwByAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABfAC4AVABhAHMAawBQAGEAdABoACAALQBtAGEAdABjAGgAIAAnAHIAdQBuAG4AZQByAHwAYQBjAHQAaQBvAG4AcwAnAAoAIAAgACAAIAAgACAAIAAgAH0ACgApAAoAWwBvAHIAZABlAHIAZQBkAF0AQAB7AAoAIAAgACAAIABoAG8AcwB0ACAAPQAgACQAZQBuAHYAOgBDAE8ATQBQAFUAVABFAFIATgBBAE0ARQAKACAAIAAgACAAYgByAG8AawBlAHIAXwBpAGQAZQBuAHQAaQB0AHkAIAA9ACAAWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApAC4ATgBhAG0AZQAKACAAIAAgACAAdABhAHIAZwBlAHQAXwBpAGQAZQBuAHQAaQB0AHkAXwBlAG4AYQBiAGwAZQBkACAAPQAgACQAVABhAHIAZwBlAHQARQBuAGEAYgBsAGUAZAAKACAAIAAgACAAdABhAHIAZwBlAHQAXwBpAGQAZQBuAHQAaQB0AHkAXwBhAGQAbQBpAG4AIAA9ACAAJABUAGEAcgBnAGUAdABBAGQAbQBpAG4ACgAgACAAIAAgAHIAdQBuAG4AZQByAF8AcAByAG8AYwBlAHMAcwBfAGMAbwB1AG4AdAAgAD0AIAAkAFIAdQBuAG4AZQByAFAAcgBvAGMAZQBzAHMAZQBzAC4AQwBvAHUAbgB0AAoAIAAgACAAIAByAHUAbgBuAGUAcgBfAHMAZQByAHYAaQBjAGUAXwBjAG8AdQBuAHQAIAA9ACAAJABSAHUAbgBuAGUAcgBTAGUAcgB2AGkAYwBlAHMALgBDAG8AdQBuAHQACgAgACAAIAAgAHIAdQBuAG4AZQByAF8AdABhAHMAawBfAGMAbwB1AG4AdAAgAD0AIAAkAFIAdQBuAG4AZQByAFQAYQBzAGsAcwAuAEMAbwB1AG4AdAAKACAAIAAgACAAcABvAHcAZQByAHMAaABlAGwAbABfAHYAZQByAHMAaQBvAG4AIAA9ACAAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALgBQAFMAVgBlAHIAcwBpAG8AbgAuAFQAbwBTAHQAcgBpAG4AZwAoACkACgAgACAAIAAgAG0AYQBjAGgAaQBuAGUAXwBwAG8AbABpAGMAeQAgAD0AIAAkAE0AYQBjAGgAaQBuAGUAUABvAGwAaQBjAHkACgAgACAAIAAgAHQAYQByAGcAZQB0AF8AdQBzAGUAcgBfAHAAbwBsAGkAYwB5ACAAPQAgACQAVABhAHIAZwBlAHQAVQBzAGUAcgBQAG8AbABpAGMAeQAKACAAIAAgACAAZQB4AGUAYwB1AHQAaQBvAG4AXwBwAG8AbABpAGMAeQBfAHQAYQByAGcAZQB0AF8AaQBkAGUAbgB0AGkAdAB5ACAAPQAgACQAVABhAHIAZwBlAHQALgBOAGEAbQBlAAoAIAAgACAAIABlAHgAZQBjAHUAdABpAG8AbgBfAHAAbwBsAGkAYwB5AF8AdABhAHIAZwBlAHQAXwBzAGkAZAAgAD0AIAAkAFQAYQByAGcAZQB0AFMAaQBkAAoAIAAgACAAIABlAGYAZgBlAGMAdABpAHYAZQBfAHAAbwBsAGkAYwB5AF8AdwBpAHQAaABfAHAAcgBvAGMAZQBzAHMAXwBiAHkAcABhAHMAcwAgAD0AIAAkAEUAZgBmAGUAYwB0AGkAdgBlAFAAbwBsAGkAYwB5AAoAfQAgAHwAIABDAG8AbgB2AGUAcgB0AFQAbwAtAEoAcwBvAG4AIAAtAEMAbwBtAHAAcgBlAHMAcwA=' 12000
            Assert-Issue305Policy $Policy $Plan
            $Result.policy=[ordered]@{machine_policy=$Policy.machine_policy; target_user_policy=$Policy.target_user_policy
                effective_policy_with_process_bypass=$Policy.effective_policy_with_process_bypass
                subject_sid=$Policy.execution_policy_target_sid; observed_at_utc=[DateTime]::UtcNow.ToString('o')}
            $Result.policy_observed=$true
        } catch {
            if ($_.Exception.Message -ceq 'OWNED_PROBE_EXIT_UNKNOWN') { $Result.broker_exit_confirmed=$false }
        } finally {
            $Launcher.StandardInput.WriteLine('RELEASE'); $Launcher.StandardInput.Close()
        }
        $Report = Wait-Issue305Task ($Launcher.StandardOutput.ReadToEndAsync()) 15000 'target-exit'
        if (-not $Launcher.WaitForExit(1000) -or $Launcher.ExitCode -ne 0 -or $Report.Length -gt 4096 -or
            (Wait-Issue305Task $LauncherErrors 1000 'launcher-stderr') -cnotmatch '\A(?:ISSUE305_HEARTBEAT:(?:target-ready|release-signal|credential-envelope|target-stderr|target-tail):[0-9]+\r?\n)*\z') { throw 'LAUNCHER_FAILED' }
        $Parsed=$Report | ConvertFrom-Json
        if ($Parsed.owned_exit_confirmed -isnot [bool] -or $Parsed.release_confirmed -isnot [bool] -or
            ($Parsed.target_pid -isnot [int] -and $Parsed.target_pid -isnot [long]) -or $Parsed.target_pid -le 0 -or
            @('TARGET_CONTEXT_RELEASED','TARGET_CONTEXT_PROBE_BLOCKED','STOP_PARTIAL_PROFILE_STATE') -cnotcontains $Parsed.status) { throw 'WORKER_REPORT_INVALID' }
        $Result.worker=$Parsed
    } catch { $Result.status='STOP_PARTIAL_PROFILE_STATE' }
    finally {
        if ($null -ne $Launcher) { try { $Launcher.StandardInput.Close() } catch {} }
        if (-not (Stop-Issue305Owned $Launcher)) { $Result.worker=$null }
        if ($null -ne $Launcher) { $Launcher.Dispose() }
        try {
            $OwnedPid=0
            if ($null -ne $Result.worker) { $OwnedPid=$Result.worker.target_pid }
            $After = Invoke-Issue305BrokerCommand $Plan (Get-Issue305StateCommand $Plan $OwnedPid) 8000
            $Result.independent_process_exit=($After.owned_pid_absent -is [bool] -and $After.owned_pid_absent -eq $true)
            $Before.PSObject.Properties.Remove('owned_pid_absent'); $After.PSObject.Properties.Remove('owned_pid_absent')
            $Result.independent_poststate=($After.mounted -eq $false -and $After.loaded -eq $false -and $After.sessions -eq 0 -and
                (($Before | ConvertTo-Json -Compress) -ceq ($After | ConvertTo-Json -Compress)))
        } catch { $Result.independent_poststate=$false }
    }
    # Timeout can race native logon completion. An empty immediate readback
    # NEVER turns an unconfirmed launcher/target exit into a restored state.
    if ($Result.broker_exit_confirmed -and $Result.independent_poststate -and $Result.independent_process_exit -and $null -ne $Result.worker -and $Result.worker.owned_exit_confirmed) {
        if ($Result.worker.status -ceq 'TARGET_CONTEXT_RELEASED' -and $Result.worker.target_exit_code -eq 0 -and $Result.worker.release_confirmed -and $Result.policy_observed) {
            $Result.status='DIAGNOSTIC_POLICY_OBSERVED'
        } else { $Result.status='TARGET_CONTEXT_PROBE_BLOCKED' }
    }
    return $Result
}

# Entry is intentionally blocked by missing/review-only bindings and decisions.
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'RUNTIME' }
if ([string]::IsNullOrEmpty($PlanPath) -or $ExpectedPlanSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'NO_REVIEWED_LIVE_PLAN' }
$PlanRaw = [IO.File]::ReadAllBytes($PlanPath)
$Hasher = [Security.Cryptography.SHA256]::Create()
try { $PlanHash=([BitConverter]::ToString($Hasher.ComputeHash($PlanRaw))).Replace('-','').ToLowerInvariant() } finally { $Hasher.Dispose() }
if ($PlanHash -cne $ExpectedPlanSha256) { throw 'PLAN_DIGEST' }
$Plan=[Text.Encoding]::UTF8.GetString($PlanRaw) | ConvertFrom-Json
Assert-Issue305Plan $Plan
$Identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $Principal=New-Object Security.Principal.WindowsPrincipal($Identity)
if ($env:COMPUTERNAME -cne $Plan.host -or $Identity.Name -cne $Plan.broker_identity -or $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'NORMAL_BROKER_REQUIRED' }
if ($Plan.executable -cne "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -or $Plan.working_directory -cne [IO.Path]::GetDirectoryName($Plan.executable)) { throw 'TRUSTED_EXECUTABLE' }
if ((Get-FileHash -LiteralPath $Plan.executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Plan.executable_sha256 -or (Get-AuthenticodeSignature -LiteralPath $Plan.executable).Status -ne 'Valid') { throw 'EXECUTABLE_DRIFT' }
if ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Plan.candidate_sha256 -or (Get-Item -LiteralPath $PSCommandPath).Length -ne $Plan.candidate_size) { throw 'CANDIDATE_DRIFT' }
if ($Worker) {
    $InputReader=[IO.StreamReader]::new([Console]::OpenStandardInput())
    $Envelope=$InputReader.ReadLineAsync(); $Cipher=Wait-Issue305Task $Envelope 3000 'credential-envelope'
    $Password=ConvertTo-SecureString $Cipher; $Cipher=$null
    Invoke-Issue305Worker $Plan $Password $InputReader | ConvertTo-Json -Compress
    exit 0
}
if ($null -eq $Credential -or $Credential.UserName -cne "$($Plan.host)\ac-runner") { throw 'TARGET_CREDENTIAL_BINDING' }
Invoke-Issue305Supervisor $Plan $Credential $PSCommandPath | ConvertTo-Json -Depth 5 -Compress
# Diagnostic result is never canonical Phase0 PASS or permission to continue.
