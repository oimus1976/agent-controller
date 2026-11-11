# Issue #316 one-shot target-profile hold (Windows PowerShell 5.1 x64).
#
# Started only by scripts/collect_private_ci_phase0_with_target_hold.py, which
# the owner launches personally. This file holds one fixed non-admin target
# child with its profile loaded until the parent sends RELEASE on stdin, then
# reports the retained-handle exit. It writes no file, reads no policy, runs no
# target repository code and never emits Phase 0 evidence or PASS. The target
# password is typed by the human into the Windows credential dialog and stays
# in this process as a SecureString only.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TargetSid,
    [Parameter(Mandatory = $true)][string]$HostName,
    [int]$ReleaseWaitMs = 240000
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

function Write-Issue316Frame([string]$Text) {
    [Console]::Out.WriteLine($Text)
    [Console]::Out.Flush()
}

function Wait-Issue316Task($Task, [int]$Milliseconds) {
    if (-not $Task.Wait($Milliseconds)) { throw 'DEADLINE' }
    return $Task.Result
}

function Get-Issue316ChildSource {
    # Fixed target command: identity line, then wait for RELEASE. The 300 s
    # self-lease and the EOF rejection stop it from outliving its parent.
    return '$ErrorActionPreference=''Stop'';$i=[Security.Principal.WindowsIdentity]::GetCurrent();$p=[Security.Principal.WindowsPrincipal]::new($i);if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 3};[Console]::Out.WriteLine((''{0}|{1}|{2}|{3}''-f $PID,$i.User.Value,$i.Name,$PSVersionTable.PSVersion));$s=[IO.StreamReader]::new([Console]::OpenStandardInput());$r=$s.ReadLineAsync();if(!$r.Wait(300000)){exit 4};if($r.Result-ne''RELEASE''){exit 5};exit 0'
}

function Assert-Issue316Broker([string]$HostName, [string]$TargetSid) {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
        -not [Environment]::Is64BitProcess) { throw 'RUNTIME' }
    if ($HostName -cnotmatch '^[A-Za-z0-9-]+$' -or $TargetSid -cnotmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw 'BINDING_FORMAT' }
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    if ($env:COMPUTERNAME -cne $HostName -or $Identity.Name -cne "$HostName\c-admin" -or
        $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'NORMAL_BROKER_REQUIRED' }
    $User = Get-LocalUser -Name 'ac-runner'
    if ($User.SID.Value -cne $TargetSid -or $User.Enabled -ne $true) { throw 'TARGET_BINDING' }
    $Mount = [Microsoft.Win32.Registry]::Users.OpenSubKey($TargetSid, $false)
    if ($null -ne $Mount) { $Mount.Dispose(); throw 'TARGET_NOT_IDLE' }
    $Executable = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if ((Get-AuthenticodeSignature -LiteralPath $Executable).Status -ne 'Valid') { throw 'TRUSTED_EXECUTABLE' }
    return $Executable
}

function Start-Issue316Target([string]$Executable, [string]$HostName, [Security.SecureString]$Password) {
    $Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + (Get-Issue316ChildSource) + '"'
    if (($Executable.Length + $Arguments.Length + 3) -gt 1024) { throw 'TARGET_ARGUMENT_LIMIT' }
    # Process.Start keeps the creation handle (#270); the Start cmdlet with a
    # credential could not be waited on or terminated by a non-elevated broker.
    return [System.Diagnostics.Process]::Start((New-Object -TypeName System.Diagnostics.ProcessStartInfo -Property @{
        FileName = $Executable; Arguments = $Arguments
        UserName = 'ac-runner'; Domain = $HostName
        Password = $Password; LoadUserProfile = $true
        UseShellExecute = $false; CreateNoWindow = $true
        WorkingDirectory = [IO.Path]::GetDirectoryName($Executable)
        RedirectStandardInput = $true; RedirectStandardOutput = $true; RedirectStandardError = $true
    }))
}

function Invoke-Issue316Hold([string]$Executable, [string]$HostName, [string]$TargetSid,
                             [Security.SecureString]$Password, $ReleaseReader, [int]$ReleaseWaitMs) {
    $Target = $null
    $ErrorTask = $null
    $Report = [ordered]@{
        status = 'TARGET_START_FAILED'; target_started = $false; ready = $false
        release_confirmed = $false; exit_confirmed = $false; target_exit_code = $null
        target_pid = $null; stderr_empty = $false
    }
    try {
        $Target = Start-Issue316Target $Executable $HostName $Password
        if ($null -eq $Target) { throw 'TARGET_START_FAILED' }
        $Report.target_started = $true
        $Report.target_pid = $Target.Id
        $Report.status = 'TARGET_READY_INVALID'
        $ErrorTask = $Target.StandardError.ReadToEndAsync()
        $Line = Wait-Issue316Task ($Target.StandardOutput.ReadLineAsync()) 30000
        if ($null -eq $Line -or $Line.Length -gt 2048) { throw 'TARGET_READY_INVALID' }
        $Parts = $Line -split '\|'
        if ($Parts.Count -ne 4 -or $Parts[0] -cnotmatch '^[0-9]+$' -or [int]$Parts[0] -ne $Target.Id -or
            $Parts[1] -cne $TargetSid -or $Parts[2] -cne "$HostName\ac-runner" -or $Parts[3] -notlike '5.1.*') { throw 'TARGET_IDENTITY' }
        $Report.ready = $true
        $Report.status = 'RELEASE_UNCONFIRMED'
        Write-Issue316Frame ('HOLD_READY ' + $Target.Id)
        $Signal = Wait-Issue316Task ($ReleaseReader.ReadLineAsync()) $ReleaseWaitMs
        if ($Signal -cne 'RELEASE') { throw 'RELEASE_UNCONFIRMED' }
        $Report.release_confirmed = $true
        $Report.status = 'TARGET_HOLD_RELEASED'
    } catch {
        # The status already names the failed stage; cleanup below always runs.
    } finally {
        if ($null -ne $Password) { $Password.Dispose() }
        if ($null -ne $Target) {
            try {
                if (-not $Target.HasExited) {
                    try { $Target.StandardInput.WriteLine('RELEASE'); $Target.StandardInput.Close() } catch { }
                }
                if (-not $Target.WaitForExit(10000)) {
                    # Only the retained creation handle; never a PID lookup.
                    try { $Target.Kill() } catch { }
                    [void]$Target.WaitForExit(5000)
                }
                $Report.exit_confirmed = [bool]$Target.HasExited
                if ($Report.exit_confirmed) { $Report.target_exit_code = $Target.ExitCode }
            } catch { $Report.exit_confirmed = $false }
            try {
                if ($null -ne $ErrorTask) { $Report.stderr_empty = ((Wait-Issue316Task $ErrorTask 2000).Length -eq 0) }
            } catch { $Report.stderr_empty = $false }
            $Target.Dispose()
        }
    }
    if ($Report.target_started -and -not $Report.exit_confirmed) { $Report.status = 'STOP_PARTIAL_PROFILE_STATE' }
    return $Report
}

function Test-Issue316Report($Report) {
    return ($Report.status -ceq 'TARGET_HOLD_RELEASED' -and $Report.ready -eq $true -and
        $Report.release_confirmed -eq $true -and $Report.exit_confirmed -eq $true -and
        $Report.target_exit_code -eq 0 -and $Report.stderr_empty -eq $true)
}

# Entry. Everything before the credential dialog is read-only.
$ReleaseReader = [IO.StreamReader]::new([Console]::OpenStandardInput())
$Executable = Assert-Issue316Broker $HostName $TargetSid
Write-Issue316Frame 'HOLD_AWAITING_CREDENTIAL'
$Credential = Get-Credential -UserName "$HostName\ac-runner" -Message 'Issue #316: authorize exactly ONE ac-runner logon/profile load for Phase 0 collection. No runner registration, dispatch or target code. Cancel to stop with no effect.'
if ($null -eq $Credential -or $Credential.UserName -ine "$HostName\ac-runner") {
    Write-Issue316Frame 'HOLD_BLOCKED_NO_EFFECT'
    exit 3
}
Write-Issue316Frame 'HOLD_STARTING_TARGET'
$Report = Invoke-Issue316Hold $Executable $HostName $TargetSid $Credential.Password $ReleaseReader $ReleaseWaitMs
Write-Issue316Frame ('HOLD_REPORT ' + ($Report | ConvertTo-Json -Compress))
if (Test-Issue316Report $Report) { exit 0 }
exit 5
