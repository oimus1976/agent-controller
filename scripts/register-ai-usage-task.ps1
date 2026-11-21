[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string] $Config,
    [Parameter(Mandatory = $true)][string] $Python,
    [Parameter(Mandatory = $true)][string] $LogFile,
    [switch] $Register
)
$ErrorActionPreference = 'Stop'
$taskName = 'AI Usage Dashboard Auto Update'
$runner = Join-Path $PSScriptRoot 'capacity-auto-update.ps1'
foreach ($value in @($Config, $Python, $LogFile, $runner)) {
    if ($value -notmatch '^[A-Za-z]:[\\/]' -or $value -match '["\r\n]') {
        throw 'Task arguments require absolute local paths.'
    }
}
foreach ($required in @($Config, $Python, $runner)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'Required task input does not exist.' }
}
if (-not (Test-Path -LiteralPath (Split-Path -Parent $LogFile) -PathType Container)) {
    throw 'Task log parent directory does not exist.'
}
if (-not $Register) {
    Write-Output 'Preview: run at the current user logon and hourly while logged in.'
    Write-Output 'Preview: run with limited privileges, ignore overlap, and stop after 30 minutes.'
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$actionArgs = '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "{0}" -Config "{1}" -Python "{2}" -LogFile "{3}" -Apply' -f $runner,$Config,$Python,$LogFile
if ($PSCmdlet.ShouldProcess($taskName, 'Register hourly production refresh')) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'The task already exists. Inspect the existing registration before changing it.'
    }
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $actionArgs
    $triggers = @(
        (New-ScheduledTaskTrigger -AtLogOn -User $identity)
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1))
    )
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Settings $settings -Principal $principal | Out-Null
    Write-Output ('Registered task: ' + $taskName)
}
