#requires -Version 5.1
# Pre-authorization check for the #216 Phase 4 target credential (#265, #270).
#
# Run this in a normal (non-elevated) Windows PowerShell 5.1 BEFORE issuing the
# Phase 4 approval. It proves that the target account password is valid by
# launching whoami.exe as the target through the same launch path the Phase 4
# candidate uses: ProcessStartInfo + [System.Diagnostics.Process]::Start, which
# keeps the creation handle. (Start-Process -Credential cannot be waited on
# from a non-elevated shell and reports a valid password as invalid, #270.)
# It consumes no authority, writes no files, changes no ACLs, and is never
# Phase 4 evidence: Phase 4 re-validates the credential itself before any
# mutation.
#
# Output: TARGET_CREDENTIAL_VALID (exit 0), TARGET_CREDENTIAL_INVALID (exit 1)
# with reason=win32_<code> and message=<text>, or
# TARGET_CREDENTIAL_IDENTITY_MISMATCH (exit 2).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExpectedIdentity = ($env:COMPUTERNAME + '\ac-runner'),

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($null -eq $Credential) {
    $Credential = Get-Credential -UserName $ExpectedIdentity -Message 'Enter the target account credential to check it before the Phase 4 approval.'
}
if ($null -eq $Credential -or $Credential.UserName -ine $ExpectedIdentity) {
    Write-Output 'TARGET_CREDENTIAL_IDENTITY_MISMATCH'
    exit 2
}
$IdentityParts = @($ExpectedIdentity -split '\\', 2)
if ($IdentityParts.Count -ne 2 -or $IdentityParts[0] -eq '' -or $IdentityParts[1] -eq '') {
    Write-Output 'TARGET_CREDENTIAL_IDENTITY_MISMATCH'
    exit 2
}

$CheckDirectory = $env:SystemRoot + '\System32'
$StartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo -Property @{
    FileName = $CheckDirectory + '\whoami.exe'
    UserName = $IdentityParts[1]
    Domain = $IdentityParts[0]
    Password = $Credential.Password
    LoadUserProfile = $false
    UseShellExecute = $false
    CreateNoWindow = $true
    WorkingDirectory = $CheckDirectory
    RedirectStandardOutput = $true
    RedirectStandardError = $true
}

$ExitCode = $null
$ObservedIdentity = ''
try {
    $Check = [System.Diagnostics.Process]::Start($StartInfo)
    $ObservedIdentity = $Check.StandardOutput.ReadToEnd().Trim()
    $Check.WaitForExit()
    $ExitCode = $Check.ExitCode
}
catch {
    $Failure = $_.Exception
    while ($null -ne $Failure.InnerException) {
        $Failure = $Failure.InnerException
    }
    $NativeCode = 'unknown'
    if ($Failure -is [System.ComponentModel.Win32Exception]) {
        $NativeCode = [string]$Failure.NativeErrorCode
    }
    Write-Output 'TARGET_CREDENTIAL_INVALID'
    Write-Output ('reason=win32_' + $NativeCode)
    Write-Output ('message=' + (($Failure.Message -replace '\s+', ' ').Trim()))
    exit 1
}

if ($ExitCode -ne 0) {
    Write-Output 'TARGET_CREDENTIAL_INVALID'
    Write-Output ('reason=whoami_exit_' + $ExitCode)
    exit 1
}
if ($ObservedIdentity -ine $ExpectedIdentity) {
    Write-Output 'TARGET_CREDENTIAL_IDENTITY_MISMATCH'
    Write-Output ('observed=' + $ObservedIdentity)
    exit 2
}

Write-Output 'TARGET_CREDENTIAL_VALID'
Write-Output ('identity=' + $ExpectedIdentity)
Write-Output 'NO_AUTHORITY_CONSUMED_NO_FILES_WRITTEN'
exit 0
