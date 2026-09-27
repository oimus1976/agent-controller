#requires -Version 5.1
# Pre-authorization check for the #216 Phase 4 target credential (#265).
#
# Run this in a normal (non-elevated) Windows PowerShell 5.1 BEFORE issuing the
# Phase 4 approval. It proves that the target account password is valid by
# launching whoami.exe as the target through the same Start-Process -Credential
# path the Phase 4 candidate uses. It consumes no authority, writes no files,
# changes no ACLs, and is never Phase 4 evidence: Phase 4 re-validates the
# credential itself before any mutation.
#
# Output: TARGET_CREDENTIAL_VALID (exit 0), TARGET_CREDENTIAL_INVALID (exit 1),
# or TARGET_CREDENTIAL_IDENTITY_MISMATCH (exit 2).

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

$CheckDirectory = $env:SystemRoot + '\System32'
$CheckPath = $CheckDirectory + '\whoami.exe'
$ExitCode = $null
try {
    $Check = Start-Process -FilePath $CheckPath -Credential $Credential -WorkingDirectory $CheckDirectory -Wait -PassThru
    $ExitCode = $Check.ExitCode
}
catch {
    Write-Output 'TARGET_CREDENTIAL_INVALID'
    Write-Output ('reason=' + $_.Exception.GetType().FullName)
    exit 1
}

if ($ExitCode -ne 0) {
    Write-Output 'TARGET_CREDENTIAL_INVALID'
    Write-Output ('reason=whoami_exit_' + $ExitCode)
    exit 1
}

Write-Output 'TARGET_CREDENTIAL_VALID'
Write-Output ('identity=' + $ExpectedIdentity)
Write-Output 'NO_AUTHORITY_CONSUMED_NO_FILES_WRITTEN'
exit 0
