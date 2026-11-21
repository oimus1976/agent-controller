[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Config,
    [Parameter(Mandatory = $true)][string] $Python,
    [string] $LogFile,
    [switch] $Apply
)
$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'ai_usage_auto_update.py'
$arguments = @($runner, '--config', $Config)
if ($Apply) { $arguments += '--apply' }
if ($LogFile) { $arguments += @('--log-file', $LogFile) }
& $Python @arguments
exit $LASTEXITCODE
