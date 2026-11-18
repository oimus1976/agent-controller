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
if ($LogFile) {
    # PowerShell 5.1 represents redirected native stderr as an ErrorRecord.
    $ErrorActionPreference = 'Continue'
    & $Python @arguments 2>&1 | ForEach-Object {
        $line = '{0:o} {1}' -f [DateTimeOffset]::Now, [string]$_
        Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
        Write-Host $line
    }
} else {
    & $Python @arguments
}
exit $LASTEXITCODE
