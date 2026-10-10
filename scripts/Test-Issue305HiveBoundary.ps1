# Fixture feasibility candidate ONLY. There is deliberately no live mode.
# No account/profile path, pilot freeze, canonical collector or UAC launch.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
    throw 'Fixture requires x64 Windows PowerShell 5.1'
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Issue305FixtureNative {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int RegLoadAppKeyW(string file, out IntPtr key, int access, int options, int reserved);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int RegLoadKeyW(IntPtr root, string name, string file);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int RegUnLoadKeyW(IntPtr root, string name);
}
'@

$FixtureId = [Guid]::NewGuid().ToString('N')
$Mount = 'AC305_FIXTURE_' + $FixtureId
$TempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$FixtureRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($TempRoot, 'ac305-fixture-' + $FixtureId))
if (-not $FixtureRoot.StartsWith($TempRoot, [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $FixtureRoot)) { throw 'Unsafe or occupied fixture directory' }
$Source = [IO.Path]::Combine($FixtureRoot, 'synthetic.hive')
$Sentinel = [IO.Path]::Combine($FixtureRoot, 'excluded.txt')
$OwnedMount = $false
$RootKey = $null
$PolicyKey = $null
$RawHandle = [IntPtr]::Zero
$Hku = [IntPtr](-2147483645)
$Result = [ordered]@{
    kind = 'SYNTHETIC_FIXTURE_ONLY'
    powershell = $PSVersionTable.PSVersion.ToString()
    elevated = $false
    app_hive_created = $false
    load_status = $null
    broker_child_status = $null
    broker_child_policy = $null
    unload_attempted = $false
    unload_status = $null
    independent_absence = $false
    source_before_sha256 = $null
    source_after_sha256 = $null
    excluded_unchanged = $false
    fixture_removed = $false
    error = $null
    verdict = 'NO_SAFE_OPERATOR_ORCHESTRATION'
}
try {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    $Result.elevated = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $Existing = [Microsoft.Win32.Registry]::Users.OpenSubKey($Mount, $false)
    if ($null -ne $Existing) { $Existing.Dispose(); throw 'Fixture mount unexpectedly exists' }
    [void][IO.Directory]::CreateDirectory($FixtureRoot)
    $Stream = [IO.File]::Open($Sentinel, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $Bytes = [Text.Encoding]::UTF8.GetBytes('excluded synthetic evidence; must not change')
        $Stream.Write($Bytes, 0, $Bytes.Length)
    } finally { $Stream.Dispose() }
    $SentinelHash = (Get-FileHash -LiteralPath $Sentinel -Algorithm SHA256).Hash.ToLowerInvariant()
    # This API creates a new empty, private application hive. Only synthetic
    # values are written, through its handle; no global policy is changed.
    $Status = [Issue305FixtureNative]::RegLoadAppKeyW($Source, [ref]$RawHandle, 0xF003F, 1, 0)
    if ($Status -ne 0) { throw "Synthetic app-hive creation failed: $Status" }
    $SafeHandle = New-Object Microsoft.Win32.SafeHandles.SafeRegistryHandle($RawHandle, $true)
    $RootKey = [Microsoft.Win32.RegistryKey]::FromHandle($SafeHandle)
    try {
        $PolicyKey = $RootKey.CreateSubKey('Software\Policies\Microsoft\Windows\PowerShell')
        try {
            $PolicyKey.SetValue('EnableScripts', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
            $PolicyKey.SetValue('ExecutionPolicy', 'AllSigned', [Microsoft.Win32.RegistryValueKind]::String)
            $PolicyKey.Flush()
        } finally { if ($null -ne $PolicyKey) { $PolicyKey.Dispose(); $PolicyKey = $null } }
        $RootKey.Flush()
    } finally { $RootKey.Dispose(); $RootKey = $null; $SafeHandle.Dispose() }
    $Result.app_hive_created = $true
    $Result.source_before_sha256 = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
    # Probe the exact global-load API family against this synthetic file only.
    # No privilege adjustment, automatic elevation, retry or alternate loader.
    $Result.load_status = [Issue305FixtureNative]::RegLoadKeyW($Hku, $Mount, $Source)
    if ($Result.load_status -ne 0) { throw "Synthetic HKU load failed: $($Result.load_status)" }
    $OwnedMount = $true
    $Reader = @'
$ErrorActionPreference = 'Stop'
$Root = $null
$Policy = $null
try {
    $Root = [Microsoft.Win32.Registry]::Users.OpenSubKey('__MOUNT__', $false)
    if ($null -eq $Root) { throw 'synthetic mount absent' }
    $Policy = $Root.OpenSubKey('Software\Policies\Microsoft\Windows\PowerShell', $false)
    if ($null -eq $Policy -or $Policy.GetValueKind('EnableScripts') -ne 'DWord' -or
        $Policy.GetValue('EnableScripts') -ne 1 -or
        $Policy.GetValueKind('ExecutionPolicy') -ne 'String' -or
        $Policy.GetValue('ExecutionPolicy') -ne 'AllSigned') { throw 'synthetic policy mismatch' }
    [ordered]@{policy='AllSigned';identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name} | ConvertTo-Json -Compress
} finally {
    if ($null -ne $Policy) { $Policy.Dispose() }
    if ($null -ne $Root) { $Root.Dispose() }
}
'@
    $Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Reader.Replace('__MOUNT__', $Mount)))
    $ChildOutput = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -EncodedCommand $Encoded
    $Result.broker_child_status = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) { throw 'Separate synthetic reader failed' }
    $Child = $ChildOutput | ConvertFrom-Json
    if ($Child.identity -ne $Identity.Name) { throw 'Synthetic child identity mismatch' }
    $Result.broker_child_policy = $Child.policy
    # Same-token process evidence is never cross-integrity broker proof.
    $Result.verdict = 'SAME_TOKEN_FIXTURE_ONLY_NOT_OPERATOR_PROOF'
} catch {
    $Result.error = $_.Exception.Message
} finally {
    if ($null -ne $PolicyKey) { $PolicyKey.Dispose() }
    if ($null -ne $RootKey) { $RootKey.Dispose() }
    if ($OwnedMount) {
        $Result.unload_attempted = $true
        $Result.unload_status = [Issue305FixtureNative]::RegUnLoadKeyW($Hku, $Mount)
    }
    # Independent process, exact fixture key only. Unknown stays false.
    $Check = "`$Key = [Microsoft.Win32.Registry]::Users.OpenSubKey('$Mount', `$false); if (`$null -ne `$Key) { `$Key.Dispose(); exit 3 }; 'ABSENT'"
    $Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Check))
    $Readback = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -EncodedCommand $Encoded
    $Result.independent_absence = $LASTEXITCODE -eq 0 -and $Readback -eq 'ABSENT'
    if (Test-Path -LiteralPath $Source) {
        $Result.source_after_sha256 = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if (Test-Path -LiteralPath $Sentinel) {
        $Result.excluded_unchanged = (Get-FileHash -LiteralPath $Sentinel -Algorithm SHA256).Hash.ToLowerInvariant() -eq $SentinelHash
    }
    # Delete only the newly created synthetic directory after independent
    # absence. Never delete a mounted hive or traverse a reparse point.
    if ($Result.independent_absence -and (Test-Path -LiteralPath $FixtureRoot)) {
        $Entries = @(Get-Item -LiteralPath $FixtureRoot) + @(Get-ChildItem -LiteralPath $FixtureRoot -Force)
        if (@($Entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -eq 0) {
            Remove-Item -LiteralPath $FixtureRoot -Recurse -Force
            $Result.fixture_removed = -not (Test-Path -LiteralPath $FixtureRoot)
        }
    }
}
$Result | ConvertTo-Json -Compress
exit 2 # Always STOP. This probe grants no operator authority.
