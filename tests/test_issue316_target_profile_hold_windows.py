"""#316 hold script on real Windows PowerShell 5.1; NO target logon/credential.

Functions are extracted from the parsed script (the entry is never run) and
the target process boundary is replaced by an in-memory double. The only real
child processes run under the test worker's own identity: the fixed child
lease fragment and a frame-protocol fixture for the Python pipe driver.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_controller.private_ci_phase0_target_hold import (
    POWERSHELL_EXECUTABLE,
    SubprocessHold,
    read_target_profile_state,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "Issue316-TargetProfileHold.ps1"
SID = "S-1-5-21-111-222-333-1007"

EXTRACT = r"""
$ErrorActionPreference='Stop'
$Tokens=$null; $Errors=$null
$Ast=[System.Management.Automation.Language.Parser]::ParseFile($env:ISSUE316_SCRIPT,[ref]$Tokens,[ref]$Errors)
if ($Errors.Count -ne 0) { throw 'hold script parse error' }
$Ast.FindAll({param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false) |
    ForEach-Object { . ([ScriptBlock]::Create($_.Extent.Text)) }
"""

FIXTURE = r"""
class FixtureTask {
    [object]$Result
    [bool]$Late=$false
    FixtureTask([object]$Result) { $this.Result=$Result }
    [bool] Wait([int]$Milliseconds) { return -not $this.Late }
}
class FixtureReader {
    [string]$Line
    [string]$Tail=''
    [bool]$Late=$false
    [object] ReadLineAsync() { $t=[FixtureTask]::new($this.Line); $t.Late=$this.Late; return $t }
    [object] ReadToEndAsync() { return [FixtureTask]::new($this.Tail) }
}
class FixtureWriter {
    [int]$Writes=0
    [bool]$Closed=$false
    [void] WriteLine([string]$Text) { $this.Writes++ }
    [void] Close() { $this.Closed=$true }
}
class FixtureProcess {
    [int]$Id=12345
    [int]$ExitCode=0
    [bool]$HasExited=$false
    [bool]$WaitDenied=$false
    [bool]$KillDenied=$false
    [bool]$Killed=$false
    [bool]$Disposed=$false
    [FixtureReader]$StandardOutput=[FixtureReader]::new()
    [FixtureReader]$StandardError=[FixtureReader]::new()
    [FixtureWriter]$StandardInput=[FixtureWriter]::new()
    [bool] WaitForExit([int]$Timeout) { if($this.WaitDenied){return $false}; $this.HasExited=$true; return $true }
    [void] Kill() { if($this.KillDenied){throw 'fixture denied'}; $this.Killed=$true; $this.HasExited=$true }
    [void] Dispose() { $this.Disposed=$true }
}
$Sid='S-1-5-21-111-222-333-1007'
$Process=[FixtureProcess]::new()
$Process.StandardOutput.Line='12345|'+$Sid+'|FIXTURE\ac-runner|5.1.1'
$script:StartCount=0
function Start-Issue316Target { param($Executable,$HostName,$Password) $script:StartCount++; return $Process }
$ReleaseReader=[FixtureReader]::new(); $ReleaseReader.Line='RELEASE'
function Invoke-Fixture {
    $Report = Invoke-Issue316Hold 'C:\fixture\powershell.exe' 'FIXTURE' $Sid (New-Object Security.SecureString) $ReleaseReader 1000
    [ordered]@{report=$Report; ok=(Test-Issue316Report $Report); killed=$Process.Killed; disposed=$Process.Disposed
        released=$Process.StandardInput.Writes; closed=$Process.StandardInput.Closed; starts=$script:StartCount} | ConvertTo-Json -Depth 4 -Compress
}
"""


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 boundary")
class Issue316HoldScriptTests(unittest.TestCase):
    def powershell(self, body):
        environment = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
        environment["ISSUE316_SCRIPT"] = str(SCRIPT)
        return subprocess.run(
            [POWERSHELL_EXECUTABLE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", body],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=environment, timeout=60,
        )

    def hold(self, changes=""):
        result = self.powershell(EXTRACT + FIXTURE + changes + "\nInvoke-Fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [line for line in result.stdout.splitlines() if not line.startswith("HOLD_READY ")]
        self.assertEqual(len(lines), 1, result.stdout)
        return json.loads(lines[0]), result.stdout

    def test_script_is_ascii_and_parses_on_5_1(self):
        SCRIPT.read_bytes().decode("ascii")
        result = self.powershell(EXTRACT + "$PSVersionTable.PSVersion.Major")
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "5"), result.stderr)

    def test_entry_requires_credential_dialog_before_any_target_start(self):
        text = SCRIPT.read_text(encoding="ascii")
        entry = text[text.index("# Entry."):]
        self.assertLess(entry.index("Assert-Issue316Broker"), entry.index("Get-Credential"))
        self.assertLess(entry.index("Get-Credential"), entry.index("Invoke-Issue316Hold"))
        self.assertEqual(text.count("::Start("), 1)
        for forbidden in ("Start-Process", "ConvertFrom-SecureString", "GetNetworkCredential",
                          "RegLoadKey", "reg.exe", "Set-Content", "Out-File", "Set-ExecutionPolicy"):
            self.assertNotIn(forbidden, text)

    def test_released_hold_reports_clean_exit(self):
        payload, stdout = self.hold()
        self.assertTrue(payload["ok"])
        self.assertIn("HOLD_READY 12345", stdout)
        self.assertEqual(payload["report"]["status"], "TARGET_HOLD_RELEASED")
        self.assertEqual((payload["released"], payload["closed"], payload["disposed"], payload["killed"]),
                         (1, True, True, False))

    def test_unconfirmed_release_still_releases_target_but_is_not_ok(self):
        for change in ("$ReleaseReader.Line=$null", "$ReleaseReader.Line='release'", "$ReleaseReader.Late=$true"):
            payload, _ = self.hold(change)
            self.assertFalse(payload["ok"], change)
            self.assertEqual(payload["report"]["status"], "RELEASE_UNCONFIRMED")
            self.assertTrue(payload["report"]["exit_confirmed"])
            self.assertEqual(payload["released"], 1)

    def test_wrong_identity_or_late_ready_is_not_ok(self):
        for change in (
            "$Process.StandardOutput.Line='12345|S-1-5-21-9-9-9-500|FIXTURE\\ac-runner|5.1.1'",
            "$Process.StandardOutput.Line='999|'+$Sid+'|FIXTURE\\ac-runner|5.1.1'",
            "$Process.StandardOutput.Line='12345|'+$Sid+'|FIXTURE\\c-admin|5.1.1'",
            "$Process.StandardOutput.Line='12345|'+$Sid+'|FIXTURE\\ac-runner|7.4.0'",
            "$Process.StandardOutput.Line=$null",
            "$Process.StandardOutput.Late=$true",
        ):
            payload, stdout = self.hold(change)
            self.assertFalse(payload["ok"], change)
            self.assertFalse(payload["report"]["ready"])
            self.assertNotIn("HOLD_READY", stdout)
            self.assertTrue(payload["report"]["exit_confirmed"])

    def test_target_failures_are_not_ok(self):
        payload, _ = self.hold("$Process.ExitCode=5")
        self.assertFalse(payload["ok"])
        payload, _ = self.hold("$Process.StandardError.Tail='boom'")
        self.assertFalse(payload["ok"])

    def test_unknown_exit_is_partial_and_only_owned_handle_is_killed(self):
        payload, _ = self.hold("$Process.WaitDenied=$true")
        self.assertTrue(payload["killed"])
        payload, _ = self.hold("$Process.WaitDenied=$true; $Process.KillDenied=$true")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["report"]["status"], "STOP_PARTIAL_PROFILE_STATE")
        self.assertFalse(payload["report"]["exit_confirmed"])

    def test_failed_start_reports_never_started(self):
        payload, _ = self.hold("function Start-Issue316Target { throw 'logon failure' }")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["report"]["status"], "TARGET_START_FAILED")
        self.assertFalse(payload["report"]["target_started"])
        self.assertIsNone(payload["report"]["start_error_code"])

    def test_failed_start_records_only_the_native_error_code(self):
        win32 = "(New-Object System.ComponentModel.Win32Exception {code}, 'SECRET-ECHO')"
        for change, expected in (
            ("function Start-Issue316Target { throw " + win32.format(code=1330) + " }", 1330),
            # Process.Start called from PowerShell surfaces as MethodInvocationException.
            ("function Start-Issue316Target { throw (New-Object System.Management.Automation.MethodInvocationException"
             " 'SECRET-ECHO', " + win32.format(code=1907) + ") }", 1907),
            # A real native start failure under the worker's own identity (file not found).
            (r"function Start-Issue316Target { [System.Diagnostics.Process]::Start("
             r"(New-Object System.Diagnostics.ProcessStartInfo -Property @{FileName='C:\no-such-dir-318\x.exe'; UseShellExecute=$false})) }", 2),
        ):
            payload, stdout = self.hold(change)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["report"]["status"], "TARGET_START_FAILED")
            self.assertEqual(payload["report"]["start_error_code"], expected, change)
            self.assertIs(type(payload["report"]["start_error_code"]), int)
            self.assertNotIn("SECRET-ECHO", stdout)

    def test_native_error_code_ignored_after_target_started(self):
        payload, _ = self.hold("$Process.StandardOutput.Line=$null")
        self.assertTrue(payload["report"]["target_started"])
        self.assertIsNone(payload["report"]["start_error_code"])

    def test_broker_assertion_blocks_wrong_host_and_bad_binding(self):
        for arguments in ("'NOT-THIS-HOST' 'S-1-5-21-1-2-3-1007'", "$env:COMPUTERNAME 'S-1-5-32-544'", "'bad host' 'S-1-5-21-1-2-3-1007'"):
            result = self.powershell(EXTRACT + f"Assert-Issue316Broker {arguments}")
            self.assertNotEqual(result.returncode, 0, arguments)

    def test_broker_assertion_orders_binding_then_elevation_before_any_target_read(self):
        text = SCRIPT.read_text(encoding="ascii")
        body = text[text.index("function Assert-Issue316Broker"):text.index("function Start-Issue316Target")]
        self.assertLess(body.index("'BROKER_BINDING'"), body.index("'ELEVATED_BROKER_REQUIRED'"))
        self.assertLess(body.index("'ELEVATED_BROKER_REQUIRED'"), body.index("Get-LocalUser"))
        self.assertIn("if (-not $Principal.IsInRole(", body)
        result = self.powershell(EXTRACT + "Assert-Issue316Broker $env:COMPUTERNAME 'S-1-5-21-1-2-3-1007'")
        self.assertNotEqual(result.returncode, 0)
        identity = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip().lower()
        elevated = self.powershell(
            "(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()))"
            ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        ).stdout.strip() == "True"
        if not identity.endswith(r"\c-admin"):
            self.assertIn("BROKER_BINDING", result.stderr)
        elif not elevated:
            self.assertIn("ELEVATED_BROKER_REQUIRED", result.stderr)

    def test_real_child_lease_fragment_under_current_identity(self):
        source = self.powershell(EXTRACT + "Get-Issue316ChildSource").stdout.strip()
        self.assertLess(len(source), 900)
        self.assertNotIn('"', source)
        for sent, expected in (("RELEASE\n", 0), ("", 5), ("other\n", 5)):
            result = subprocess.run(
                [POWERSHELL_EXECUTABLE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", source],
                input=sent, capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 3:
                self.skipTest("test worker is elevated; the child refuses administrators by design")
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual(result.stdout.strip().count("|"), 3)

    def test_state_reader_reads_password_expiry_for_current_account(self):
        # Read-only observation of the test worker's own logged-on account.
        def runner(*command):
            return subprocess.run(list(command), capture_output=True, text=True, timeout=60)

        try:
            payload = read_target_profile_state(runner, os.environ.get("USERNAME", ""))
        except ValueError:
            self.skipTest("current account is not a local account with a single profile")
        self.assertIs(payload["password_expired"], False)

    def test_state_reader_fails_closed_without_target_account(self):
        def runner(*command):
            return subprocess.run(list(command), capture_output=True, text=True, timeout=60)

        try:
            read_target_profile_state(runner, "ac-no-such-user-316")
        except ValueError:
            return
        self.fail("missing target account must not produce a state")


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 boundary")
class SubprocessHoldProtocolTests(unittest.TestCase):
    FIXTURE = r"""
[Console]::Out.WriteLine('HOLD_AWAITING_CREDENTIAL'); [Console]::Out.Flush()
[Console]::Error.WriteLine('diagnostic line')
$Reader=[IO.StreamReader]::new([Console]::OpenStandardInput())
$Line=$Reader.ReadLine()
[Console]::Out.WriteLine('HOLD_REPORT {"got":"' + $Line + '"}'); [Console]::Out.Flush()
if ($Line -ceq 'RELEASE') { exit 0 }
exit 5
"""

    def test_frames_release_exit_and_stderr_over_real_pipes(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "fixture.ps1"
            script.write_text(self.FIXTURE, encoding="ascii")
            process = SubprocessHold(
                [POWERSHELL_EXECUTABLE, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
            )
            try:
                self.assertEqual(process.read_line(60), "HOLD_AWAITING_CREDENTIAL")
                with self.assertRaises(TimeoutError):
                    process.read_line(0.2)
                self.assertIsNone(process.wait(0.2))
                process.send_release()
                self.assertEqual(process.read_line(30), 'HOLD_REPORT {"got":"RELEASE"}')
                self.assertIsNone(process.read_line(30))
                self.assertEqual(process.wait(30), 0)
                self.assertIn("diagnostic line", process.stderr_tail())
            finally:
                process.kill()
                process.wait(10)
                process.close()


if __name__ == "__main__":
    unittest.main()
