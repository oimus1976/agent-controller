"""Native 5.1 parsing and in-memory process/profile doubles; NO target launch.

Parse/extract function definitions only. Override every OS process/profile
boundary used by the exercised orchestration. Never dot-source the live entry.
"""
import json
import os
from pathlib import Path
import subprocess
import unittest

from scripts import issue305_target_context_probe as probe


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "docs/operations/issue-305-target-context/Issue305-TargetContextProbe.ps1"

EXTRACT = r"""
$ErrorActionPreference='Stop'
$Tokens=$null; $Errors=$null
$Ast=[System.Management.Automation.Language.Parser]::ParseFile($env:ISSUE305_CANDIDATE,[ref]$Tokens,[ref]$Errors)
if ($Errors.Count -ne 0) { throw 'candidate parse error' }
$Ast.FindAll({param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false) |
    ForEach-Object { . ([ScriptBlock]::Create($_.Extent.Text)) }
$script:Worker=$true
"""

FIXTURE = r"""
class FixtureTask {
    [bool]$IsCompleted=$true
    [bool]$IsFaulted=$false
    [bool]$IsCanceled=$false
    [object]$Result
    FixtureTask([object]$Result) { $this.Result=$Result }
}
class FixtureReader {
    [string]$Line
    [string]$Tail=''
    [object] ReadLineAsync() { return [FixtureTask]::new($this.Line) }
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
$Plan=[pscustomobject]@{host='FIXTURE';broker_identity='FIXTURE\c-admin';target_sid='S-1-5-21-111-222-333-1007';executable='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';working_directory='C:\Windows\System32\WindowsPowerShell\v1.0'}
$Process=[FixtureProcess]::new()
$Process.StandardOutput.Line='12345|'+$Plan.target_sid+'|FIXTURE\ac-runner|5.1.1'
$Policy=[pscustomobject]@{host=$Plan.host;broker_identity=$Plan.broker_identity;execution_policy_target_identity='ac-runner';execution_policy_target_sid=$Plan.target_sid;target_identity_enabled=$true;target_identity_admin=$false;powershell_version='5.1.1';machine_policy='Undefined';target_user_policy='Undefined';effective_policy_with_process_bypass='Bypass'}
function Start-Issue305Target { param($Plan,$Password) return $Process }
function Read-Issue305State { param($Plan) return [pscustomobject]@{mounted=$false;loaded=$false;sessions=0;enabled=$true;admin=$false} }
function Get-CimInstance { param($ClassName,$Filter,$OperationTimeoutSec) return [pscustomobject]@{ExecutablePath=$Plan.executable} }
function Invoke-CimMethod { param($InputObject,$MethodName,$OperationTimeoutSec) return [pscustomobject]@{ReturnValue=0;Sid=$Plan.target_sid} }
$ReleaseReader=[FixtureReader]::new();$ReleaseReader.Line='RELEASE'
"""


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 mock boundary")
class Issue305WindowsTests(unittest.TestCase):
    def execute(self, body, fixture=True):
        environment = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
        environment["ISSUE305_CANDIDATE"] = str(CANDIDATE)
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", EXTRACT + (FIXTURE if fixture else "") + body],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=environment, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # TARGET_READY is the fixed protocol frame, not evidence/PASS.
        lines = [line for line in result.stdout.splitlines() if line != "TARGET_READY"]
        return json.loads("\n".join(lines))

    def worker(self, changes=""):
        return self.execute(changes + r"""
$Password=ConvertTo-SecureString 'SYNTHETIC_ONLY' -AsPlainText -Force
$Result=Invoke-Issue305Worker $Plan $Password $ReleaseReader
@{report=$Result;release_count=$Process.StandardInput.Writes;disposed=$Process.Disposed;killed=$Process.Killed}|ConvertTo-Json -Depth 6 -Compress
""")

    def test_parser_and_exact_functions_only(self):
        result = self.execute("@{version=$PSVersionTable.PSVersion.ToString();function_count=@($Ast.FindAll({param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)).Count}|ConvertTo-Json -Compress", fixture=False)
        self.assertTrue(result["version"].startswith("5.1."))
        self.assertGreater(result["function_count"], 5)

    def test_mock_positive_is_diagnostic_only_and_releases_owned_child(self):
        result = self.worker()
        self.assertEqual(result["report"]["status"], "TARGET_CONTEXT_RELEASED")
        self.assertEqual(result["report"]["target_exit_code"], 0)
        self.assertEqual(result["release_count"], 1)
        self.assertTrue(result["disposed"])
        self.assertNotIn("SYNTHETIC_ONLY", json.dumps(result))

    def test_wrong_sid_and_unconfirmed_release_cleanup_child(self):
        for change in (
            "$Process.StandardOutput.Line=$Process.StandardOutput.Line.Replace('1007','9999')",
            "$ReleaseReader.Line='UNKNOWN'",
            "$ReleaseReader.Line=$null",
        ):
            with self.subTest(change=change):
                result = self.worker(change + "\n")
                self.assertEqual(result["report"]["status"], "TARGET_CONTEXT_PROBE_BLOCKED")
                self.assertEqual(result["release_count"], 1)

    def test_nonzero_child_and_extra_output_are_blocked(self):
        for change in (
            "$Process.ExitCode=9",
            "$Process.StandardOutput.Tail='UNEXPECTED_OUTPUT'",
        ):
            with self.subTest(change=change):
                result = self.worker(change + "\n")
                self.assertEqual(result["report"]["status"], "TARGET_CONTEXT_PROBE_BLOCKED")
                self.assertTrue(result["report"]["owned_exit_confirmed"])

    def test_start_failure_timeout_and_unconfirmed_exit(self):
        failed = self.worker("function Start-Issue305Target { throw 'startup failure' }\n")
        self.assertEqual(failed["report"]["status"], "STOP_PARTIAL_PROFILE_STATE")
        timeout = self.worker("function Wait-Issue305Task { param($Task,$Milliseconds,$Phase) if($Phase -eq 'release-signal'){throw 'DEADLINE'};return $Task.Result }\n")
        self.assertEqual(timeout["report"]["status"], "TARGET_CONTEXT_PROBE_BLOCKED")
        self.assertEqual(timeout["release_count"], 1)
        partial = self.worker("$Process.WaitDenied=$true;$Process.KillDenied=$true\n")
        self.assertEqual(partial["report"]["status"], "STOP_PARTIAL_PROFILE_STATE")

    def test_real_wait_deadline_and_channel_fault_are_finite(self):
        result = self.execute(r"""
$Task=[FixtureTask]::new('');$Task.IsCompleted=$false
$Watch=[Diagnostics.Stopwatch]::StartNew();$Blocked=$false
try { Wait-Issue305Task $Task 30 'target-ready' } catch { $Blocked=$true }
@{blocked=$Blocked;elapsed=$Watch.ElapsedMilliseconds}|ConvertTo-Json -Compress
""")
        self.assertTrue(result["blocked"])
        self.assertLess(result["elapsed"], 1000)

    def test_plan_boolean_identity_window_and_extra_fields_fail_closed(self):
        for alteration in ("$Live.decision_a='true'", "$Live.broker_identity='FIXTURE\\ac-runner'", "$Live.target_sid='Unknown'", "$Live|Add-Member credential 'DO_NOT_PUBLISH'", "$Live.expires_utc='2000-01-01T00:00:00Z'"):
            result = self.execute(r"""
$Live=[pscustomobject]@{schema='issue305.target-context-live.v1';host='FIXTURE';broker_identity='FIXTURE\c-admin';target_sid=$Plan.target_sid;profile_path='C:\Users\fixture';executable=$Plan.executable;executable_sha256=('a'*64);working_directory=$Plan.working_directory;candidate_sha256=('b'*64);candidate_size=1;decision_a=$true;decision_b=$true;not_before_utc=[DateTime]::UtcNow.AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ssZ');expires_utc=[DateTime]::UtcNow.AddSeconds(100).ToString('yyyy-MM-ddTHH:mm:ssZ')}
""" + alteration + "\n$Blocked=$false;try { Assert-Issue305Plan $Live } catch { $Blocked=$true };@{blocked=$Blocked}|ConvertTo-Json -Compress")
            self.assertTrue(result["blocked"], alteration)

    def test_native_pipe_lease_release_eof_and_timeout_without_target(self):
        # Execute only the exact lease fragment under the calling identity. No
        # credentials, target ProcessStartInfo, profile load or registry access.
        lease = '$s=' + probe.CHILD.split('$s=', 1)[1]
        for input_text, expected in (("RELEASE\n", 0), ("", 5)):
            completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", lease], input=input_text, capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, expected, completed.stderr)
        # Open pipe with no data, scaled fixture duration; actual stream API and
        # cleanup stay exact. This catches Console.In's synchronous wrapper.
        process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", lease.replace('60000', '150')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.wait(timeout=10), 4)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def supervisor(self, changes=""):
        return self.execute(r"""
$Before=[pscustomobject][ordered]@{mounted=$false;loaded=$false;sessions=0;enabled=$true;admin=$false;sid=$Plan.target_sid;profile_acl='FIXTURE_ACL';owned_pid_absent=$null}
$After=$Before|ConvertTo-Json|ConvertFrom-Json
$After.owned_pid_absent=$true
$Reads=0
function Invoke-Issue305BrokerCommand { param($Plan,$Encoded,$TimeoutMs) $script:Reads++;if($Reads -eq 1){return $Before};if($Reads -eq 2){if($script:PolicyFailure){throw $script:PolicyFailure};return $Policy};return $After }
function Start-Issue305Launcher { param($Plan,$CandidatePath) return $Process }
function ConvertFrom-SecureString { param($SecureString) return 'SYNTHETIC_CIPHER' }
$Process.StandardOutput.Line='TARGET_READY'
$Process.StandardOutput.Tail=(@{status='TARGET_CONTEXT_RELEASED';owned_exit_confirmed=$true;target_exit_code=0;release_confirmed=$true;target_pid=12345}|ConvertTo-Json -Compress)
$Credential=[Management.Automation.PSCredential]::new('FIXTURE\ac-runner',(ConvertTo-SecureString 'SYNTHETIC_ONLY' -AsPlainText -Force))
""" + changes + r"""
$Result=Invoke-Issue305Supervisor $Plan $Credential 'C:\FIXTURE\candidate.ps1'
@{report=$Result;disposed=$Process.Disposed;killed=$Process.Killed;reads=$Reads;input_writes=$Process.StandardInput.Writes;input_closed=$Process.StandardInput.Closed}|ConvertTo-Json -Depth 7 -Compress
""")

    def test_supervisor_requires_independent_restoration_and_confirmed_exit(self):
        good = self.supervisor()
        self.assertEqual(good["report"]["status"], "DIAGNOSTIC_POLICY_OBSERVED")
        self.assertEqual(good["reads"], 3)
        self.assertEqual(good["input_writes"], 2)
        self.assertTrue(good["input_closed"])
        self.assertTrue(good["disposed"])
        for changes in ("$After.loaded=$true", "$After.mounted=$true", "$After.profile_acl='CHANGED'", "$After.owned_pid_absent=$false", "$Process.StandardOutput.Line='UNCONFIRMED_START'", "$Process.StandardOutput.Tail=$Process.StandardOutput.Tail.Replace('true','\"true\"')"):
            with self.subTest(changes=changes):
                bad = self.supervisor(changes + "\n")
                self.assertEqual(bad["report"]["status"], "STOP_PARTIAL_PROFILE_STATE")

    def test_supervisor_timeout_never_accepts_immediate_absence(self):
        bad = self.supervisor("function Wait-Issue305Task { throw 'DEADLINE' };function Invoke-Issue305BrokerCommand { param($Plan,$Encoded,$TimeoutMs) $script:Reads++;if($Reads -eq 1){return $Before};return $After }\n")
        self.assertEqual(bad["report"]["status"], "STOP_PARTIAL_PROFILE_STATE")
        self.assertTrue(bad["report"]["independent_poststate"])
        self.assertTrue(bad["killed"])

    def test_supervisor_policy_failure_releases_and_unknown_collector_exit_stays_partial(self):
        for change in ("$Policy.target_user_policy='Unknown'", "$Policy.target_user_policy='Restricted';$Policy.effective_policy_with_process_bypass='Restricted'", "$Policy.machine_policy='AllSigned';$Policy.target_user_policy='Bypass'", "$Policy.execution_policy_target_sid='WRONG'", "$script:PolicyFailure='HKU access denied'", "$script:PolicyFailure='DEADLINE'"):
            bad=self.supervisor(change+'\n')
            self.assertEqual(bad['report']['status'],'TARGET_CONTEXT_PROBE_BLOCKED')
            self.assertEqual(bad['input_writes'],2)
        partial=self.supervisor("$script:PolicyFailure='OWNED_PROBE_EXIT_UNKNOWN'\n")
        self.assertEqual(partial['report']['status'],'STOP_PARTIAL_PROFILE_STATE')
        self.assertFalse(partial['report']['broker_exit_confirmed'])
        self.assertTrue(partial['report']['independent_poststate'])

    def test_broker_timeout_tears_down_retained_process_and_disposes_on_unknown_exit(self):
        for denied in (False,True):
            body=r"""
function Start-Issue305Broker { param($Plan,$Encoded) return $Process }
function Wait-Issue305Task { throw 'DEADLINE' }
"""+("$Process.KillDenied=$true;$Process.WaitDenied=$true\n" if denied else "")+r"""
$Message='';try { Invoke-Issue305BrokerCommand $Plan 'FIXTURE_ONLY' 30 } catch { $Message=$_.Exception.Message }
@{message=$Message;killed=$Process.Killed;disposed=$Process.Disposed;exited=$Process.HasExited}|ConvertTo-Json -Compress
"""
            result=self.execute(body)
            self.assertEqual(result['message'],'OWNED_PROBE_EXIT_UNKNOWN' if denied else 'DEADLINE')
            self.assertTrue(result['disposed'])
            self.assertEqual(result['exited'],not denied)

    def test_loaded_unknown_or_busy_target_is_never_started(self):
        for field in ("loaded=$true", "mounted=$true", "loaded='false'", "sessions=1"):
            bad = self.worker("function Read-Issue305State { $State=[pscustomobject]@{mounted=$false;loaded=$false;sessions=0;enabled=$true;admin=$false};$State." + field + ";return $State }\n")
            self.assertEqual(bad["report"]["status"], "STOP_PARTIAL_PROFILE_STATE")
            self.assertEqual(bad["release_count"], 0)

    def test_exact_generated_broker_command_rejects_absent_denied_and_malformed_policy(self):
        from test_private_ci_phase0_policy_windows import HARNESS
        script = probe.broker_command().replace("([Microsoft.Win32.Registry]::Users)", "$Users").replace("([Microsoft.Win32.Registry]::LocalMachine)", "$MachineHive")
        base = {"loaded":True,"policy_present":True,"values":{},"kinds":{},"users_denied":False,"hive_denied":False,"value_denied":False,"machine_values":{},"machine_kinds":{},"machine_policy_present":True,"machine_hive_denied":False,"machine_value_denied":False}
        for change in ({"loaded":False}, {"users_denied":True}, {"values":{"EnableScripts":2},"kinds":{"EnableScripts":"DWord"}}, {"machine_values":{"EnableScripts":1},"machine_kinds":{"EnableScripts":"DWord"}}):
            environment={key:value for key,value in os.environ.items() if key.upper()!='PSMODULEPATH'}
            environment['PHASE0_POLICY_FIXTURE']=json.dumps(base|change)
            completed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',HARNESS+'\n'+script],env=environment,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=15)
            self.assertNotEqual(completed.returncode,0)
            self.assertEqual(completed.stdout.strip(),'')


if __name__ == "__main__":
    unittest.main()
