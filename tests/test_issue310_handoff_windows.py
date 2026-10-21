"""PS5.1 AST functions only, fake authority/state/credentials/diagnostic.

No target entry, logon, profile, registry, real credential dialog or dispatch.
Real OS effects: exclusive disposable files, current-user PowerShell test processes.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import issue310_handoff as bridge
from test_issue310_handoff import fixture


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts/Issue310-ExactHandoff.ps1"
EXTRACT = r"""
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$T=$null;$E=$null
$A=[System.Management.Automation.Language.Parser]::ParseFile($env:ISSUE310_ENTRY,[ref]$T,[ref]$E)
if($E.Count -ne 0){throw ($E | Out-String)}
$A.FindAll({param($N)$N -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false) |
    ForEach-Object { . ([ScriptBlock]::Create($_.Extent.Text)) }
"""


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 synthetic boundary")
class Issue310WindowsTests(unittest.TestCase):
    def command(self, body, directory=None):
        env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
        env["ISSUE310_ENTRY"] = str(ENTRY)
        if directory:
            env["ISSUE310_TEMP"] = str(directory)
        return dict(args=["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", EXTRACT + body],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", env=env)

    def execute(self, body, directory=None):
        result = subprocess.run(**self.command(body, directory), timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_ps51_parser_and_utc_window_reserves(self):
        result = self.execute(r"""
$P=[pscustomobject]@{not_before_utc=[DateTime]::UtcNow.AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ssZ');expires_utc=[DateTime]::UtcNow.AddSeconds(500).ToString('yyyy-MM-ddTHH:mm:ssZ')}
Assert-Issue310Window $P 240
$Blocked=0
foreach($Seconds in @(-1,60,180,240,700)){
    $P.expires_utc=[DateTime]::UtcNow.AddSeconds($Seconds).ToString('yyyy-MM-ddTHH:mm:ssZ')
    try{Assert-Issue310Window $P 240}catch{$Blocked++}
}
$P.not_before_utc='2099-01-01T00:00:00Z';$P.expires_utc='2099-01-01T00:10:00Z'
try{Assert-Issue310Window $P 240}catch{$Blocked++}
@{version=$PSVersionTable.PSVersion.ToString();blocked=$Blocked}|ConvertTo-Json -Compress
""")
        self.assertTrue(result["version"].startswith("5.1."))
        self.assertEqual(result["blocked"], 6)

    def test_cross_language_prepared_entry_checks_actual_pins_only(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            directory = Path(temp)
            _, spec = fixture(directory)
            plan, packet = bridge.assemble(spec)
            Path(spec["plan_path"]).write_bytes(plan)
            Path(spec["packet_path"]).write_bytes(packet)
            args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", spec["entry"]["path"],
                    "-Stage", "PREPARED_FOR_OWNER_B", "-PacketPath", spec["packet_path"], "-ExpectedPacketSha256", bridge.digest(packet)]
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("prospective pins only; NOT live readiness", result.stdout)
            self.assertFalse(Path(spec["packet_path"]).parent.joinpath(bridge.OPERATION + ".claim").exists())
            # The same prospect is rejected when bytes/size change, before any native gate.
            Path(spec["plan_path"]).write_bytes(plan + b" ")
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("RAW_PIN_DRIFT", result.stderr)

    def test_invalid_microsoft_subject_thumbprint_hash_owner_and_size(self):
        result = self.execute(r"""
$Exe=[pscustomobject]@{sha256='60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f';bytes=495616;owner='NT SERVICE\TrustedInstaller';last_write_utc='2026-10-13T18:08:40.7318476Z'}
$Sig=[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Thumbprint='667BBA1E1F478221AA65DE4F75187A751B03A453';Subject='CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'}}
Assert-Issue310Runtime $Exe $Sig
$Blocked=0
foreach($Name in $Exe.PSObject.Properties.Name){
    $Changed=$Exe|ConvertTo-Json|ConvertFrom-Json;$Changed.$Name='wrong'
    try{Assert-Issue310Runtime $Changed $Sig}catch{$Blocked++}
}
foreach($Name in @('Thumbprint','Subject')){
    $Changed=$Sig|ConvertTo-Json|ConvertFrom-Json;$Changed.SignerCertificate.$Name='wrong'
    try{Assert-Issue310Runtime $Exe $Changed}catch{$Blocked++}
}
$Sig.Status='UnknownError'
try{Assert-Issue310Runtime $Exe $Sig}catch{$Blocked++}
@{blocked=$Blocked}|ConvertTo-Json -Compress
""")
        self.assertEqual(result["blocked"], 7)

    def test_fresh_exact_direct_human_b_and_forged_or_expired_b(self):
        result = self.execute(r"""
$Now=[DateTime]::UtcNow
$P=[pscustomobject]@{not_before_utc=$Now.AddSeconds(-10).ToString('yyyy-MM-ddTHH:mm:ssZ');expires_utc=$Now.AddSeconds(500).ToString('yyyy-MM-ddTHH:mm:ssZ')}
$K=[pscustomobject]@{operation_id='fixture';entry=[pscustomobject]@{sha256=('e'*64)};plan=[pscustomobject]@{sha256=('f'*64)};authority=[pscustomobject]@{a_body_sha256=(Get-Issue310Hash ([Text.Encoding]::UTF8.GetBytes('FAKE_A')));delta_body_sha256=(Get-Issue310Hash ([Text.Encoding]::UTF8.GetBytes('FAKE_A')));main_sha=('a'*40);latest216=216;latest195=195}}
$B=[pscustomobject]@{id=[long]9999999999;user=[pscustomobject]@{id=22843471;login='oimus1976';type='User'};author_association='OWNER';performed_via_github_app=$null;issue_url='https://api.github.com/repos/oimus1976/agent-controller/issues/305';created_at=$Now.ToString('yyyy-MM-ddTHH:mm:ssZ');updated_at=$Now.ToString('yyyy-MM-ddTHH:mm:ssZ');body=(Get-Issue310ApprovalText $K $P ('a'*64) 123)}
function Read-Issue310GitHub($Suffix){
    if($Suffix -match '^issues/comments/(6104605714|6244245123)$'){return [pscustomobject]@{id=[long]$Matches[1];user=[pscustomobject]@{id=22843471};body='FAKE_A'}}
    if($Suffix -eq 'issues/comments/9999999999'){return $B}
    if($Suffix -eq 'git/ref/heads/main'){return [pscustomobject]@{object=[pscustomobject]@{sha=('a'*40)}}}
    if($Suffix -match '^issues/(305|216|195)/comments\?'){return [pscustomobject]@{id=$(if($Matches[1] -eq '305'){[long]9999999999}else{[long]$Matches[1]})}}
    if($Suffix -match '^issues/(305|216|195)$'){return [pscustomobject]@{comments=1;updated_at='fixture'}}
    throw 'UNEXPECTED_API'
}
Assert-Issue310Authority $K $P 9999999999 ('a'*64) 123
$Blocked=0
try{Assert-Issue310Authority $K $P 6251090806 ('a'*64) 123}catch{$Blocked++}
try{Assert-Issue310Authority $K $P 0 ('a'*64) 123}catch{$Blocked++}
$B.performed_via_github_app=[pscustomobject]@{id=1}
try{Assert-Issue310Authority $K $P 9999999999 ('a'*64) 123}catch{$Blocked++}
$B.performed_via_github_app=$null;$B.body+=' forged'
try{Assert-Issue310Authority $K $P 9999999999 ('a'*64) 123}catch{$Blocked++}
$B.body=Get-Issue310ApprovalText $K $P ('a'*64) 123;$B.user.id=1
try{Assert-Issue310Authority $K $P 9999999999 ('a'*64) 123}catch{$Blocked++}
@{blocked=$Blocked}|ConvertTo-Json -Compress
""")
        self.assertEqual(result["blocked"], 5)

    def test_typed_snapshot_unknown_and_every_required_drift(self):
        result = self.execute(r"""
$Base=[pscustomobject]@{host='FIXTURE';sid='fixture';sha256='fake';size=1;subject='Microsoft';thumbprint='fake';dacl='fake';working_directory='fixture';source='fixture';hku_absent=$true;profile_idle=$true;slots_absent=$true;processes_idle=$true}
$Blocked=0
foreach($Name in $Base.PSObject.Properties.Name){
    $Changed=$Base|ConvertTo-Json|ConvertFrom-Json;$Changed.$Name=$null
    try{Assert-Issue310Equal $Base $Changed}catch{$Blocked++}
}
$Changed=$Base|ConvertTo-Json|ConvertFrom-Json;$Changed.hku_absent='True'
try{Assert-Issue310Equal $Base $Changed}catch{$Blocked++}
Assert-Issue310Equal $Base ($Base|ConvertTo-Json|ConvertFrom-Json)
@{blocked=$Blocked}|ConvertTo-Json -Compress
""")
        self.assertEqual(result["blocked"], 14)

    def test_unreadable_process_ownership_is_a_known_stop_not_zero(self):
        result=self.execute(r"""
$Blocked=0
foreach($Owner in @([pscustomobject]@{ReturnValue=2;Sid=$null},[pscustomobject]@{ReturnValue=0;Sid='garbage'},[pscustomobject]@{ReturnValue=0;Sid='S-1-5-21-1-2-3-1007'})){
    try{Assert-Issue310ProcessOwner $Owner 'powershell.exe' 'S-1-5-21-1-2-3-1007'}catch{$Blocked++}
}
Assert-Issue310ProcessOwner ([pscustomobject]@{ReturnValue=0;Sid='S-1-5-18'}) 'System' 'S-1-5-21-1-2-3-1007'
@{blocked=$Blocked}|ConvertTo-Json -Compress
""")
        self.assertEqual(result['blocked'],3)

    def test_independent_readback_timeout_retains_owned_cleanup_result(self):
        result=self.execute(r"""
class Issue310Reader { [object] ReadToEndAsync(){return [object]::new()} }
class Issue310Process {
    [bool]$HasExited=$false
    [bool]$Killed=$false
    [bool]$Disposed=$false
    [bool]$DenyKill=$false
    [Issue310Reader]$StandardOutput=[Issue310Reader]::new()
    [Issue310Reader]$StandardError=[Issue310Reader]::new()
    [void] Kill(){if($this.DenyKill){throw 'SYNTHETIC_DENIED'};$this.Killed=$true;$this.HasExited=$true}
    [bool] WaitForExit([int]$Timeout){return $this.HasExited}
    [void] Dispose(){$this.Disposed=$true}
}
function Start-Issue310Postread {param($Packet,$Plan,$Hash,$PidToObserve) return $script:Process}
function Wait-Issue310Read {param($Task,$Milliseconds) throw 'SYNTHETIC_TIMEOUT'}
$Out=@()
foreach($Denied in @($false,$true)){
    $script:Process=[Issue310Process]::new();$script:Process.DenyKill=$Denied
    $Report=Invoke-Issue310Postread ([pscustomobject]@{}) ([pscustomobject]@{}) ('a'*64) 0
    $Out+=@{report=$Report;killed=$Process.Killed;disposed=$Process.Disposed}
}
$Out|ConvertTo-Json -Depth 6 -Compress
""")
        for r in result:
            self.assertFalse(r['report']['available'])
            self.assertTrue(r['disposed'])
            self.assertEqual(r['report']['reason'],'POSTREAD_UNAVAILABLE_OR_DEADLINE')
        self.assertTrue(result[0]['report']['owned_exit_confirmed'])
        self.assertFalse(result[1]['report']['owned_exit_confirmed'])

    def test_claim_two_processes_partial_file_and_no_replay(self):
        body = r"""
$Path=Join-Path $env:ISSUE310_TEMP 'fixed-operation.claim'
try{$Claim=New-Issue310Claim $Path ('a'*64);Start-Sleep -Milliseconds 250;$Claim.Dispose();@{claimed=$true}|ConvertTo-Json -Compress}
catch{@{claimed=$false}|ConvertTo-Json -Compress}
"""
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            commands = [subprocess.Popen(**self.command(body, temp)) for _ in range(2)]
            reports = []
            for process in commands:
                out, err = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, err)
                reports.append(json.loads(out)["claimed"])
            self.assertEqual(sum(reports), 1)
            self.assertFalse(self.execute(body, temp)["claimed"])
            partial = Path(temp) / "partial"
            partial.mkdir()
            (partial / "fixed-operation.claim").write_bytes(b"")
            self.assertFalse(self.execute(body, partial)["claimed"])
            self.assertEqual((partial / "fixed-operation.claim").read_bytes(), b"")

    def test_execution_sequence_gates_cancellation_timeouts_and_poststate(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            result = self.execute(r"""
$Root=$env:ISSUE310_TEMP
$Candidate=Join-Path $Root 'fake-diagnostic.ps1'
[IO.File]::WriteAllText($Candidate,'if($global:Issue310Mode -eq ''throw''){throw ''SYNTHETIC_START_FAILURE''};if($global:Issue310Mode -eq ''malformed''){''not-json''}else{$global:Issue310Report | ConvertTo-Json -Depth 10 -Compress}')
$Dummy=Join-Path $Root 'dummy';[IO.File]::WriteAllText($Dummy,'SYNTHETIC')
$script:Prompts=0;$script:Gates=0;$script:FailGate=0;$script:PostUnknown=$false
$script:K=[pscustomobject]@{entry=[pscustomobject]@{path=$Dummy};candidate=[pscustomobject]@{path=$Candidate};plan=[pscustomobject]@{path=$Dummy;sha256=('a'*64)};proposal=[pscustomobject]@{path=$Dummy};baseline=[pscustomobject]@{path=$Dummy};approved_scope=[pscustomobject]@{path=$Dummy};packet_path=$Dummy;claim_path='';expected_facts=[pscustomobject]@{source=[pscustomobject]@{attributes=1;bytes=2;sha256='fake';last_write_utc='fake'}}}
$P=[pscustomobject]@{executable=$Dummy}
function Assert-Issue310PreEffect {param($Packet,$Plan,$Hash,$Size,$DecisionId,$Reserve,[switch]$Claimed) $script:Gates++;if($script:FailGate -eq $script:Gates){throw 'SYNTHETIC_GATE_STOP'}}
function Assert-Issue310Window {param($Plan,$ReserveSeconds)}
function Read-Host {param($Prompt) return ('a'*64)}
function Get-Credential {param($UserName,$Message) $script:Prompts++;return [pscredential]::new('WOBBUFFET\ac-runner',(ConvertTo-SecureString 'SYNTHETIC_ONLY' -AsPlainText -Force))}
function Assert-Issue310ApprovedScope {param($Packet,$Facts,[switch]$Post)}
function Invoke-Issue310Postread {param($Packet,$Plan,$Hash,$PidToObserve) $script:Postreads++;return [pscustomobject]@{available=(-not $script:PostUnknown);owned_exit_confirmed=$true;owned_pid_absent=$true;facts=[pscustomobject]@{source=[pscustomobject]@{attributes=1}}}}
function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec) return @()}
$Out=@()
foreach($Case in @('success','missing-b','preprompt-expiry','postprompt-expiry','startup-timeout','collector-timeout','exit-failure','late-logon','forged-boolean','throw','malformed')){
    $script:Prompts=0;$script:Gates=0;$script:FailGate=0;$script:PostUnknown=$false
    $script:Postreads=0;$global:Issue310Mode=$Case
    $K.claim_path=Join-Path $Root ($Case+'.claim')
    $global:Issue310Report=[pscustomobject]@{status='DIAGNOSTIC_POLICY_OBSERVED';startup_confirmed=$true;policy_observed=$true;broker_exit_confirmed=$true;independent_poststate=$true;independent_process_exit=$true;worker=[pscustomobject]@{status='TARGET_CONTEXT_RELEASED';owned_exit_confirmed=$true;release_confirmed=$true;target_exit_code=0;target_pid=123}}
    switch($Case){
        'missing-b' {$script:FailGate=1}
        'preprompt-expiry' {$script:FailGate=2}
        'postprompt-expiry' {$script:FailGate=3}
        'startup-timeout' {$global:Issue310Report.startup_confirmed=$false}
        'collector-timeout' {$global:Issue310Report.policy_observed=$false;$global:Issue310Report.status='TARGET_CONTEXT_PROBE_BLOCKED'}
        'exit-failure' {$global:Issue310Report.worker.target_exit_code=9}
        'late-logon' {$script:PostUnknown=$true}
        'forged-boolean' {$global:Issue310Report.startup_confirmed='True'}
    }
    $Status=''
    try{$Status=(Invoke-Issue310Execution $K $P ('a'*64) 1 9999999999).status}catch{$Status=$_.Exception.Message}
    $Out+=@{case=$Case;status=$Status;prompts=$script:Prompts;claim=(Test-Path -LiteralPath $K.claim_path);postreads=$script:Postreads}
}
$Out|ConvertTo-Json -Compress
""", temp)
        by_case = {r["case"]: r for r in result}
        self.assertEqual(by_case["success"]["status"], "DIAGNOSTIC_POLICY_OBSERVED")
        self.assertFalse(by_case["missing-b"]["claim"])
        self.assertEqual(by_case["missing-b"]["prompts"], 0)
        self.assertEqual(by_case["preprompt-expiry"]["prompts"], 0)
        for case in ("missing-b", "preprompt-expiry", "postprompt-expiry"):
            self.assertEqual(by_case[case]["status"], "SYNTHETIC_GATE_STOP")
            self.assertEqual(by_case[case]["postreads"], 0)
        for case in ("startup-timeout", "collector-timeout", "exit-failure", "late-logon", "forged-boolean", "throw", "malformed"):
            self.assertEqual(by_case[case]["status"], "STOP_PARTIAL_PROFILE_STATE")
            self.assertTrue(by_case[case]["claim"])
            self.assertEqual(by_case[case]["postreads"], 1)


if __name__ == "__main__":
    unittest.main()
