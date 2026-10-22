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

SCOPED = r"""
$K=[pscustomobject]@{candidate=[pscustomobject]@{path='C:\Review\candidate.ps1'};entry=[pscustomobject]@{path='C:\Review\entry.ps1'};claim_path='C:\Handoff\operation.claim'}
$P=[pscustomobject]@{target_sid='S-1-5-21-1-2-3-1007';profile_path='C:\Users\ac-runner'}
$Target=[pscustomobject]@{sid=$P.target_sid;profile_path=$P.profile_path;profile_list_path=$P.profile_path;loaded=$false;hku_absent=$true;hku_classes_absent=$true;sessions=0}
$script:Queries=@();$script:Inventory=@();$script:Owners=@{}
function New-Process($Id,$Parent,$Name,$Image){[pscustomobject]@{ProcessId=$Id;ParentProcessId=$Parent;SessionId=0;Name=$Name;ExecutablePath=$Image}}
function Get-CimInstance {param($ClassName,$Property,$OperationTimeoutSec)
    if($ClassName -cne 'Win32_Process' -or ($Property -join ',') -cne 'ProcessId,ParentProcessId,SessionId,Name,ExecutablePath'){throw 'UNSCOPED_METADATA_QUERY'}
    return $script:Inventory
}
function Invoke-CimMethod {param($InputObject,$MethodName,$OperationTimeoutSec)
    if($MethodName -cne 'GetOwnerSid'){throw 'UNEXPECTED_METHOD'}
    $script:Queries+=@($InputObject.ProcessId)
    return $script:Owners[$InputObject.ProcessId]
}
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
$B.user.id=22843471;$K.authority.a_body_sha256=('0'*64)
try{Assert-Issue310Authority $K $P 9999999999 ('a'*64) 123}catch{$Blocked++}
@{blocked=$Blocked}|ConvertTo-Json -Compress
""")
        self.assertEqual(result["blocked"], 6)

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

    def test_scoped_133_null_ambient_images_and_139_unqueried_owners(self):
        result = self.execute(SCOPED + r"""
$script:Inventory+=@(New-Process 0 0 'System Idle Process' $null)
# Real WOBBUFFET read-only observation included a NULL-image PID4.
foreach($Id in 4..136){
    $Name=if($Id -eq 4){'System'}else{'svchost.exe'}
    $script:Inventory+=@(New-Process $Id 4 $Name $null)
    $script:Owners[$Id]=[pscustomobject]@{ReturnValue=2;Sid=$null}
}
foreach($Id in 200..205){
    $script:Inventory+=@(New-Process $Id 4 'svchost.exe' 'C:\Windows\System32\svchost.exe')
    $script:Owners[$Id]=[pscustomobject]@{ReturnValue=2;Sid=$null}
}
$script:Inventory+=@(New-Process 300 1 'powershell.exe' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
$script:Owners[300]=[pscustomobject]@{ReturnValue=0;Sid='S-1-5-21-1-2-3-1002'}
$Report=Get-Issue310ProcessObservation $K $P $Target 0
@{report=$Report;queries=@($script:Queries)}|ConvertTo-Json -Depth 5 -Compress
""")
        self.assertEqual(result['queries'], [300])
        self.assertEqual(result['report']['unverified_ambient_process_count'], 139)
        self.assertEqual(result['report']['unverified_ambient_image_path_count'], 133)
        self.assertEqual(result['report']['related_owner_checked_count'], 1)
        self.assertFalse(result['report']['ownership_complete'])
        self.assertFalse(result['report']['image_path_complete'])
        self.assertEqual(result['report']['limitation'], 'UNVERIFIED_AMBIENT_PROCESS_VISIBILITY')

    def test_scoped_related_unknown_target_and_runner_activity_stop(self):
        result = self.execute(SCOPED + r"""
$Out=@()
foreach($Case in @('unknown','malformed','target','runner','path-runner','descendant','bound-pid','bound-descendant','operation-path')){
    $script:Queries=@();$script:Owners=@{}
    $script:Inventory=@(New-Process 300 1 'powershell.exe' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
    $script:Owners[300]=[pscustomobject]@{ReturnValue=0;Sid='S-1-5-18'}
    $Bound=0
    switch($Case){
        'unknown' {$script:Owners[300]=[pscustomobject]@{ReturnValue=2;Sid=$null}}
        'malformed' {$script:Owners[300]=[pscustomobject]@{ReturnValue=0;Sid='garbage'}}
        'target' {$script:Owners[300].Sid=$P.target_sid}
        'runner' {$script:Inventory[0]=New-Process 300 1 'Runner.Listener.exe' 'C:\Program Files\Agent\Runner.Listener.exe'}
        'path-runner' {$script:Inventory[0]=New-Process 300 1 'node.exe' 'C:\Program Files\actions\node.exe'}
        'descendant' {$script:Inventory+=@(New-Process 301 300 'svchost.exe' 'C:\Windows\System32\svchost.exe');$script:Owners[301]=[pscustomobject]@{ReturnValue=2;Sid=$null}}
        'bound-pid' {$Bound=301;$script:Inventory=@(New-Process 301 1 'svchost.exe' 'C:\Windows\System32\svchost.exe');$script:Owners[301]=[pscustomobject]@{ReturnValue=2;Sid=$null}}
        'bound-descendant' {$Bound=299;$script:Inventory=@(New-Process 301 299 'svchost.exe' 'C:\Windows\System32\svchost.exe');$script:Owners[301]=[pscustomobject]@{ReturnValue=2;Sid=$null}}
        'operation-path' {$script:Inventory=@(New-Process 301 1 'ordinary.exe' 'C:\Review\ordinary.exe');$script:Owners[301]=[pscustomobject]@{ReturnValue=2;Sid=$null}}
    }
    $Status='UNEXPECTED_PASS'
    try{$null=Get-Issue310ProcessObservation $K $P $Target $Bound}catch{$Status=$_.Exception.Message}
    $Out+=@{case=$Case;status=$Status;queries=@($script:Queries)}
}
$Out|ConvertTo-Json -Depth 5 -Compress
""")
        by_case = {r['case']: r for r in result}
        for case in ('unknown', 'malformed', 'descendant', 'bound-pid', 'bound-descendant', 'operation-path'):
            self.assertEqual(by_case[case]['status'], 'PROCESS_OWNER_UNKNOWN')
        for case in ('target', 'runner', 'path-runner'):
            self.assertEqual(by_case[case]['status'], 'TARGET_OR_RUNNER_PROCESS')
        self.assertEqual(by_case['descendant']['queries'], [300, 301])
        self.assertEqual(by_case['bound-pid']['queries'], [301])
        self.assertEqual(by_case['runner']['queries'], [])

    def test_scoped_missing_target_evidence_blocks_before_process_queries(self):
        result = self.execute(SCOPED + r"""
$Out=@()
foreach($Name in @('sid','profile_path','profile_list_path','loaded','hku_absent','hku_classes_absent','sessions')){
    foreach($Bad in @('missing','unknown','active')){
        $T=$Target|ConvertTo-Json|ConvertFrom-Json
        if($Bad -eq 'missing'){$T.PSObject.Properties.Remove($Name)}
        elseif($Bad -eq 'unknown'){$T.$Name=$null}
        else{$T.$Name=$(switch($Name){'loaded'{$true};'sessions'{1};'hku_absent'{$false};'hku_classes_absent'{$false};default{'wrong'}})}
        $Blocked=$false
        try{$null=Get-Issue310ProcessObservation $K $P $T 0}catch{$Blocked=$true}
        $Out+=@{blocked=$Blocked;queries=@($script:Queries)}
    }
}
$Out|ConvertTo-Json -Depth 4 -Compress
""")
        self.assertEqual(len(result), 21)
        self.assertTrue(all(r['blocked'] and r['queries'] == [] for r in result))

    def test_scoped_ambient_missing_images_record_uncertainty_and_bad_metadata_stop(self):
        result = self.execute(SCOPED + r"""
$Out=@()
foreach($Case in @('missing-path','relative','dot-path','unc','wrong-name','outside','prefix',
                    'related-null-image','related-bad-path','descendant-null-image','bound-null-image',
                    'runner-null-image','missing-session','boolean-pid','duplicate','empty','overflow')){
    $script:Queries=@();$script:Owners=@{}
    $script:Inventory=@(New-Process 100 4 'service.exe' 'C:\Windows\System32\service.exe')
    $Bound=0
    switch($Case){
        'missing-path' {$script:Inventory[0].ExecutablePath=$null}
        'relative' {$script:Inventory[0].ExecutablePath='service.exe'}
        'dot-path' {$script:Inventory[0].ExecutablePath='C:\Windows\System32\..\service.exe'}
        'unc' {$script:Inventory[0].ExecutablePath='\\host\Windows\service.exe'}
        'wrong-name' {$script:Inventory[0].Name='other.exe'}
        'outside' {$script:Inventory[0].ExecutablePath='C:\Unknown\service.exe'}
        'prefix' {$script:Inventory[0].ExecutablePath='C:\Windows-old\service.exe'}
        'related-null-image' {$script:Inventory[0]=New-Process 100 4 'powershell.exe' $null}
        'related-bad-path' {$script:Inventory[0]=New-Process 100 4 'powershell.exe' 'powershell.exe'}
        'descendant-null-image' {$script:Inventory=@((New-Process 90 4 'powershell.exe' 'C:\Windows\powershell.exe'),(New-Process 100 90 'service.exe' $null));$script:Owners[90]=[pscustomobject]@{ReturnValue=0;Sid='S-1-5-18'}}
        'bound-null-image' {$Bound=100;$script:Inventory[0].ExecutablePath=$null}
        'runner-null-image' {$script:Inventory[0]=New-Process 100 4 'Runner.Listener.exe' $null}
        'missing-session' {$script:Inventory[0].SessionId=$null}
        'boolean-pid' {$script:Inventory[0].ProcessId=$true}
        'duplicate' {$script:Inventory+=@($script:Inventory[0])}
        'empty' {$script:Inventory=@()}
        'overflow' {$script:Inventory=@(1..4097|ForEach-Object {New-Process $_ 0 'service.exe' 'C:\Windows\service.exe'})}
    }
    $Status='PASS';$Missing=-1
    try{$R=Get-Issue310ProcessObservation $K $P $Target $Bound;$Missing=$R.unverified_ambient_image_path_count}catch{$Status=$_.Exception.Message}
    $Out+=@{case=$Case;status=$Status;missing=$Missing;queries=@($script:Queries)}
}
$Out|ConvertTo-Json -Depth 4 -Compress
""")
        by_case={r['case']:r for r in result}
        for case in ('missing-path','relative','dot-path','unc','wrong-name'):
            self.assertEqual(by_case[case]['status'],'PASS')
            self.assertEqual(by_case[case]['missing'],1)
            self.assertEqual(by_case[case]['queries'],[])
        for case in ('outside','prefix'):
            self.assertEqual(by_case[case]['status'],'PASS')
            self.assertEqual(by_case[case]['missing'],0)
        for case in ('related-null-image','related-bad-path','descendant-null-image','bound-null-image'):
            self.assertEqual(by_case[case]['status'],'PROCESS_RELEVANCE_UNKNOWN')
        self.assertEqual(by_case['runner-null-image']['status'],'TARGET_OR_RUNNER_PROCESS')
        for case in ('missing-session','boolean-pid','duplicate'):
            self.assertEqual(by_case[case]['status'],'PROCESS_METADATA_UNKNOWN')
        for case in ('empty','overflow'):
            self.assertEqual(by_case[case]['status'],'PROCESS_METADATA_LIMIT')

    def test_positive_image_host_and_normalized_operation_root_stop_even_if_name_conflicts(self):
        result = self.execute(SCOPED + r"""
$Out=@()
foreach($Case in @('image-host-name-contradiction','normalized-operation-root','image-host-null-child','normalized-root-null-child')){
    $script:Queries=@();$script:Owners=@{}
    if($Case -match 'image-host'){
        $script:Inventory=@(New-Process 300 4 'ordinary.exe' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
    }else{
        $script:Inventory=@(New-Process 300 4 'ordinary.exe' 'C:\Windows\..\Review\ordinary.exe')
    }
    if($Case -match 'null-child'){
        $script:Inventory+=@(New-Process 301 300 'service.exe' $null)
    }
    $script:Owners[300]=[pscustomobject]@{ReturnValue=0;Sid='S-1-5-18'}
    $Status='UNEXPECTED_PASS'
    try{$null=Get-Issue310ProcessObservation $K $P $Target 0}catch{$Status=$_.Exception.Message}
    $Out+=@{case=$Case;status=$Status;queries=@($script:Queries)}
}
$Out|ConvertTo-Json -Depth 4 -Compress
""")
        self.assertEqual(len(result),4)
        for row in result:
            self.assertEqual(row['status'],'PROCESS_RELEVANCE_UNKNOWN',row)
            self.assertEqual(row['queries'],[],row)

    def test_mandatory_process_name_requires_actual_string_before_ambient_fallback(self):
        result = self.execute(SCOPED + r"""
$Out=@()
foreach($Case in @('number','boolean','null','array')){
    $script:Queries=@();$script:Owners=@{}
    $script:Inventory=@(New-Process 300 4 'ordinary.exe' $null)
    switch($Case){
        'number' {$script:Inventory[0].Name=42}
        'boolean' {$script:Inventory[0].Name=$true}
        'null' {$script:Inventory[0].Name=$null}
        'array' {$script:Inventory[0].Name=@('ordinary.exe')}
    }
    $Status='UNEXPECTED_PASS'
    try{$null=Get-Issue310ProcessObservation $K $P $Target 0}catch{$Status=$_.Exception.Message}
    $Out+=@{case=$Case;status=$Status;queries=@($script:Queries)}
}
$Out|ConvertTo-Json -Depth 4 -Compress
""")
        self.assertEqual(len(result),4)
        for row in result:
            self.assertEqual(row['status'],'PROCESS_METADATA_UNKNOWN',row)
            self.assertEqual(row['queries'],[],row)

    def test_dynamic_observation_does_not_hide_fixed_fact_drift(self):
        result = self.execute(r"""
$Before=[pscustomobject]@{profile=[pscustomobject]@{owner='target';dacl='original'};process_observation=[pscustomobject]@{unverified_ambient_process_count=139}}
$After=$Before|ConvertTo-Json -Depth 5|ConvertFrom-Json
$After.process_observation.unverified_ambient_process_count=140
Assert-Issue310StaticFacts $Before $After
$After.profile.dacl='drift'
$Blocked=$false
try{Assert-Issue310StaticFacts $Before $After}catch{$Blocked=$true}
$TypedBlocked=$false
try{Assert-Issue310StaticFacts ([pscustomobject]@{count=1}) ([pscustomobject]@{count=[double]1})}catch{$TypedBlocked=$true}
@{blocked=$Blocked;typed_blocked=$TypedBlocked;before=$Before.process_observation.unverified_ambient_process_count;after=$After.process_observation.unverified_ambient_process_count}|ConvertTo-Json -Compress
""")
        self.assertEqual(result, dict(blocked=True, typed_blocked=True, before=139, after=140))

    def test_scoped_path_boundaries_case_and_descendant_closure(self):
        result = self.execute(SCOPED + r"""
$K.candidate.path='C:\Program Files\Review\candidate.ps1';$K.entry.path='C:\Program Files\Review\entry.ps1'
$script:Inventory=@(
    (New-Process 303 302 'child.exe' 'C:\Windows\child.exe'),
    (New-Process 302 301 'middle.exe' 'C:\Windows\middle.exe'),
    (New-Process 301 1 'ordinary.exe' 'c:\program files\review\ordinary.exe'),
    (New-Process 304 1 'ordinary.exe' 'C:\Program Files\Reviewer\ordinary.exe'))
foreach($Id in 301..303){$script:Owners[$Id]=[pscustomobject]@{ReturnValue=0;Sid='S-1-5-18'}}
$Report=Get-Issue310ProcessObservation $K $P $Target 0
@{report=$Report;queries=@($script:Queries)}|ConvertTo-Json -Depth 5 -Compress
""")
        self.assertEqual(result['queries'], [303, 302, 301])
        self.assertEqual(result['report']['unverified_ambient_process_count'], 1)

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
function Assert-Issue310PreEffect {param($Packet,$Plan,$Hash,$Size,$DecisionId,$Reserve,[switch]$Claimed) $script:Gates++;if($script:FailGate -eq $script:Gates){throw 'SYNTHETIC_GATE_STOP'};return [pscustomobject]@{limitation='UNVERIFIED_AMBIENT_PROCESS_VISIBILITY';unverified_ambient_process_count=139}}
function Assert-Issue310Window {param($Plan,$ReserveSeconds)}
function Read-Host {param($Prompt) return ('a'*64)}
function Get-Credential {param($UserName,$Message) $script:Prompts++;return [pscredential]::new('WOBBUFFET\ac-runner',(ConvertTo-SecureString 'SYNTHETIC_ONLY' -AsPlainText -Force))}
function Assert-Issue310ApprovedScope {param($Packet,$Facts,[switch]$Post)}
function Invoke-Issue310Postread {param($Packet,$Plan,$Hash,$PidToObserve) $script:Postreads++;return [pscustomobject]@{available=(-not $script:PostUnknown);owned_exit_confirmed=($global:Issue310Mode -ne 'reader-exit-unknown');owned_pid_absent=($global:Issue310Mode -ne 'pid-present');facts=[pscustomobject]@{source=[pscustomobject]@{attributes=$(if($global:Issue310Mode -eq 'restoration-drift'){9}else{1})};process_observation=[pscustomobject]@{limitation='UNVERIFIED_AMBIENT_PROCESS_VISIBILITY';unverified_ambient_process_count=140}}}}
function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec) return @()}
$Out=@()
foreach($Case in @('success','missing-b','preprompt-expiry','postprompt-expiry','startup-timeout','collector-timeout','exit-failure','late-logon','forged-boolean','throw','malformed','reader-exit-unknown','pid-present','restoration-drift')){
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
    $Observations=@();$PostCount=0
    try{$Report=Invoke-Issue310Execution $K $P ('a'*64) 1 9999999999;$Status=$Report.status;$Observations=@($Report.preflight_observations);$PostCount=$Report.postread.facts.process_observation.unverified_ambient_process_count}catch{$Status=$_.Exception.Message}
    $Out+=@{case=$Case;status=$Status;prompts=$script:Prompts;claim=(Test-Path -LiteralPath $K.claim_path);postreads=$script:Postreads;observations=$Observations;post_count=$PostCount}
}
$Out|ConvertTo-Json -Depth 6 -Compress
""", temp)
        by_case = {r["case"]: r for r in result}
        self.assertEqual(by_case["success"]["status"], "DIAGNOSTIC_POLICY_OBSERVED")
        self.assertEqual(len(by_case['success']['observations']), 3)
        self.assertTrue(all(r['unverified_ambient_process_count'] == 139 for r in by_case['success']['observations']))
        self.assertEqual(by_case['success']['post_count'], 140)
        self.assertFalse(by_case["missing-b"]["claim"])
        self.assertEqual(by_case["missing-b"]["prompts"], 0)
        self.assertEqual(by_case["preprompt-expiry"]["prompts"], 0)
        for case in ("missing-b", "preprompt-expiry", "postprompt-expiry"):
            self.assertEqual(by_case[case]["status"], "SYNTHETIC_GATE_STOP")
            self.assertEqual(by_case[case]["postreads"], 0)
        for case in ("startup-timeout", "collector-timeout", "exit-failure", "late-logon", "forged-boolean", "throw", "malformed", "reader-exit-unknown", "pid-present", "restoration-drift"):
            self.assertEqual(by_case[case]["status"], "STOP_PARTIAL_PROFILE_STATE")
            self.assertTrue(by_case[case]["claim"])
            self.assertEqual(by_case[case]["postreads"], 1)


if __name__ == "__main__":
    unittest.main()
