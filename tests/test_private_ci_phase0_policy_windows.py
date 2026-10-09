"""Execute the collector's policy probe under Windows PowerShell 5.1.

Only OS observations use in-memory fixtures. No registry writes, hive loads,
account/profile changes, target logon/code, or pilot effects are performed.
"""
import json
import os
import subprocess
import unittest

from agent_controller.private_ci_phase0_collector import _local_probe


SID = "S-1-5-21-111-222-333-1007"
POLICY_PATH = r"Software\Policies\Microsoft\Windows\PowerShell"

HARNESS = r"""
$ErrorActionPreference = 'Stop'
class FixtureKey {
    [hashtable]$Values = @{}
    [hashtable]$Kinds = @{}
    [hashtable]$Children = @{}
    [bool]$Denied = $false
    [bool]$Disposed = $false
    [string]$OpenedName = ''
    [object] OpenSubKey([string]$Name, [bool]$Writable) {
        if ($Writable) { throw 'unexpected writable registry access' }
        if ($this.Denied) { throw [UnauthorizedAccessException]::new('fixture access denied') }
        $this.OpenedName = $Name
        return $this.Children[$Name]
    }
    [string[]] GetValueNames() { return @($this.Values.Keys) }
    [Microsoft.Win32.RegistryValueKind] GetValueKind([string]$Name) {
        return $this.Kinds[$Name]
    }
    [object] GetValue([string]$Name) {
        if ($this.Denied) { throw [UnauthorizedAccessException]::new('fixture value access denied') }
        return $this.Values[$Name]
    }
    [void] Dispose() { $this.Disposed = $true }
}
$Fixture = $env:PHASE0_POLICY_FIXTURE | ConvertFrom-Json
$Users = [FixtureKey]::new()
$TargetHive = [FixtureKey]::new()
$PolicyKey = [FixtureKey]::new()
$MachineHive = [FixtureKey]::new()
$MachinePolicyKey = [FixtureKey]::new()
$MachineHive.Denied = $Fixture.machine_hive_denied
$MachinePolicyKey.Denied = $Fixture.machine_value_denied
$Users.Denied = $Fixture.users_denied
$TargetHive.Denied = $Fixture.hive_denied
$PolicyKey.Denied = $Fixture.value_denied
foreach ($Property in $Fixture.values.PSObject.Properties) {
    $PolicyKey.Values[$Property.Name] = $Property.Value
    $PolicyKey.Kinds[$Property.Name] = $Fixture.kinds.($Property.Name)
}
if ($Fixture.loaded) { $Users.Children['S-1-5-21-111-222-333-1007'] = $TargetHive }
if ($Fixture.policy_present) {
    $TargetHive.Children['Software\Policies\Microsoft\Windows\PowerShell'] = $PolicyKey
}
foreach ($Property in $Fixture.machine_values.PSObject.Properties) {
    $MachinePolicyKey.Values[$Property.Name] = $Property.Value
    $MachinePolicyKey.Kinds[$Property.Name] = $Fixture.machine_kinds.($Property.Name)
}
if ($Fixture.machine_policy_present) {
    $MachineHive.Children['Software\Policies\Microsoft\Windows\PowerShell'] = $MachinePolicyKey
}
# Broker has a readable hive without UserPolicy. It must never be selected.
$Users.Children['S-1-5-21-111-222-333-1001'] = [FixtureKey]::new()
function Get-LocalUser {
    param($Name, $ErrorAction)
    [pscustomobject]@{ Name = $Name; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-111-222-333-1007' } }
}
function Get-LocalGroup { param($SID) [pscustomobject]@{ Name = 'FixtureAdministrators' } }
function Get-LocalGroupMember { param($Group, $ErrorAction) }
function Get-CimInstance { param($ClassName, $ErrorAction) }
function Get-ScheduledTask { param($ErrorAction) }
"""


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 Phase 0 policy regression")
class Phase0PolicyWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        commands = []

        def capture(*command):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "{}", "")

        _local_probe(capture, "ac-runner")
        # Execute the exact collector script; substitute only its OS registry
        # root. Cmdlet doubles above provide all other OS observations.
        cls.script = commands[0][-1].replace(
            "([Microsoft.Win32.Registry]::Users)", "$Users",
        ).replace("([Microsoft.Win32.Registry]::LocalMachine)", "$MachineHive")

    def probe(self, **changes):
        fixture = {
            "loaded": True, "policy_present": True,
            "values": {}, "kinds": {}, "users_denied": False,
            "hive_denied": False, "value_denied": False,
            "machine_values": {}, "machine_kinds": {}, "machine_policy_present": True,
            "machine_hive_denied": False, "machine_value_denied": False,
        }
        machine_policy = changes.pop("machine_policy", "Undefined")
        if machine_policy != "Undefined":
            fixture["machine_values"] = {"EnableScripts": 0 if machine_policy == "Restricted" else 1}
            fixture["machine_kinds"] = {"EnableScripts": "DWord"}
            if machine_policy != "Restricted":
                fixture["machine_values"]["ExecutionPolicy"] = machine_policy
                fixture["machine_kinds"]["ExecutionPolicy"] = "String"
        fixture.update(changes)
        environment = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
        environment["PHASE0_POLICY_FIXTURE"] = json.dumps(fixture)
        # Validate SID selection and read-only handle disposal after successful
        # execution. The fixture rejects writable opens on every key.
        postcheck = r"""
if ($Users.OpenedName -ne 'S-1-5-21-111-222-333-1007') { throw 'wrong policy SID' }
if (-not $TargetHive.Disposed) { throw 'hive handle leaked' }
if ($Fixture.policy_present -and -not $PolicyKey.Disposed) { throw 'policy handle leaked' }
if ($Fixture.machine_policy_present -and -not $MachinePolicyKey.Disposed) { throw 'machine policy handle leaked' }
"""
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", HARNESS + "\n" + self.script + "\n" + postcheck],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=environment, timeout=30, check=False,
        )

    def test_loaded_target_hive_without_policy_allows_process_bypass(self):
        for changes in ({}, {"policy_present": False}, {"machine_policy_present": False}):
            with self.subTest(changes=changes):
                completed = self.probe(**changes)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                evidence = json.loads(completed.stdout)
                self.assertTrue(evidence["powershell_version"].startswith("5.1."))
                self.assertEqual(evidence["machine_policy"], "Undefined")
                self.assertEqual(evidence["target_user_policy"], "Undefined")
                self.assertEqual(evidence["execution_policy_target_sid"], SID)
                self.assertEqual(evidence["execution_policy_target_identity"], "ac-runner")
                self.assertEqual(evidence["effective_policy_with_process_bypass"], "Bypass")

    def test_policy_mapping_and_machine_precedence(self):
        cases = [({"EnableScripts": 0}, {"EnableScripts": "DWord"}, "Restricted")]
        for policy in ("AllSigned", "RemoteSigned", "Unrestricted", "Bypass"):
            cases.append((
                {"EnableScripts": 1, "ExecutionPolicy": policy.lower()},
                {"EnableScripts": "DWord", "ExecutionPolicy": "String"}, policy,
            ))
        for values, kinds, expected in cases:
            with self.subTest(expected=expected):
                completed = self.probe(values=values, kinds=kinds)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                evidence = json.loads(completed.stdout)
                self.assertEqual(evidence["target_user_policy"], expected)
                self.assertEqual(evidence["effective_policy_with_process_bypass"], expected)
        completed = self.probe(machine_policy="AllSigned", values={"EnableScripts": 0}, kinds={"EnableScripts": "DWord"})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["effective_policy_with_process_bypass"], "AllSigned")

    def test_unloaded_or_unreadable_target_never_uses_readable_broker_hive(self):
        for changes, message in (
            ({"loaded": False}, "target SID hive is not loaded"),
            ({"users_denied": True}, "target UserPolicy unreadable/unknown"),
            ({"hive_denied": True}, "target UserPolicy unreadable/unknown"),
            ({"value_denied": True, "values": {"EnableScripts": 0}, "kinds": {"EnableScripts": "DWord"}}, "target UserPolicy unreadable/unknown"),
        ):
            with self.subTest(changes=changes):
                completed = self.probe(**changes)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(message, completed.stderr)
                self.assertEqual(completed.stdout.strip(), "")

    def test_malformed_target_policy_is_unknown(self):
        cases = (
            ({"EnableScripts": "1"}, {"EnableScripts": "String"}),
            ({"EnableScripts": 2}, {"EnableScripts": "DWord"}),
            ({"EnableScripts": 1}, {"EnableScripts": "DWord"}),
            ({"EnableScripts": 1, "ExecutionPolicy": "unrecognized"}, {"EnableScripts": "DWord", "ExecutionPolicy": "String"}),
            ({"EnableScripts": 1, "ExecutionPolicy": 4}, {"EnableScripts": "DWord", "ExecutionPolicy": "DWord"}),
        )
        for values, kinds in cases:
            with self.subTest(values=values):
                completed = self.probe(values=values, kinds=kinds)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("target UserPolicy unknown", completed.stderr)
                self.assertEqual(completed.stdout.strip(), "")

    def test_malformed_or_unreadable_machine_policy_cannot_become_undefined(self):
        cases = (
            {"machine_values": {"EnableScripts": 1}, "machine_kinds": {"EnableScripts": "DWord"}},
            {"machine_values": {"EnableScripts": 2}, "machine_kinds": {"EnableScripts": "DWord"}},
            {"machine_values": {"EnableScripts": "1"}, "machine_kinds": {"EnableScripts": "String"}},
            {"machine_values": {"EnableScripts": 1, "ExecutionPolicy": "Unknown"}, "machine_kinds": {"EnableScripts": "DWord", "ExecutionPolicy": "String"}},
            {"machine_hive_denied": True},
            {"machine_value_denied": True, "machine_values": {"EnableScripts": 0}, "machine_kinds": {"EnableScripts": "DWord"}},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                completed = self.probe(**changes)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("MachinePolicy unreadable/unknown", completed.stderr)
                self.assertEqual(completed.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
