"""Execute the trusted workflow gates with real Windows ACL objects and fake IO.

No accounts, credentials, runners, or host ACLs are provisioned by these tests.
The assertions check resulting authority independently of the construction code.
"""
import base64
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_self_hosted_fallback_workflow import WORKFLOW, extract_run_blocks


@unittest.skipUnless(sys.platform == "win32", "Windows ACL contract regression")
class FallbackAclTests(unittest.TestCase):
    def run_gate(self, script):
        shell = shutil.which("powershell.exe")
        self.assertIsNotNone(shell)
        # A Python child of pwsh can inherit incompatible PowerShell 7 modules.
        script = "$env:PSModulePath = Join-Path $PSHOME 'Modules'\n" + script
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_credential_requires_complete_read_and_delete_without_extra_authority(self):
        block = extract_run_blocks(WORKFLOW.read_text(encoding="utf-8"))[0]
        gate = block[block.index("$credentialAcl ="):block.index("$headers =")]
        scenarios = {
            "Read, Synchronize": False,  # The actual first-pilot ACL.
            "ReadAttributes, Delete": False,  # Partial Read is insufficient.
            "Read, Delete": True,
            "Read, Delete, Write": False,
            "Read, Delete, ChangePermissions": False,
            "Read, Delete, TakeOwnership": False,
            "FullControl": False,
        }
        for rights, accepted in scenarios.items():
            for extra in ("none", "target", "broad", "deny", "owner"):
                with self.subTest(rights=rights, extra=extra):
                    script = r"""
                    $ErrorActionPreference = 'Stop'
                    $controlSid = 'S-1-5-21-100-200-300-1001'
                    $targetSid = 'S-1-5-21-100-200-300-1002'
                    $adminSid = 'S-1-5-32-544'
                    $credentialFile = 'unused'
                    $fixture = [Security.AccessControl.FileSecurity]::new()
                    $fixture.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
                    $fixture.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                        [Security.Principal.SecurityIdentifier]::new($controlSid), $rights, 'Allow'))
                    if ($extra -in @('target', 'broad', 'deny')) {
                        $sid = $targetSid
                        $type = 'Allow'
                        if ($extra -eq 'broad') { $sid = 'S-1-5-11' }
                        if ($extra -eq 'deny') { $sid = $controlSid; $type = 'Deny' }
                        $fixture.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                            [Security.Principal.SecurityIdentifier]::new($sid), 'Read', $type))
                    }
                    if ($extra -eq 'owner') { $fixture.SetOwner([Security.Principal.SecurityIdentifier]::new($controlSid)) }
                    function Get-Acl { $fixture }
                    """
                    script = f"$rights = '{rights}'\n$extra = '{extra}'\n" + script
                    script += "\ntry {\n" + gate + "\n'ACCEPT'\n} catch { 'REJECT' }"
                    self.assertEqual(self.run_gate(script), "ACCEPT" if accepted and extra == "none" else "REJECT")

    def test_checkout_children_keep_control_and_target_denial(self):
        block = extract_run_blocks(WORKFLOW.read_text(encoding="utf-8"))[1]
        gate = block[block.index("$systemSid ="):]
        for scenario in ("inherited", "empty", "reparse", "corrupt", "late_corrupt", "unknown_owner"):
            with self.subTest(scenario=scenario):
                harness = r"""
                $ErrorActionPreference = 'Stop'
                $controlSid = 'S-1-5-21-100-200-300-1001'
                $targetSid = 'S-1-5-21-100-200-300-1002'
                $env:GITHUB_WORKSPACE = 'root'
                $nodes = @{}
                $acls = @{}
                $script:writes = @()
                foreach ($path in @('root', 'hooks', 'applypatch-msg.sample')) {
                    $nodes[$path] = [pscustomobject]@{
                        FullName = $path; Parent = $null
                        PSIsContainer = ($path -ne 'applypatch-msg.sample')
                        Attributes = [IO.FileAttributes]::Normal
                    }
                    $nodes[$path] | Add-Member ScriptMethod SetAccessControl {
                        param($acl)
                        Set-Acl -LiteralPath $this.FullName -AclObject $acl
                    }
                    $acl = [Security.AccessControl.FileSecurity]::new()
                    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;BA)')
                    $acls[$path] = $acl
                }
                if ($scenario -eq 'inherited') {
                    $acls['applypatch-msg.sample'].SetSecurityDescriptorSddlForm('O:BAD:(A;ID;FA;;;BA)')
                } else { $acls['applypatch-msg.sample'].SetSecurityDescriptorSddlForm('O:BAD:P') }
                if ($scenario -eq 'reparse') { $nodes['hooks'].Attributes = [IO.FileAttributes]::ReparsePoint }
                if ($scenario -eq 'unknown_owner') { $acls['hooks'].SetOwner([Security.Principal.SecurityIdentifier]::new($targetSid)) }
                function Get-Item { param($LiteralPath, [switch]$Force, $ErrorAction) $nodes[$LiteralPath] }
                function Get-ChildItem {
                    param($LiteralPath, [switch]$Force, $ErrorAction)
                    if ($LiteralPath -eq 'root') { $nodes['hooks'] }
                    if ($LiteralPath -eq 'hooks') { $nodes['applypatch-msg.sample'] }
                }
                function Get-Acl {
                    param($LiteralPath, $ErrorAction)
                    # Return a detached descriptor, as a real read would.
                    $copy = [Security.AccessControl.FileSecurity]::new()
                    $copy.SetSecurityDescriptorSddlForm($acls[$LiteralPath].Sddl)
                    $copy
                }
                function Set-Acl {
                    param($LiteralPath, $AclObject, $ErrorAction)
                    $script:writes += $LiteralPath
                    $acls[$LiteralPath] = $AclObject
                    if ($scenario -eq 'corrupt' -and $LiteralPath -eq 'applypatch-msg.sample') {
                        $acls[$LiteralPath].SetSecurityDescriptorSddlForm('O:BAD:P')
                    }
                    if ($scenario -eq 'late_corrupt' -and $LiteralPath -eq 'root') {
                        $acls['applypatch-msg.sample'].SetSecurityDescriptorSddlForm('O:BAD:P')
                    }
                }
                # Model the pilot: native commands report success but a child is empty.
                function icacls.exe { $global:LASTEXITCODE = 0 }
                """
                assertions = r"""
                foreach ($path in $acls.Keys) {
                    $acl = $acls[$path]
                    if (-not $acl.AreAccessRulesProtected -or $acl.Access.Count -ne 5) { throw 'missing explicit child authority' }
                    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $controlSid)) {
                        $rules = @($acl.Access | Where-Object {
                            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid
                        })
                        if ($rules.Count -ne 1 -or $rules[0].AccessControlType -ne 'Allow' -or
                            [int]$rules[0].FileSystemRights -ne 2032127 -or $rules[0].IsInherited) { throw 'cleanup authority lost' }
                    }
                    $target = @($acl.Access | Where-Object {
                        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $targetSid
                    })
                    $allow = @($target | Where-Object AccessControlType -eq 'Allow')
                    $deny = @($target | Where-Object AccessControlType -eq 'Deny')
                    if ($allow.Count -ne 1 -or [int]$allow[0].FileSystemRights -ne 1179817) { throw 'target RX differs' }
                    if ($deny.Count -ne 1 -or [int]$deny[0].FileSystemRights -ne 852310) { throw 'target write denial differs' }
                }
                if (($script:writes -join ',') -ne 'applypatch-msg.sample,hooks,root') { throw 'children must be protected before parents' }
                """
                script = f"$scenario = '{scenario}'\n" + harness
                script += "\ntry {\n" + gate + assertions + "\n'ACCEPT'\n} catch { 'REJECT' }"
                expected = "ACCEPT" if scenario in ("inherited", "empty") else "REJECT"
                self.assertEqual(self.run_gate(script), expected)

    def test_credential_removal_precedes_target_launch(self):
        block = extract_run_blocks(WORKFLOW.read_text(encoding="utf-8"))[2]
        removal = 'Remove-Item -LiteralPath $credentialFile'
        self.assertIn(removal, block)
        self.assertNotIn(f"{removal} -Force", block)
        self.assertLess(block.index(removal), block.index('Start-Process'))
        self.assertLess(block.index('if (Test-Path -LiteralPath $credentialFile)'), block.index('Start-Process'))

    def test_credential_removal_survives_force_only_failure_model(self):
        block = extract_run_blocks(WORKFLOW.read_text(encoding="utf-8"))[2]
        removal = 'Remove-Item -LiteralPath $credentialFile'
        start = block.index(removal)
        end_marker = '$password = $null'
        end = block.index(end_marker, start) + len(end_marker)
        gate = block[start:end]
        script = r"""
        $ErrorActionPreference = 'Stop'
        $credentialFile = 'credential'
        $password = 'secret'
        $script:exists = $true
        function Remove-Item {
            param([string]$LiteralPath, [switch]$Force)
            if ($Force) { throw [UnauthorizedAccessException]::new('force-only regression') }
            $script:exists = $false
        }
        function Test-Path {
            param([string]$LiteralPath)
            return $script:exists
        }
        """
        script += "\ntry {\n" + gate + "\nif ($script:exists) { throw 'credential remains' }\n'ACCEPT'\n} catch { 'REJECT' }"
        self.assertEqual(self.run_gate(script), "ACCEPT")

    def test_native_nested_checkout_dacls_survive_parent_changes(self):
        block = extract_run_blocks(WORKFLOW.read_text(encoding="utf-8"))[1]
        gate = block[block.index("$systemSid ="):]
        # Exercise actual DACL persistence/Get-Acl on this disposable tree.
        with tempfile.TemporaryDirectory(prefix="issue197-acl-") as temporary:
            root = Path(temporary)
            hooks = root / ".git" / "hooks"
            hooks.mkdir(parents=True)
            (hooks / "applypatch-msg.sample").write_text("fixture", encoding="utf-8")
            (hooks / "literal[1].sample").write_text("fixture", encoding="utf-8")
            quoted = str(root).replace("'", "''")
            script = f"$env:GITHUB_WORKSPACE = '{quoted}'\n" + r"""
            $ErrorActionPreference = 'Stop'
            $controlSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $targetSid = 'S-1-5-21-100-200-300-1002'
            """ + gate + r"""
            $all = @((Get-Item -LiteralPath $env:GITHUB_WORKSPACE -Force)) +
                @(Get-ChildItem -LiteralPath $env:GITHUB_WORKSPACE -Force -Recurse)
            if ($all.Count -ne 5) { throw 'fixture traversal missed children' }
            foreach ($item in $all) {
                $acl = Get-Acl -LiteralPath $item.FullName
                if (-not $acl.AreAccessRulesProtected -or $acl.Access.Count -ne 5) { throw 'native child DACL lost ACEs' }
                $trusted = @($acl.Access | Where-Object {
                    $_.AccessControlType -eq 'Allow' -and [int]$_.FileSystemRights -eq 2032127
                })
                if ($trusted.Count -ne 3) { throw 'native cleanup authority lost' }
                if (-not $item.PSIsContainer -and (Get-Content -LiteralPath $item.FullName -Raw) -ne 'fixture') {
                    throw 'control cannot read child'
                }
            }
            'ACCEPT'
            """
            self.assertEqual(self.run_gate(script), "ACCEPT")
