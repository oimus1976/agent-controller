import json
from pathlib import Path
import tempfile
import unittest

from scripts import issue305_target_context_probe as probe


class Issue305DesignTests(unittest.TestCase):
    def test_fixed_bytes_and_line_endings_are_distinct(self):
        artifact = probe.ROOT / "docs/operations/issue-305-target-context/Issue305-TargetContextProbe.ps1"
        raw = artifact.read_bytes()
        plan = json.loads((artifact.parent / "design-plan.json").read_text())
        self.assertEqual(raw.replace(b"\r\n", b"\n"), probe.render())
        self.assertEqual(plan, probe.design_plan())
        self.assertIn(probe.digest(raw), {plan["candidate_lf"]["sha256"], plan["candidate_crlf"]["sha256"]})
        self.assertNotEqual(plan["candidate_lf"], plan["candidate_crlf"])
        self.assertIsNone(plan["live_binding"])
        self.assertFalse(plan["decision_a"])
        self.assertFalse(plan["decision_b"])

    def test_collector_script_is_reused_without_semantic_change(self):
        import base64
        source = probe.render().decode()
        encoded = base64.b64encode(probe.broker_command().encode("utf-16-le")).decode()
        self.assertIn(encoded, source)
        self.assertIn("[Microsoft.Win32.Registry]::Users", probe.broker_command())
        self.assertIn("target SID hive is not loaded", probe.broker_command())
        self.assertNotIn("CurrentUser", probe.broker_command())

    def test_launch_payload_fits_documented_logon_command_limit(self):
        command = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + probe.CHILD + '"'
        self.assertLess(len(command) + len(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") + 3, 1024)
        self.assertIn("ReadLineAsync", probe.CHILD)
        self.assertIn("Wait(60000)", probe.CHILD)
        self.assertIn("exit 5", probe.CHILD)  # EOF or wrong release is failure.
        self.assertNotIn('"', probe.CHILD)
        for forbidden in ("Start-Process", "Invoke-Expression", "Download", "Get-Content", "New-LocalUser"):
            self.assertNotIn(forbidden, probe.CHILD)

    def test_launch_retains_supported_creation_handle_and_profile_shape(self):
        source = probe.render().decode()
        self.assertIn("$Target = [System.Diagnostics.Process]::Start((New-Object", source)
        for field in ("UserName = 'ac-runner'", "Domain = $Plan.host", "Password = $Password; LoadUserProfile = $true", "RedirectStandardInput = $true", "UseShellExecute = $false", "WorkingDirectory = $Plan.working_directory"):
            self.assertIn(field, source)
        # A null environment is supplied through the existing supported shape;
        # never enumerate/copy broker auth environment into the target child.
        self.assertNotIn(".EnvironmentVariables", source)
        self.assertNotIn("Start-Process -Credential", source)
        self.assertNotIn("GetProcessById", source)

    def test_review_artifact_write_is_exclusive(self):
        with tempfile.TemporaryDirectory(dir=probe.ROOT) as temporary:
            path = Path(temporary) / "candidate"
            probe.write_exclusive(path, b"first")
            with self.assertRaises(FileExistsError):
                probe.write_exclusive(path, b"second")
            self.assertEqual(path.read_bytes(), b"first")

    def test_effects_do_not_expand_to_pilot_or_direct_hive_mutation(self):
        source = probe.render().decode()
        for forbidden in ("RegLoadKey", "RegUnLoadKey", "-Verb RunAs", "Get-Credential", "New-Service", "Register-ScheduledTask", "Set-Acl", "issue216-phase0-canonical", "create_private_ci_pilot_freeze", "/dispatches", "config.cmd", "run.cmd"):
            self.assertNotIn(forbidden, source)
        self.assertIn("STOP_PARTIAL_PROFILE_STATE", source)
        self.assertNotIn("PHASE0_PASS", source)


if __name__ == "__main__":
    unittest.main()
