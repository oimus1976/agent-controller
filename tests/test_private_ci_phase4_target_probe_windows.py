import os
import re
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 Phase 4 probe regression")
class PrivateCiPhase4TargetProbeWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.probe = cls.repo_root / "scripts" / "Invoke-PrivateCiPhase4TargetProbe.ps1"

    def test_probe_parses_under_windows_powershell_51(self):
        script = r"""
$Tokens = $null
$Errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $env:PHASE4_PROBE_PATH,
    [ref]$Tokens,
    [ref]$Errors
) | Out-Null
if ($Errors.Count -ne 0) {
    $Errors | ForEach-Object { Write-Error $_.Message }
    exit 1
}
exit 0
""".strip()
        environment = os.environ.copy()
        environment["PHASE4_PROBE_PATH"] = str(self.probe)
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            check=False,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_probe_checks_runtime_identity_and_authority_isolation(self):
        source = self.probe.read_text(encoding="utf-8")
        required_fragments = (
            "whoami.exe",
            "S-1-5-32-544",
            "S-1-16-12288",
            "ACTIONS_RUNNER_INPUT_TOKEN",
            "GH_TOKEN",
            "OPENAI_API_KEY",
            "auth status --hostname github.com",
            "[System.IO.File]::Open",
            "[System.IO.FileAccess]::Write",
            "authority_marker_write_denied",
            "TARGET_PROBE_PASS",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)

    def test_probe_does_not_expand_into_runner_or_dispatch_mutation(self):
        source = self.probe.read_text(encoding="utf-8")
        forbidden = (
            "-UseNewEnvironment",
            "workflow run",
            "/dispatches",
            "config.cmd",
            "run.cmd",
            "Remove-Item",
            "New-LocalUser",
            "Remove-LocalUser",
            "Register-ScheduledTask",
            "New-Service",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, source)
        self.assertIsNone(
            re.search(r"(?im)^\s*Set-Acl\b|^\s*icacls(?:\.exe)?\b", source)
        )


if __name__ == "__main__":
    unittest.main()
