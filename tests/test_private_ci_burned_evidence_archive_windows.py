import os
import shutil
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows-only PowerShell 5.1 regression")
class PrivateCiBurnedEvidenceArchiveWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.script = (
            cls.repo_root / "scripts" / "Archive-PrivateCiBurnedEvidence.ps1"
        )
        cls.powershell = shutil.which("powershell.exe")
        if cls.powershell is None:
            raise unittest.SkipTest("Windows PowerShell 5.1 unavailable")

    def test_apply_bridge_parses_under_windows_powershell_51(self):
        quoted = str(self.script).replace("'", "''")
        command = (
            "$ErrorActionPreference='Stop';"
            "$Errors=$null;"
            "$Tokens=$null;"
            "[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{quoted}',[ref]$Tokens,[ref]$Errors) | Out-Null;"
            "if (@($Errors).Count -ne 0) {"
            "  @($Errors) | ForEach-Object { Write-Error $_.Message };"
            "  exit 2"
            "}"
        )
        completed = subprocess.run(
            [
                self.powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            cwd=self.repo_root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + "\n" + completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
