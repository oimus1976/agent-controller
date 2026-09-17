import os
import re
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 approval issuer regression")
class PrivateCiApprovalIssuerWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.issuer = cls.repo_root / "scripts" / "Approve-PrivateCiLiveRegistration.ps1"

    def test_approval_issuer_parses_under_windows_powershell_51_without_execution(self):
        escaped = str(self.issuer).replace("'", "''")
        parser_script = (
            "$Tokens = $null; $Errors = $null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile('{escaped}', [ref]$Tokens, [ref]$Errors) | Out-Null; "
            "if ($Errors.Count -ne 0) { $Errors | ForEach-Object { Write-Error $_.Message }; exit 1 }; "
            "Write-Output 'APPROVAL_ISSUER_PARSE_PASS'"
        )
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                parser_script,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("APPROVAL_ISSUER_PARSE_PASS", completed.stdout)

    def test_approval_issuer_never_assigns_powershell_args_automatic_variable(self):
        source = self.issuer.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?im)^\s*\$(?:global:)?args\s*=", source))
        self.assertIsNone(re.search(r"(?im)^\s*\$\{args\}\s*=", source))
        self.assertIn("WindowsPrincipal", source)
        self.assertIn("MessageBox", source)
        self.assertIn("SetAccessRuleProtection($true, $false)", source)


if __name__ == "__main__":
    unittest.main()
