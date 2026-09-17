import os
import re
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 consumption helper regression")
class PrivateCiConsumptionHelperWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.helper = cls.repo_root / "scripts" / "Consume-PrivateCiLiveRegistrationApproval.ps1"

    def test_consumption_helper_parses_under_windows_powershell_51_without_execution(self):
        escaped = str(self.helper).replace("'", "''")
        parser_script = (
            "$Tokens = $null; $Errors = $null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile('{escaped}', [ref]$Tokens, [ref]$Errors) | Out-Null; "
            "if ($Errors.Count -ne 0) { $Errors | ForEach-Object { Write-Error $_.Message }; exit 1 }; "
            "Write-Output 'CONSUMPTION_HELPER_PARSE_PASS'"
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
        self.assertIn("CONSUMPTION_HELPER_PARSE_PASS", completed.stdout)

    def test_consumption_helper_never_assigns_powershell_args_automatic_variable(self):
        source = self.helper.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?im)^\s*\$(?:global:)?args\s*=", source))
        self.assertIsNone(re.search(r"(?im)^\s*\$\{args\}\s*=", source))
        self.assertIn("CreateNew", source)
        self.assertIn("SetAccessRuleProtection($true, $false)", source)
        self.assertIn("DeleteSubdirectoriesAndFiles", source)
        self.assertIn("private-ci-authority", source)

    def test_consumption_helper_rejects_reparse_paths_before_protected_writes(self):
        source = self.helper.read_text(encoding="utf-8")
        self.assertIn("function Assert-NotReparsePoint", source)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", source)
        self.assertIn("Assert-NotReparsePoint -LiteralPath $RequiredPath", source)
        self.assertIn("Assert-NotReparsePoint -LiteralPath $Parent", source)
        self.assertIn("Assert-NotReparsePoint -LiteralPath $MarkerPath", source)

        authority_function = source.split("function New-ProtectedAuthorityDirectory", 1)[1].split(
            "$Principal =", 1
        )[0]
        self.assertLess(
            authority_function.index("Assert-NotReparsePoint -LiteralPath $LiteralPath"),
            authority_function.index("Test-ProtectedAcl -LiteralPath $LiteralPath"),
        )


if __name__ == "__main__":
    unittest.main()
