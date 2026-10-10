"""Execute only the candidate's absence child with in-memory registry doubles.

No native fixture script execution, registry writes, account/profile access,
live operation, or output deletion is performed by these regressions.
"""
import os
from pathlib import Path
import re
import subprocess
import unittest


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 absence child")
class Issue305AbsenceReadbackTests(unittest.TestCase):
    def run_child(self, behavior):
        candidate = Path(__file__).resolve().parents[1] / "scripts/Test-Issue305HiveBoundary.ps1"
        source = candidate.read_text(encoding="utf-8")
        assignment = re.search(r'^\s*(\$Check = ".*")$', source, re.MULTILINE)
        self.assertIsNotNone(assignment)
        # Evaluate the exact double-quoted expression under PowerShell, then
        # substitute only its OS root. The return/exception flow stays exact.
        harness = r"""
class FixtureKey {
    [void] Dispose() {}
}
class FixtureUsers {
    [object] OpenSubKey([string]$Name, [bool]$Writable) {
        if ($Name -ne 'AC305_FIXTURE_TEST' -or $Writable) { throw 'bad fixture binding' }
        __BEHAVIOR__
    }
}
$Users = [FixtureUsers]::new()
""".replace("__BEHAVIOR__", behavior)
        script = (
            "$Mount = 'AC305_FIXTURE_TEST'\n"
            + assignment.group(1)
            + "\n$Check = $Check.Replace('[Microsoft.Win32.Registry]::Users', '$Users')\n"
            + "& ([ScriptBlock]::Create(@'\n"
            + harness
            + "\n'@ + $Check))\n"
        )
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
        )

    def test_denied_read_cannot_report_absence(self):
        result = self.run_child("throw [UnauthorizedAccessException]::new('fixture read denied')")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertNotIn("ABSENT", result.stdout)

    def test_other_read_error_cannot_report_absence(self):
        result = self.run_child("throw [IO.IOException]::new('fixture read failed')")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertNotIn("ABSENT", result.stdout)

    def test_present_mount_is_not_absent(self):
        result = self.run_child("return [FixtureKey]::new()")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertNotIn("ABSENT", result.stdout)

    def test_successful_null_read_reports_absence(self):
        result = self.run_child("return $null")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ABSENT")


if __name__ == "__main__":
    unittest.main()
