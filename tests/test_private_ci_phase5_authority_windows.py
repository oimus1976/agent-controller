import os
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(
    os.name == "nt",
    "Windows PowerShell 5.1 Phase 5 authority regression",
)
class PrivateCiPhase5AuthorityWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.approval = cls.repo_root / "scripts" / "Approve-PrivateCiPhase5.ps1"
        cls.consume = (
            cls.repo_root
            / "scripts"
            / "Consume-PrivateCiPhase5Approval.ps1"
        )

    def assert_parses(self, path):
        environment = os.environ.copy()
        environment["SCRIPT_TO_PARSE"] = str(path)
        script = r"""
$Tokens = $null
$Errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $env:SCRIPT_TO_PARSE,
    [ref]$Tokens,
    [ref]$Errors
) | Out-Null
if ($Errors.Count -ne 0) {
    $Errors | ForEach-Object { Write-Error $_.Message }
    exit 1
}
exit 0
""".strip()
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

    def test_phase5_authority_scripts_parse(self):
        self.assert_parses(self.approval)
        self.assert_parses(self.consume)

    def test_approval_scope_is_exactly_one_phase5_attempt(self):
        source = self.approval.read_text(encoding="utf-8")
        required = (
            "issue225-phase5-plan.json",
            "issue225-phase5-approval-",
            "exactly one #225 Phase 5 private-CI job attempt",
            "exactly one workflow_dispatch request",
            "retrying or sending a second workflow dispatch",
            "executing target repository scripts, builds, tests, hooks, or executables",
            "Ready for review, merge",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotIn("gh.exe api --method POST", source)
        self.assertNotIn("run.cmd", source)

    def test_consumption_is_phase4_result_keyed_and_create_new(self):
        source = self.consume.read_text(encoding="utf-8")
        required = (
            "issue225-phase5-result-{0}.consumed.json",
            "Phase4ResultSha256",
            "[System.IO.FileMode]::CreateNew",
            "agent-controller.private-ci-phase5-consumed.v1",
            "dispatch must not be retried",
            "issue225-phase4-result.json",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotIn("gh.exe api --method POST", source)
        self.assertNotIn("run.cmd", source)


if __name__ == "__main__":
    unittest.main()
