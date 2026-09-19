import os
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 Phase 4 authority regression")
class PrivateCiPhase4AuthorityWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.approval = cls.repo_root / "scripts" / "Approve-PrivateCiPhase4.ps1"
        cls.consume = cls.repo_root / "scripts" / "Consume-PrivateCiPhase4Approval.ps1"

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

    def test_phase4_authority_scripts_parse(self):
        self.assert_parses(self.approval)
        self.assert_parses(self.consume)

    def test_approval_is_phase4_specific_and_does_not_authorize_phase5(self):
        source = self.approval.read_text(encoding="utf-8")
        self.assertIn("issue225-phase4-plan.json", source)
        self.assertIn("issue225-phase4-approval-", source)
        self.assertIn("generation-scoped ACL preparation", source)
        self.assertIn("does NOT start the Actions runner listener", source)
        self.assertIn("dispatch a workflow", source)
        self.assertNotIn("run.cmd", source)
        self.assertNotIn("/dispatches", source)

    def test_consumption_is_handoff_keyed_and_create_new(self):
        source = self.consume.read_text(encoding="utf-8")
        self.assertIn(
            "issue225-phase4-handoff-{0}.consumed.json",
            source,
        )
        self.assertIn("RegistrationHandoffSha256", source)
        self.assertIn("[System.IO.FileMode]::CreateNew", source)
        self.assertIn(
            "agent-controller.private-ci-phase4-consumed.v1",
            source,
        )
        self.assertIn(
            "C:\\ProgramData\\agent-controller-private-ci-authority",
            source,
        )
        self.assertNotIn("workflow run", source)
        self.assertNotIn("run.cmd", source)


if __name__ == "__main__":
    unittest.main()
