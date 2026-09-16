import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 producer regression")
class PrivateCiAstProducerWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.producer = cls.repo_root / "scripts" / "Invoke-PrivateCiAstAttestation.ps1"
        cls.spec_sha = "b" * 64

    def run_producer(self, candidate_text):
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate_path = Path(temporary_directory) / "candidate.ps1"
            candidate_bytes = candidate_text.encode("utf-8")
            candidate_path.write_bytes(candidate_bytes)
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(self.producer),
                    "-CandidatePath",
                    str(candidate_path),
                    "-SpecSha256",
                    self.spec_sha,
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return json.loads(completed.stdout.strip()), candidate_bytes

    @staticmethod
    def bound_candidate(extra=""):
        return (
            "$BridgeRepository = 'owner/private-repo'\n"
            "$BridgePullRequestNumber = 42\n"
            f"$BridgeTargetSha = '{'a' * 40}'\n"
            "$BridgeTargetHostRole = 'private-ci-owner-machine'\n"
            "$BridgeRequiredIdentity = 'c-admin'\n"
            "$BridgeEvidenceRoot = 'C:\\Users\\Public\\Documents\\agent-controller-handoff'\n"
            "$BridgeTranscriptFilename = 'issue213-register.log'\n"
            "$BridgeExpectedSuccessMarker = 'ISSUE213_REGISTER_PASS'\n"
            f"{extra}\n"
        )

    def test_real_powershell_parser_extracts_structured_bindings_without_execution(self):
        candidate = self.bound_candidate("throw 'must not execute'")
        report, candidate_bytes = self.run_producer(candidate)
        self.assertTrue(report["parsed"])
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(report["runtime"], "Windows PowerShell 5.1")
        self.assertEqual(report["parser"], "System.Management.Automation.Language.Parser")
        self.assertEqual(report["repository"], "owner/private-repo")
        self.assertEqual(report["pull_request_number"], 42)
        self.assertEqual(report["target_sha"], "a" * 40)
        self.assertEqual(report["required_identity"], "c-admin")
        self.assertEqual(report["spec_sha256"], self.spec_sha)
        self.assertEqual(
            report["candidate_sha256"],
            hashlib.sha256(candidate_bytes).hexdigest(),
        )

    def test_parser_error_is_reported_fail_closed(self):
        candidate = self.bound_candidate("if (")
        report, _ = self.run_producer(candidate)
        self.assertFalse(report["parsed"])
        self.assertGreater(report["error_count"], 0)

    def test_scoped_and_braced_args_collisions_are_reported(self):
        for spelling in ("$global:args = 1", "${args} = 1", "Write-Output x; $Args = 1"):
            with self.subTest(spelling=spelling):
                report, _ = self.run_producer(self.bound_candidate(spelling))
                self.assertIn("args", report["automatic_variable_collisions"])

    def test_dynamic_command_is_never_silently_read_only(self):
        report, _ = self.run_producer(
            self.bound_candidate("& ('Remove' + '-Item') -LiteralPath C:\\target")
        )
        self.assertIn("DYNAMIC_OR_UNKNOWN_COMMAND", report["observed_effect_families"])

    def test_direct_destructive_command_is_classified(self):
        report, _ = self.run_producer(
            self.bound_candidate("Remove-Item -LiteralPath C:\\target")
        )
        self.assertIn("FILESYSTEM_DESTRUCTIVE_MUTATION", report["observed_effect_families"])


if __name__ == "__main__":
    unittest.main()
