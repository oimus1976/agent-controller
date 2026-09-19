import hashlib
import json
import os
import re
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
        report, _ = self.run_producer(self.bound_candidate("if ("))
        self.assertFalse(report["parsed"])
        self.assertGreater(report["error_count"], 0)

    def test_duplicate_dead_branch_and_function_binding_assignments_fail_closed(self):
        cases = (
            "$BridgeRepository = 'attacker/repo'",
            "if ($false) { $BridgeRepository = 'owner/private-repo' }",
            "function Set-FakeBinding { $BridgeRepository = 'owner/private-repo' }",
        )
        for extra in cases:
            with self.subTest(extra=extra):
                report, _ = self.run_producer(self.bound_candidate(extra))
                self.assertFalse(report["parsed"])
                self.assertGreater(report["error_count"], 0)
                self.assertTrue(
                    any(
                        item.startswith("BINDING_COUNT_INVALID:BridgeRepository")
                        or item.startswith("NONCANONICAL_BINDING:BridgeRepository")
                        for item in report["unresolved_placeholders"]
                    )
                )

    def test_foreach_rebinding_of_canonical_field_fails_closed(self):
        cases = (
            "foreach ($BridgeRepository in 'attacker/repo') { config.cmd --version }",
            "foreach ($script:BridgeRepository in 'attacker/repo') { config.cmd --version }",
        )
        for expression in cases:
            with self.subTest(expression=expression):
                report, _ = self.run_producer(self.bound_candidate(expression))
                self.assertFalse(report["parsed"])
                self.assertIn(
                    "NONCANONICAL_BINDING:BridgeRepository",
                    report["unresolved_placeholders"],
                )
                self.assertIn(
                    "BINDING_COUNT_INVALID:BridgeRepository",
                    report["unresolved_placeholders"],
                )

    def test_automatic_variable_binding_forms_are_reported(self):
        cases = (
            ("$global:args = 1", "args"),
            ("${args} = 1", "args"),
            ("[int]$LASTEXITCODE = 0", "lastexitcode"),
            ("foreach ($LASTEXITCODE in 0) { Write-Output x }", "lastexitcode"),
        )
        for spelling, expected in cases:
            with self.subTest(spelling=spelling):
                report, _ = self.run_producer(self.bound_candidate(spelling))
                self.assertIn(expected, report["automatic_variable_collisions"])

    def test_producer_source_does_not_assign_to_powershell_args_automatic_variable(self):
        source = self.producer.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?im)^\s*\$(?:global:)?args\s*=", source))
        self.assertIsNone(re.search(r"(?im)^\s*\$\{args\}\s*=", source))

    def test_dynamic_and_indirect_execution_are_never_silently_read_only(self):
        cases = (
            "& ('Remove' + '-Item') -LiteralPath C:\\target",
            "$CommandName = 'Remove-Item'; & $CommandName -LiteralPath C:\\target",
            ". .\\helper.ps1",
        )
        for command in cases:
            with self.subTest(command=command):
                report, _ = self.run_producer(self.bound_candidate(command))
                self.assertIn("DYNAMIC_OR_UNKNOWN_COMMAND", report["observed_effect_families"])

    def test_every_unclassified_static_command_fails_closed_as_unknown(self):
        cases = (
            "Set-Content -LiteralPath C:\\target -Value x",
            "New-LocalUser -Name x -NoPassword",
            "cmd.exe /c echo x",
        )
        for command in cases:
            with self.subTest(command=command):
                report, _ = self.run_producer(self.bound_candidate(command))
                self.assertIn("DYNAMIC_OR_UNKNOWN_COMMAND", report["observed_effect_families"])

    def test_module_qualified_destructive_command_is_normalized_and_classified(self):
        report, _ = self.run_producer(
            self.bound_candidate(
                "Microsoft.PowerShell.Management\\Remove-Item -LiteralPath C:\\target"
            )
        )
        self.assertIn("FILESYSTEM_DESTRUCTIVE_MUTATION", report["observed_effect_families"])

    def test_direct_destructive_command_is_classified(self):
        report, _ = self.run_producer(
            self.bound_candidate("Remove-Item -LiteralPath C:\\target")
        )
        self.assertIn("FILESYSTEM_DESTRUCTIVE_MUTATION", report["observed_effect_families"])

    def test_redirection_and_member_invocation_fail_closed_as_unknown_effects(self):
        cases = (
            "Write-Output x > C:\\victim",
            "[System.IO.File]::Delete('C:\\victim')",
        )
        for expression in cases:
            with self.subTest(expression=expression):
                report, _ = self.run_producer(self.bound_candidate(expression))
                self.assertIn(
                    "DYNAMIC_OR_UNKNOWN_COMMAND",
                    report["observed_effect_families"],
                )

    def test_effectful_assignment_targets_fail_closed_as_unknown(self):
        cases = (
            "$env:PATH = 'C:\\attacker'",
            "$script:HelperPath = 'C:\\attacker'",
            "$Object = [pscustomobject]@{ Value = 0 }; $Object.Value = 1",
        )
        for expression in cases:
            with self.subTest(expression=expression):
                report, _ = self.run_producer(self.bound_candidate(expression))
                self.assertIn(
                    "DYNAMIC_OR_UNKNOWN_COMMAND",
                    report["observed_effect_families"],
                )

    def test_execution_control_proofs_remain_false_even_with_matching_comments_or_code(self):
        candidate = self.bound_candidate(
            "# $ChildExitCode = $LASTEXITCODE\n"
            "# $ErrorActionPreference = 'Stop'\n"
            "# if ($ChildExitCode -ne 0) { throw 'failed' }\n"
            "if ($false) { $ChildExitCode = $LASTEXITCODE }"
        )
        report, _ = self.run_producer(candidate)
        self.assertFalse(report["heartbeat_or_progress_proven"])
        self.assertFalse(report["child_exit_code_proven"])
        self.assertFalse(report["fail_fast_proven"])

    def test_automatic_variable_read_is_not_a_collision(self):
        report, _ = self.run_producer(
            self.bound_candidate("$BridgeNativeExit = $LASTEXITCODE")
        )
        self.assertNotIn(
            "lastexitcode",
            report["automatic_variable_collisions"],
        )

    def test_phase4_mutation_commands_have_explicit_effect_families(self):
        cases = (
            (
                "Copy-Item -LiteralPath C:\\source -Destination C:\\target",
                "FILESYSTEM_WRITE_MUTATION",
            ),
            (
                "Stop-Process -Id 123 -Force",
                "PROCESS_CONTROL",
            ),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                report, _ = self.run_producer(self.bound_candidate(command))
                self.assertIn(expected, report["observed_effect_families"])
                self.assertNotIn(
                    "DYNAMIC_OR_UNKNOWN_COMMAND",
                    report["observed_effect_families"],
                )

    def test_bounded_child_process_shape_proves_progress_exit_and_fail_fast(self):
        candidate = self.bound_candidate(
            "$BridgeStartedAt = Get-Date\n"
            "$BridgeChild = Start-Process -FilePath 'powershell.exe' "
            "-ArgumentList @('-NoProfile', '-Command', 'exit 0') -PassThru\n"
            "while (-not $BridgeChild.HasExited) {\n"
            "  $BridgeElapsedSeconds = [int]((Get-Date) - $BridgeStartedAt).TotalSeconds\n"
            "  Write-Host (\"heartbeat phase=phase4 elapsed_seconds={0}\" -f $BridgeElapsedSeconds)\n"
            "  Start-Sleep -Seconds 5\n"
            "}\n"
            "$BridgeChildExitCode = $BridgeChild.ExitCode\n"
            "if ($BridgeChildExitCode -ne 0) { throw 'child failed' }"
        )
        report, _ = self.run_producer(candidate)
        self.assertTrue(report["parsed"])
        self.assertIn("PROCESS_LAUNCH", report["observed_effect_families"])
        self.assertTrue(report["heartbeat_or_progress_proven"])
        self.assertTrue(report["child_exit_code_proven"])
        self.assertTrue(report["fail_fast_proven"])

    def test_child_exit_proof_requires_passthru_process_exitcode(self):
        cases = (
            "$BridgeChild = Start-Process powershell.exe\n"
            "$BridgeChildExitCode = 0\n"
            "if ($BridgeChildExitCode -ne 0) { throw 'failed' }",
            "$BridgeChild = Start-Process powershell.exe -PassThru\n"
            "$BridgeChildExitCode = 0\n"
            "if ($BridgeChildExitCode -ne 0) { throw 'failed' }",
        )
        for candidate_body in cases:
            with self.subTest(candidate_body=candidate_body):
                report, _ = self.run_producer(self.bound_candidate(candidate_body))
                self.assertFalse(report["child_exit_code_proven"])

    def test_fail_fast_proof_requires_nonzero_exit_guard_with_throw(self):
        cases = (
            "$BridgeChild = Start-Process powershell.exe -PassThru\n"
            "$BridgeChildExitCode = $BridgeChild.ExitCode",
            "$BridgeChild = Start-Process powershell.exe -PassThru\n"
            "$BridgeChildExitCode = $BridgeChild.ExitCode\n"
            "if ($BridgeChildExitCode -eq 0) { throw 'wrong guard' }",
            "$BridgeChild = Start-Process powershell.exe -PassThru\n"
            "$BridgeChildExitCode = $BridgeChild.ExitCode\n"
            "if ($BridgeChildExitCode -ne 0) { Write-Host 'failed' }",
        )
        for candidate_body in cases:
            with self.subTest(candidate_body=candidate_body):
                report, _ = self.run_producer(self.bound_candidate(candidate_body))
                self.assertFalse(report["fail_fast_proven"])

    def test_heartbeat_proof_requires_process_liveness_loop_and_bounded_sleep(self):
        cases = (
            "Write-Host 'heartbeat phase=phase4 elapsed_seconds=0'\nStart-Sleep -Seconds 5",
            "$BridgeChild = Start-Process powershell.exe -PassThru\n"
            "while (-not $BridgeChild.HasExited) { Write-Host 'working'; Start-Sleep -Seconds 5 }",
            "$BridgeChild = Start-Process powershell.exe -PassThru\n"
            "while (-not $BridgeChild.HasExited) { "
            "Write-Host 'heartbeat phase=phase4 elapsed_seconds=0'; Start-Sleep -Seconds 120 }",
        )
        for candidate_body in cases:
            with self.subTest(candidate_body=candidate_body):
                report, _ = self.run_producer(self.bound_candidate(candidate_body))
                self.assertFalse(report["heartbeat_or_progress_proven"])


if __name__ == "__main__":
    unittest.main()
