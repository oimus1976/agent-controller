"""Real Windows PowerShell 5.1 AST gate regressions for #270.

A non-elevated broker cannot wait on, read the exit code of, or stop a child
started with ``Start-Process -Credential``: PowerShell 5.1 returns a Process
rebuilt from the PID, and every later ``OpenProcess`` on the target-owned child
fails with ERROR_ACCESS_DENIED. The Phase 4/5 candidates therefore launch
target children through ``ProcessStartInfo`` + ``[System.Diagnostics.Process]::Start``
and keep the creation handle.

The operator-step AST gate treats every method invocation and member
assignment as ``DYNAMIC_OR_UNKNOWN_COMMAND``. These tests pin the exact shapes
the owner approved as exceptions (#270 comment 5852616248) and prove that any
variation stays unknown, and that ``Start-Process -Credential`` is rejected.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


def _annotate(title: str, message: str) -> None:
    # CI job logs cannot be downloaded from every review surface; surface the
    # failure as a GitHub check-run annotation instead.
    flat = " ".join(str(message).split())[:1500]
    print(f"::error title=issue270-{title}::{flat}", flush=True)


class _AnnotatedTestCase(unittest.TestCase):
    def run(self, result=None):
        failures_before = len(result.failures) + len(result.errors) if result is not None else 0
        outcome = super().run(result)
        if result is not None and len(result.failures) + len(result.errors) > failures_before:
            _test, trace = (result.failures + result.errors)[-1]
            _annotate(self._testMethodName, trace.strip().splitlines()[-1] + " || " + trace[-1200:])
        return outcome


DYNAMIC = "DYNAMIC_OR_UNKNOWN_COMMAND"
REJECTED = "START_PROCESS_CREDENTIAL_REJECTED"

START_INFO = (
    "$BridgeChildStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo -Property @{\n"
    "    FileName = 'powershell.exe'; Arguments = '-NoProfile -Command exit'; UserName = 'ac-runner'; Domain = 'WOBBUFFET'\n"
    "    Password = $BridgeTargetCredential.Password; LoadUserProfile = $true\n"
    "    UseShellExecute = $false; CreateNoWindow = $true; WorkingDirectory = $BridgeRunnerRoot\n"
    "    RedirectStandardOutput = $true; RedirectStandardError = $true\n"
    "}\n"
)
START = "$BridgeChild = [System.Diagnostics.Process]::Start($BridgeChildStartInfo)\n"


@unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 AST gate regression")
class PrivateCiProcessStartShapeWindowsTests(_AnnotatedTestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.producer = cls.repo_root / "scripts" / "Invoke-PrivateCiAstAttestation.ps1"

    def run_producer(self, extra: str) -> dict:
        candidate = (
            "$BridgeRepository = 'owner/private-repo'\n"
            "$BridgePullRequestNumber = 42\n"
            f"$BridgeTargetSha = '{'a' * 40}'\n"
            "$BridgeTargetHostRole = 'private-ci-owner-machine'\n"
            "$BridgeRequiredIdentity = 'c-admin'\n"
            "$BridgeEvidenceRoot = 'C:\\Users\\Public\\Documents\\agent-controller-handoff'\n"
            "$BridgeTranscriptFilename = 'issue270.log'\n"
            "$BridgeExpectedSuccessMarker = 'ISSUE270_PASS'\n"
            f"{extra}\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate_path = Path(temporary_directory) / "candidate.ps1"
            candidate_path.write_bytes(candidate.encode("utf-8"))
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
                    "b" * 64,
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout.strip())
        self.assertTrue(report["parsed"], report)
        return report

    def effects(self, extra: str) -> set[str]:
        return set(self.run_producer(extra)["observed_effect_families"])

    # --- allowed shapes -------------------------------------------------

    def test_start_info_alone_has_no_effect(self):
        self.assertEqual(self.effects(START_INFO), set())

    def test_root_level_process_start_is_a_process_launch(self):
        self.assertEqual(self.effects(START_INFO + START), {"PROCESS_LAUNCH"})

    def test_kill_through_the_held_handle_is_process_control(self):
        self.assertEqual(
            self.effects(START_INFO + START + "$BridgeChild.Kill()\n"),
            {"PROCESS_LAUNCH", "PROCESS_CONTROL"},
        )

    def test_pipe_reads_and_wait_are_read_only(self):
        extra = (
            START_INFO
            + START
            + "$BridgeChildStdoutTask = $BridgeChild.StandardOutput.ReadToEndAsync()\n"
            + "$BridgeChildStderrTask = $BridgeChild.StandardError.ReadToEndAsync()\n"
            + "$BridgeChild.WaitForExit()\n"
            + "$BridgeChildStdoutText = $BridgeChildStdoutTask.Result\n"
        )
        self.assertEqual(self.effects(extra), {"PROCESS_LAUNCH"})

    def test_exact_set_content_shape_is_a_filesystem_write(self):
        self.assertEqual(
            self.effects("Set-Content -LiteralPath $BridgeOutPath -Value $BridgeOutText -Encoding UTF8\n"),
            {"FILESYSTEM_WRITE_MUTATION"},
        )

    def test_all_three_launch_names_are_accepted(self):
        for name in ("BridgeChild", "BridgeSecurityProbeChild", "BridgeCredentialCheck"):
            with self.subTest(name=name):
                extra = (
                    START_INFO.replace("$BridgeChildStartInfo", f"${name}StartInfo")
                    + f"${name} = [System.Diagnostics.Process]::Start(${name}StartInfo)\n"
                    + f"${name}.WaitForExit()\n"
                    + f"${name}.Kill()\n"
                )
                self.assertEqual(self.effects(extra), {"PROCESS_LAUNCH", "PROCESS_CONTROL"})

    def test_process_start_child_proves_exit_code_heartbeat_and_fail_fast(self):
        report = self.run_producer(
            START_INFO
            + "$BridgeStartedAt = Get-Date\n"
            + START
            + "while (-not $BridgeChild.HasExited) {\n"
            + "  $BridgeElapsedSeconds = [int]((Get-Date) - $BridgeStartedAt).TotalSeconds\n"
            + "  Write-Host (\"heartbeat phase=phase4 elapsed_seconds={0}\" -f $BridgeElapsedSeconds)\n"
            + "  Start-Sleep -Seconds 5\n"
            + "}\n"
            + "$BridgeChildExitCode = $BridgeChild.ExitCode\n"
            + "if ($BridgeChildExitCode -ne 0) { throw 'child failed' }\n"
        )
        self.assertTrue(report["heartbeat_or_progress_proven"])
        self.assertTrue(report["child_exit_code_proven"])
        self.assertTrue(report["fail_fast_proven"])

    # --- variations stay unknown ---------------------------------------

    def test_variations_of_the_allowed_shapes_stay_dynamic(self):
        cases = {
            "other method": START_INFO + START + "$BridgeChild.Refresh()",
            "kill with argument": START_INFO + START + "$BridgeChild.Kill($true)",
            "wait with timeout": START_INFO + START + "$BridgeChild.WaitForExit(1000)",
            "other variable kill": START_INFO + START + "$BridgeOther.Kill()",
            "other stream method": START_INFO + START + "$BridgeChild.StandardInput.WriteLine('x')",
            "other static method": "[System.Diagnostics.Process]::GetProcessById(4)",
            "short type name": START_INFO + "$BridgeChild = [Diagnostics.Process]::Start($BridgeChildStartInfo)",
            "other type": START_INFO + "$BridgeChild = [System.IO.File]::Start($BridgeChildStartInfo)",
            "string start": "$BridgeChild = [System.Diagnostics.Process]::Start('cmd.exe')",
            "mismatched start info": START_INFO + "$BridgeSecurityProbeChild = [System.Diagnostics.Process]::Start($BridgeChildStartInfo)",
            "other launch name": (
                START_INFO.replace("$BridgeChildStartInfo", "$EvilStartInfo")
                + "$Evil = [System.Diagnostics.Process]::Start($EvilStartInfo)"
            ),
            "non-root start": START_INFO + "if ($true) { $BridgeChild = [System.Diagnostics.Process]::Start($BridgeChildStartInfo) }",
            "piped start": START_INFO + "$BridgeChild = [System.Diagnostics.Process]::Start($BridgeChildStartInfo) | Select-Object -First 1",
            "start not assigned": START_INFO + "[System.Diagnostics.Process]::Start($BridgeChildStartInfo)",
            "scoped start target": START_INFO + "$script:BridgeChild = [System.Diagnostics.Process]::Start($BridgeChildStartInfo)",
            "child rebound": START_INFO + START + "$BridgeChild = Get-Item -LiteralPath C:\\x\n$BridgeChild.Kill()",
            "start info rebound": START_INFO + "$BridgeChildStartInfo = Get-Item -LiteralPath C:\\x\n" + START,
            "extra key": START_INFO.replace("CreateNoWindow = $true", "CreateNoWindow = $true; Verb = 'runas'"),
            "expression key": START_INFO.replace("CreateNoWindow = $true", "('Create' + 'NoWindow') = $true"),
            "invocation value": START_INFO.replace("FileName = 'powershell.exe'", "FileName = (Get-Command powershell.exe)"),
            "subexpression value": START_INFO.replace("Arguments = '-NoProfile -Command exit'", 'Arguments = "$(Get-Date)"'),
            "expandable value": START_INFO.replace("Arguments = '-NoProfile -Command exit'", 'Arguments = "-x $BridgeRunnerRoot"'),
            "environment value": START_INFO.replace("FileName = 'powershell.exe'", "FileName = $env:ComSpec"),
            "method value": START_INFO.replace("Password = $BridgeTargetCredential.Password", "Password = $BridgeTargetCredential.GetNetworkCredential()"),
            "static member value": START_INFO.replace("FileName = 'powershell.exe'", "FileName = [Environment]::SystemDirectory"),
            "other new-object type": "$BridgeChildStartInfo = New-Object -TypeName System.Net.WebClient",
            "new-object positional": "$BridgeChildStartInfo = New-Object System.Diagnostics.ProcessStartInfo -Property @{ FileName = 'x' }",
            "new-object argument list": "$BridgeChildStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo -ArgumentList 'x'",
            "new-object not assigned": "New-Object -TypeName System.Diagnostics.ProcessStartInfo -Property @{ FileName = 'x' }",
            "member assignment": START_INFO + "$BridgeChildStartInfo.FileName = 'cmd.exe'",
            "set-content path": "Set-Content -Path $BridgeOutPath -Value $BridgeOutText -Encoding UTF8",
            "set-content expression value": "Set-Content -LiteralPath $BridgeOutPath -Value (Get-Date) -Encoding UTF8",
            "set-content literal path": "Set-Content -LiteralPath C:\\x -Value $BridgeOutText -Encoding UTF8",
            "set-content other encoding": "Set-Content -LiteralPath $BridgeOutPath -Value $BridgeOutText -Encoding ASCII",
            "set-content extra parameter": "Set-Content -LiteralPath $BridgeOutPath -Value $BridgeOutText -Encoding UTF8 -Force",
            "set-content pipeline": "$BridgeOutText | Set-Content -LiteralPath $BridgeOutPath -Value $BridgeOutText -Encoding UTF8",
        }
        for label, extra in cases.items():
            with self.subTest(case=label):
                self.assertIn(DYNAMIC, self.effects(extra + "\n"))

    def test_start_process_with_credential_is_rejected(self):
        cases = (
            "Start-Process -FilePath 'whoami.exe' -Credential $BridgeTargetCredential -Wait -PassThru",
            "$BridgeChild = Start-Process -FilePath 'cmd.exe' -Credential $BridgeTargetCredential -PassThru",
            "Start-Process -FilePath 'whoami.exe' -RunAs $BridgeTargetCredential",
            "Start-Process -FilePath 'whoami.exe' -Cred $BridgeTargetCredential",
            "Start-Process -FilePath 'whoami.exe' -Credential:$BridgeTargetCredential",
            "Start-Process @BridgeLaunchArguments",
        )
        for command in cases:
            with self.subTest(command=command):
                self.assertIn(REJECTED, self.effects(command))

    def test_start_process_without_credential_is_not_rejected(self):
        effects = self.effects("Start-Process -FilePath 'x.exe' -Verb RunAs -PassThru")
        self.assertIn("PROCESS_LAUNCH", effects)
        self.assertNotIn(REJECTED, effects)


if __name__ == "__main__":
    unittest.main()
