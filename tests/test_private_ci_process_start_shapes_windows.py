"""Real Windows PowerShell 5.1 AST gate regressions for #270.

A non-elevated broker cannot wait on, read the exit code of, or stop a child
started with ``Start-Process -Credential``: PowerShell 5.1 returns a Process
rebuilt from the PID, and every later ``OpenProcess`` on the target-owned child
fails with ERROR_ACCESS_DENIED. The Phase 4/5 candidates therefore launch
target children through ``[System.Diagnostics.Process]::Start`` with an inline
``ProcessStartInfo`` and keep the creation handle.

The operator-step AST gate treats every method invocation and member
assignment as ``DYNAMIC_OR_UNKNOWN_COMMAND``. These tests pin the exact shapes
allowed as exceptions (#270 comment 5852616248, revised by owner-approved
option A after Codex review) and prove that every variation stays unknown.

The gate classifies effect families; it is defense in depth. Payload and
identity integrity are owned by the exact canonical candidate comparison in
the Python contracts/runtimes.
"""

from __future__ import annotations

import json
import os
import re
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
OUTPUT_WRITE = "EVIDENCE_OUTPUT_WRITE"

RUNNER_ARGUMENTS = "'/d /s /c \"run.cmd 1>\"C:\\x\\out.log\" 2>\"C:\\x\\err.log\"\"'"

SHAPES = {
    "credential": dict(
        file_name="$BridgeCredentialCheckPath",
        arguments=None,
        load_user_profile=False,
        working_directory="$BridgeCredentialCheckDirectory",
        redirect_output=False,
    ),
    "probe": dict(
        file_name="'powershell.exe'",
        arguments="$BridgeTargetProbeArguments",
        load_user_profile=True,
        working_directory="$BridgeRunnerRoot",
        redirect_output=True,
    ),
    "security": dict(
        file_name="'powershell.exe'",
        arguments="$BridgeSecurityProbeArguments",
        load_user_profile=True,
        working_directory="$BridgeRunnerRoot",
        redirect_output=True,
    ),
    "runner": dict(
        file_name="'cmd.exe'",
        arguments=RUNNER_ARGUMENTS,
        load_user_profile=True,
        working_directory="$BridgeRunnerRoot",
        redirect_output=False,
    ),
}
SHAPE_NAME = {
    "credential": "BridgeCredentialCheck",
    "probe": "BridgeChild",
    "security": "BridgeSecurityProbeChild",
    "runner": "BridgeChild",
}


def launch(shape: str, name: str | None = None) -> str:
    """Launch text exactly as the Phase 4/5 renderer emits it."""
    # Imported lazily so the Linux suite still loads this module.
    from agent_controller.private_ci_phase4_contract import target_launch_lines

    lines = target_launch_lines(
        name or SHAPE_NAME[shape],
        user_name="ac-runner",
        domain="WOBBUFFET",
        password="$BridgeTargetCredential.Password",
        **SHAPES[shape],
    )
    return "\n".join(lines) + "\n"


def drop(text: str, key: str) -> str:
    """Remove one ``Key = value`` pair from rendered launch text."""
    result, count = re.subn(r"(;\s*)?\b" + key + r" = [^;\n]+(;\s*)?", _drop_join, text)
    if count != 1:
        raise AssertionError(f"key {key!r} not found exactly once")
    return result


def _drop_join(match) -> str:
    # Keep a separator only when the key sat between two others on one line.
    return "; " if match.group(1) and match.group(2) else ""


def swap(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"{old!r} not found exactly once")
    return text.replace(old, new)


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

    def test_each_rendered_launch_shape_is_a_process_launch(self):
        for shape in SHAPES:
            with self.subTest(shape=shape):
                name = SHAPE_NAME[shape]
                extra = launch(shape) + f"${name}.WaitForExit()\n" + f"${name}.Kill()\n"
                self.assertEqual(self.effects(extra), {"PROCESS_LAUNCH", "PROCESS_CONTROL"})

    def test_pipe_reads_and_wait_are_read_only(self):
        extra = (
            launch("probe")
            + "$BridgeChildStdoutTask = $BridgeChild.StandardOutput.ReadToEndAsync()\n"
            + "$BridgeChildStderrTask = $BridgeChild.StandardError.ReadToEndAsync()\n"
            + "$BridgeChild.WaitForExit()\n"
            + "$BridgeChildStdoutText = $BridgeChildStdoutTask.Result\n"
        )
        self.assertEqual(self.effects(extra), {"PROCESS_LAUNCH"})

    def test_exact_output_capture_write_is_its_own_narrow_family(self):
        # Option A: the broker-written probe output is not a general
        # FILESYSTEM_WRITE_MUTATION, so Phase 5 does not have to allow Copy-Item.
        for path, value in (
            ("BridgeTargetProbeStdoutPath", "BridgeChildStdoutText"),
            ("BridgeTargetProbeStderrPath", "BridgeChildStderrText"),
            ("BridgeSecurityProbeStdoutPath", "BridgeSecurityProbeChildStdoutText"),
            ("BridgeSecurityProbeStderrPath", "BridgeSecurityProbeChildStderrText"),
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    self.effects(f"Set-Content -LiteralPath ${path} -Value ${value} -Encoding UTF8\n"),
                    {OUTPUT_WRITE},
                )

    def test_process_start_child_proves_exit_code_heartbeat_and_fail_fast(self):
        report = self.run_producer(
            "$BridgeStartedAt = Get-Date\n"
            + launch("probe")
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

    # --- the start info must be the exact inline shape ----------------

    def test_start_info_must_be_inline_and_match_the_shape_for_its_name(self):
        probe = launch("probe")
        runner = launch("runner")
        credential = launch("credential")
        security = launch("security")
        cases = {
            # Codex P1 on ea13afd: a key subset starts the child as the broker.
            "subset without identity": (
                "$BridgeChild = [System.Diagnostics.Process]::Start((New-Object -TypeName "
                "System.Diagnostics.ProcessStartInfo -Property @{ FileName = 'cmd.exe'; Arguments = '/c exit' }))"
            ),
            "missing UserName": drop(probe, "UserName"),
            "missing Domain": drop(probe, "Domain"),
            "missing Password": drop(probe, "Password"),
            "missing UseShellExecute": drop(probe, "UseShellExecute"),
            "missing CreateNoWindow": drop(probe, "CreateNoWindow"),
            "missing WorkingDirectory": drop(probe, "WorkingDirectory"),
            "probe with one redirect": drop(probe, "RedirectStandardError"),
            "runner without arguments": drop(runner, "Arguments"),
            "extra key": swap(probe, "CreateNoWindow = $true", "CreateNoWindow = $true; Verb = 'runas'"),
            "expression key": swap(probe, "CreateNoWindow = $true", "('Create' + 'NoWindow') = $true"),
            "shell execute": swap(probe, "UseShellExecute = $false", "UseShellExecute = $true"),
            "window": swap(probe, "CreateNoWindow = $true", "CreateNoWindow = $false"),
            "redirect false": swap(probe, "RedirectStandardOutput = $true", "RedirectStandardOutput = $false"),
            "probe without profile": swap(probe, "LoadUserProfile = $true", "LoadUserProfile = $false"),
            "credential with profile": swap(credential, "LoadUserProfile = $false", "LoadUserProfile = $true"),
            "empty user": swap(probe, "UserName = 'ac-runner'", "UserName = ''"),
            "variable user": swap(probe, "UserName = 'ac-runner'", "UserName = $BridgeTargetIdentity"),
            "empty domain": swap(probe, "Domain = 'WOBBUFFET'", "Domain = ''"),
            # Codex P1 on 53b4c5e: launch values must be the rendered ones.
            "password literal": swap(probe, "Password = $BridgeTargetCredential.Password", "Password = 'x'"),
            "password other variable": swap(probe, "Password = $BridgeTargetCredential.Password", "Password = $BridgeOtherCredential.Password"),
            "password other member": swap(probe, "Password = $BridgeTargetCredential.Password", "Password = $BridgeTargetCredential.UserName"),
            "probe other file": swap(probe, "FileName = 'powershell.exe'", "FileName = 'cmd.exe'"),
            "probe file variable": swap(probe, "FileName = 'powershell.exe'", "FileName = $BridgeProbeFile"),
            "probe other arguments": swap(probe, "Arguments = $BridgeTargetProbeArguments", "Arguments = $BridgeOtherArguments"),
            "probe literal arguments": swap(probe, "Arguments = $BridgeTargetProbeArguments", "Arguments = '-Command evil'"),
            "probe other directory": swap(probe, "WorkingDirectory = $BridgeRunnerRoot", "WorkingDirectory = $BridgeOtherRoot"),
            "security with probe arguments": swap(security, "Arguments = $BridgeSecurityProbeArguments", "Arguments = $BridgeTargetProbeArguments"),
            "runner as powershell": swap(runner, "FileName = 'cmd.exe'", "FileName = 'powershell.exe'"),
            "runner other command": swap(runner, "run.cmd 1>", "evil.cmd 1>"),
            "runner chained command": swap(runner, "run.cmd 1>", "run.cmd & calc 1>"),
            "runner variable arguments": swap(runner, "Arguments = " + RUNNER_ARGUMENTS, "Arguments = $BridgeRunnerArguments"),
            "runner metacharacter path": swap(runner, "C:\\x\\out.log", "C:\\x\\%TEMP_OUT%.log"),
            "credential other file": swap(credential, "FileName = $BridgeCredentialCheckPath", "FileName = 'cmd.exe'"),
            "credential other directory": swap(credential, "WorkingDirectory = $BridgeCredentialCheckDirectory", "WorkingDirectory = $BridgeRunnerRoot"),
            "credential with redirect": swap(
                credential, "\n}))", "\n    RedirectStandardOutput = $true; RedirectStandardError = $true\n}))"
            ),
            "security probe as runner": launch("runner", "BridgeSecurityProbeChild"),
            "credential name with probe shape": launch("probe", "BridgeCredentialCheck"),
            "child name with credential shape": launch("credential", "BridgeChild"),
            # A start-info variable is no longer accepted at all: a variable can
            # be rebound (param default, -OutVariable, the Variable provider).
            "start info variable": (
                "$BridgeChildStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo -Property @{ FileName = 'x' }\n"
                "$BridgeChild = [System.Diagnostics.Process]::Start($BridgeChildStartInfo)"
            ),
            "param start info": (
                "param($BridgeChildStartInfo = 'cmd.exe')\n"
                "$BridgeChild = [System.Diagnostics.Process]::Start($BridgeChildStartInfo)"
            ),
            "string start": "$BridgeChild = [System.Diagnostics.Process]::Start('cmd.exe')",
            "new-object alone": "New-Object -TypeName System.Diagnostics.ProcessStartInfo -Property @{ FileName = 'x' }",
            "new-object positional": swap(probe, "New-Object -TypeName System.Diagnostics.ProcessStartInfo", "New-Object System.Diagnostics.ProcessStartInfo"),
            "other new-object type": swap(probe, "System.Diagnostics.ProcessStartInfo", "System.Net.WebClient"),
        }
        for label, extra in cases.items():
            with self.subTest(case=label):
                self.assertIn(DYNAMIC, self.effects(extra + "\n"))

    # --- the launch name must be bound exactly once ---------------------

    def test_launch_name_must_be_bound_only_by_the_validated_start(self):
        probe = launch("probe")
        cases = {
            "rebound by assignment": probe + "$BridgeChild = [pscustomobject]@{ HasExited = $true; ExitCode = 0 }\n$BridgeChild.Kill()",
            "assigned twice": probe + probe,
            "scoped assignment": probe + "$script:BridgeChild = $null\n$BridgeChild.Kill()",
            "param binding": "param($BridgeChild)\n" + probe,
            "function param binding": probe + "function Get-Child { param($BridgeChild) }",
            "foreach binding": probe + "foreach ($BridgeChild in @(1)) { Write-Output x }",
            "out-variable": probe + "Write-Output 1 -OutVariable BridgeChild",
            "out-variable append": probe + "Write-Output 1 -OutVariable +BridgeChild",
            "out-variable alias": probe + "Write-Output 1 -ov BridgeChild",
            "out-variable prefix": probe + "Write-Output 1 -OutVar BridgeChild",
            "out-variable colon": probe + "Write-Output 1 -OutVariable:BridgeChild",
            "out-variable computed": probe + "$BridgeName = 'Bridge' + 'Child'\nWrite-Output 1 -OutVariable $BridgeName",
            "error-variable": probe + "Get-Item -LiteralPath C:\\x -ErrorVariable BridgeChild",
            "warning-variable": probe + "Write-Output 1 -WarningVariable BridgeChild",
            "information-variable": probe + "Write-Output 1 -InformationVariable BridgeChild",
            "pipeline-variable": probe + "Get-ChildItem -LiteralPath C:\\x -PipelineVariable BridgeChild | Write-Output",
            "pipeline-variable alias": probe + "Get-ChildItem -LiteralPath C:\\x -pv BridgeChild | Write-Output",
            "non-root start": "if ($true) {\n" + probe + "}",
            "piped start": swap(probe, "\n}))", "\n})) | Select-Object -First 1"),
            "scoped start target": swap(probe, "$BridgeChild = ", "$script:BridgeChild = "),
            "other launch name": swap(probe, "$BridgeChild = ", "$Evil = "),
            "short type name": swap(probe, "[System.Diagnostics.Process]", "[Diagnostics.Process]"),
            "other type": swap(probe, "[System.Diagnostics.Process]", "[System.IO.File]"),
            "other method": probe + "$BridgeChild.Refresh()",
            "kill with argument": probe + "$BridgeChild.Kill($true)",
            "wait with timeout": probe + "$BridgeChild.WaitForExit(1000)",
            "other variable kill": probe + "$BridgeOther.Kill()",
            "other stream method": probe + "$BridgeChild.StandardInput.WriteLine('x')",
            "other static method": "[System.Diagnostics.Process]::GetProcessById(4)",
            "member assignment": probe + "$BridgeChild.EnableRaisingEvents = $true",
        }
        for label, extra in cases.items():
            with self.subTest(case=label):
                self.assertIn(DYNAMIC, self.effects(extra + "\n"))

    def test_variable_binding_parameters_are_allowed_without_a_launch(self):
        # The binding rule only applies once a classified launch exists.
        effects = self.effects("Get-Item -LiteralPath C:\\x -ErrorVariable BridgeReadErrors\n")
        self.assertNotIn(DYNAMIC, effects)

    # --- output capture write ------------------------------------------

    def test_output_capture_write_variations_stay_dynamic(self):
        cases = {
            "path": "Set-Content -Path $BridgeChildStdoutPath -Value $BridgeChildStdoutText -Encoding UTF8",
            "other path variable": "Set-Content -LiteralPath $BridgeRunnerRoot -Value $BridgeChildStdoutText -Encoding UTF8",
            "other value variable": "Set-Content -LiteralPath $BridgeTargetProbeStdoutPath -Value $BridgeTargetSha -Encoding UTF8",
            "expression value": "Set-Content -LiteralPath $BridgeTargetProbeStdoutPath -Value (Get-Date) -Encoding UTF8",
            "literal path": "Set-Content -LiteralPath C:\\x -Value $BridgeChildStdoutText -Encoding UTF8",
            "other encoding": "Set-Content -LiteralPath $BridgeTargetProbeStdoutPath -Value $BridgeChildStdoutText -Encoding ASCII",
            "extra parameter": "Set-Content -LiteralPath $BridgeTargetProbeStdoutPath -Value $BridgeChildStdoutText -Encoding UTF8 -Force",
            "pipeline": "$BridgeChildStdoutText | Set-Content -LiteralPath $BridgeTargetProbeStdoutPath -Value $BridgeChildStdoutText -Encoding UTF8",
            "scoped path": "Set-Content -LiteralPath $env:BridgeTargetProbeStdoutPath -Value $BridgeChildStdoutText -Encoding UTF8",
        }
        for label, extra in cases.items():
            with self.subTest(case=label):
                self.assertIn(DYNAMIC, self.effects(extra + "\n"))

    # --- Start-Process -Credential --------------------------------------

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
