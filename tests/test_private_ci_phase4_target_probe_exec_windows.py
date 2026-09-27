"""Real Windows PowerShell 5.1 execution regressions for #273.

The Phase 4 target probe (``scripts/Invoke-PrivateCiPhase4TargetProbe.ps1``)
burned the second #216 pilot identity: under Windows PowerShell 5.1 with
``$ErrorActionPreference = 'Stop'``, redirecting a native command's stderr
(``*> $null``) turned gh's correct "not logged in" line into a terminating
``NativeCommandError`` before the probe read ``$LASTEXITCODE``.

``test_private_ci_phase4_target_probe_windows.py`` only parses the probe and
matches source fragments, so it never saw this. The tests here **execute** the
tracked probe under ``powershell.exe`` 5.1 as a throwaway non-administrator
local account (standing in for ``ac-runner``), with small compiled ``gh``
stubs and with the runner image's real, unauthenticated ``gh.exe``.

A second, non-elevated test class scans every tracked ``scripts/*.ps1`` and the
rendered Phase 4/5/6 candidates with the real PowerShell 5.1 AST and rejects any
stderr (``2>``) or all-stream (``*>``) redirection on a native command, so the
same shape cannot come back.

The execution tests need an elevated administrator to create the account. They
skip on developer machines without elevation, but fail instead of skipping
under CI.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE = REPO_ROOT / "scripts" / "Invoke-PrivateCiPhase4TargetProbe.ps1"
REAL_GH = Path(r"C:\Program Files\GitHub CLI\gh.exe")
LAUNCH_TIMEOUT_SECONDS = 90

EXPECTED_PASS_PAYLOAD_KEYS = {
    "schema",
    "status",
    "host",
    "identity",
    "admin_sid_present",
    "high_integrity_present",
    "forbidden_environment_count",
    "broker_credential_roots_readable",
    "gh_authenticated",
    "authority_marker_write_denied",
}

GH_STUBS = {
    # gh's real unauthenticated shape: one line on stderr, exit 1.
    "gh-unauthenticated": (
        'Console.Error.WriteLine("You are not logged into any GitHub hosts. '
        'To log in, run: gh auth login"); return 1;'
    ),
    # A usable authentication: stdout only, exit 0.
    "gh-authenticated": (
        'Console.Out.WriteLine("github.com"); '
        'Console.Out.WriteLine("  Logged in to github.com account stub"); return 0;'
    ),
    # Authenticated but noisy on stderr: must still fail closed for the right reason.
    "gh-authenticated-noisy": (
        'Console.Error.WriteLine("github.com"); '
        'Console.Error.WriteLine("  Logged in to github.com account stub"); return 0;'
    ),
    # Never returns: the probe must not wait forever.
    "gh-hang": "System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite); return 1;",
}


def _powershell_env() -> dict[str, str]:
    # Let Windows PowerShell 5.1 rebuild its own module path (a PowerShell 7
    # PSModulePath breaks Set-Acl and friends).
    return {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}


def _run_powershell(script: str, *, directory: Path, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    path = directory / f"step-{secrets.token_hex(6)}.ps1"
    path.write_text(script, encoding="utf-8-sig")
    try:
        return subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_powershell_env(),
            timeout=timeout,
        )
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _is_elevated_admin() -> bool:
    if os.name != "nt":
        return False
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
            ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_powershell_env(),
    )
    return completed.returncode == 0 and completed.stdout.strip() == "True"


def _new_password() -> str:
    return "Aa1!" + secrets.token_hex(12)


def _annotate(title: str, message: str) -> None:
    # CI job logs cannot be downloaded from every review surface; surface the
    # failure as a GitHub check-run annotation instead.
    flat = " ".join(str(message).split())[:1500]
    print(f"::error title=issue273-{title}::{flat}", flush=True)


class _AnnotatedTestCase(unittest.TestCase):
    def run(self, result=None):
        if result is None:
            return super().run(result)
        failures_before = len(result.failures)
        errors_before = len(result.errors)
        outcome = super().run(result)
        # Annotate only this test's own new failures/errors.
        for _test, trace in result.failures[failures_before:] + result.errors[errors_before:]:
            _annotate(self._testMethodName, trace.strip().splitlines()[-1] + " || " + trace[-1200:])
        return outcome


@unittest.skipUnless(os.name == "nt", "real Windows PowerShell 5.1 target-probe execution regression")
class PrivateCiPhase4TargetProbeExecutionWindowsTests(_AnnotatedTestCase):
    @classmethod
    def setUpClass(cls):
        if not _is_elevated_admin():
            if os.environ.get("CI", "").lower() == "true":
                _annotate("setup", "target-probe execution regressions must run elevated under CI")
                raise AssertionError("target-probe execution regressions must run elevated under CI")
            raise unittest.SkipTest("requires an elevated administrator to create a test account")

        suffix = secrets.token_hex(3)
        cls.target_name = f"acprb{suffix}"
        cls.target_password = _new_password()
        cls.work = Path(tempfile.mkdtemp(prefix="ac-issue273-"))
        cls.base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / f"ac-issue273-{suffix}"
        cls.computer = os.environ.get("COMPUTERNAME", ".")

        host = subprocess.run(["hostname.exe"], check=False, capture_output=True, text=True)
        if host.returncode != 0 or not host.stdout.strip():
            raise AssertionError("hostname.exe readback failed")
        cls.expected_host = host.stdout.strip()

        stub_lines = []
        for index, (name, body) in enumerate(GH_STUBS.items()):
            source = (
                "using System; public static class Ac273GhStub%d { "
                "public static int Main(string[] args) { %s } }" % (index, body)
            )
            stub_lines.append(
                f"Add-Type -TypeDefinition {_ps_quote(source)} -Language CSharp "
                f"-OutputAssembly (Join-Path $Bin {_ps_quote(name + '.exe')}) -OutputType ConsoleApplication"
            )

        created = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Base = {_ps_quote(str(cls.base))}",
                    "New-Item -ItemType Directory -Path $Base | Out-Null",
                    "$Bin = Join-Path $Base 'bin'",
                    "New-Item -ItemType Directory -Path $Bin | Out-Null",
                    "New-Item -ItemType Directory -Path (Join-Path $Base 'scripts') | Out-Null",
                    "New-Item -ItemType Directory -Path (Join-Path $Base 'out') | Out-Null",
                    *stub_lines,
                    f"$Target = New-LocalUser -Name {_ps_quote(cls.target_name)} -Password (ConvertTo-SecureString {_ps_quote(cls.target_password)} -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires",
                    "try { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $Target -ErrorAction Stop }",
                    "catch [Microsoft.PowerShell.Commands.MemberExistsException] { }",
                    "[ordered]@{ target_sid = $Target.SID.Value } | ConvertTo-Json -Compress",
                ]
            ),
            directory=cls.work,
        )
        if created.returncode != 0:
            cls._cleanup()
            _annotate("setup", "test account or stub creation failed: " + created.stderr)
            raise AssertionError("test account or stub creation failed: " + created.stderr)
        cls.target_sid = json.loads(created.stdout.strip().splitlines()[-1])["target_sid"]

        cls.probe_copy = cls.base / "scripts" / PROBE.name
        shutil.copyfile(PROBE, cls.probe_copy)

        # Protected authority marker: the target may read it but not write it,
        # as with the real authority container.
        cls.protected_marker = cls.base / "marker-protected.json"
        cls.writable_marker = cls.base / "marker-writable.json"
        marker = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Protected = {_ps_quote(str(cls.protected_marker))}",
                    f"$Writable = {_ps_quote(str(cls.writable_marker))}",
                    "Set-Content -LiteralPath $Protected -Value '{}' -Encoding ASCII",
                    "Set-Content -LiteralPath $Writable -Value '{}' -Encoding ASCII",
                    f"icacls.exe $Protected /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' '*{cls.target_sid}:(R)' /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'protected marker ACL failed' }",
                    f"icacls.exe $Writable /grant '*{cls.target_sid}:(M)' /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'writable marker ACL failed' }",
                ]
            ),
            directory=cls.work,
        )
        if marker.returncode != 0:
            cls._cleanup()
            _annotate("setup", "marker preparation failed: " + marker.stderr)
            raise AssertionError("marker preparation failed: " + marker.stderr)

    @classmethod
    def tearDownClass(cls):
        cls._cleanup()

    @classmethod
    def _cleanup(cls):
        work = getattr(cls, "work", None)
        if work is None:
            return
        base = getattr(cls, "base", None)
        script = ["$ErrorActionPreference = 'Continue'"]
        if base is not None:
            script.extend(
                [
                    f"$Base = {_ps_quote(str(base))}",
                    "if (Test-Path -LiteralPath $Base) {",
                    "    takeown.exe /F $Base /R /D Y | Out-Null",
                    "    icacls.exe $Base /reset /T /C /Q | Out-Null",
                    "    Remove-Item -LiteralPath $Base -Recurse -Force -ErrorAction SilentlyContinue",
                    "}",
                ]
            )
        name = getattr(cls, "target_name", None)
        if name:
            script.extend(
                [
                    f"$User = Get-LocalUser -Name {_ps_quote(name)} -ErrorAction SilentlyContinue",
                    "if ($null -ne $User) {",
                    "    Get-CimInstance Win32_UserProfile -Filter (\"SID='\" + $User.SID.Value + \"'\") -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue",
                    "    Remove-LocalUser -SID $User.SID -ErrorAction SilentlyContinue",
                    "}",
                ]
            )
        _run_powershell("\n".join(script), directory=work)
        shutil.rmtree(work, ignore_errors=True)

    def _run_probe(self, gh_path: Path, *, marker: Path | None = None) -> dict:
        """Execute the tracked probe as the non-admin target account.

        The launcher holds the child handle and bounds the wait, so a probe that
        never returns is reported as ``timeout`` instead of hanging the job.
        """
        label = f"case-{secrets.token_hex(4)}"
        out_dir = self.base / "out" / label
        result_path = out_dir / "result.json"
        stdout_path = self.base / "out" / f"{label}.out"
        stderr_path = self.base / "out" / f"{label}.err"
        marker = marker or self.protected_marker
        arguments = " ".join(
            [
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass",
                f'-File "{self.probe_copy}"',
                f'-ExpectedHost "{self.expected_host}"',
                f'-ExpectedIdentity "{self.computer}\\{self.target_name}"',
                f'-AuthorityMarkerPath "{marker}"',
                f'-ResultPath "{result_path}"',
                f'-TrustedGhPath "{gh_path}"',
            ]
        )
        launcher = "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$OutDir = {_ps_quote(str(out_dir))}",
                "New-Item -ItemType Directory -Path $OutDir | Out-Null",
                f"icacls.exe $OutDir /grant '*{self.target_sid}:(OI)(CI)(M)' /Q | Out-Null",
                "if ($LASTEXITCODE -ne 0) { throw 'result directory ACL failed' }",
                "foreach ($Name in @('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN')) {",
                "    Remove-Item -LiteralPath ('Env:' + $Name) -ErrorAction SilentlyContinue",
                "}",
                "$Credential = New-Object System.Management.Automation.PSCredential("
                f"{_ps_quote(self.computer + chr(92) + self.target_name)}, "
                f"(ConvertTo-SecureString {_ps_quote(self.target_password)} -AsPlainText -Force))",
                f"$Child = Start-Process -FilePath 'powershell.exe' -ArgumentList {_ps_quote(arguments)} "
                "-Credential $Credential "
                f"-WorkingDirectory {_ps_quote(str(self.base / 'scripts'))} "
                f"-RedirectStandardOutput {_ps_quote(str(stdout_path))} "
                f"-RedirectStandardError {_ps_quote(str(stderr_path))} -PassThru",
                # The launcher is elevated, so it can open the target-owned
                # child; take the handle now so the exit code stays readable.
                "$null = $Child.Handle",
                f"if (-not $Child.WaitForExit({LAUNCH_TIMEOUT_SECONDS * 1000})) {{",
                "    taskkill.exe /T /F /PID $Child.Id | Out-Null",
                "    Write-Output 'child_exit=timeout'",
                "    exit 0",
                "}",
                "$Child.WaitForExit()",
                "Write-Output ('child_exit=' + $Child.ExitCode)",
            ]
        )
        started = time.monotonic()
        completed = _run_powershell(launcher, directory=self.work, timeout=LAUNCH_TIMEOUT_SECONDS + 120)
        elapsed = time.monotonic() - started
        if completed.returncode != 0:
            self.fail(f"probe launcher failed: {completed.stdout} {completed.stderr}")
        exit_lines = [line for line in completed.stdout.splitlines() if line.startswith("child_exit=")]
        self.assertEqual(len(exit_lines), 1, completed.stdout)
        exit_text = exit_lines[0].split("=", 1)[1].strip()
        read = lambda path: path.read_text(encoding="utf-8-sig", errors="replace") if path.exists() else ""
        return {
            "exit": None if exit_text == "timeout" else int(exit_text),
            "stdout": read(stdout_path),
            "stderr": read(stderr_path),
            "result_path": result_path,
            "elapsed": elapsed,
        }

    def _assert_probe_pass(self, run: dict) -> None:
        detail = f"exit={run['exit']} stdout={run['stdout']!r} stderr={run['stderr']!r}"
        self.assertEqual(run["exit"], 0, detail)
        self.assertIn("TARGET_PROBE_PASS", run["stdout"], detail)
        self.assertTrue(run["result_path"].is_file(), "probe result missing: " + detail)
        raw = run["result_path"].read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "probe result must be UTF-8 without BOM")
        payload = json.loads(raw.decode("utf-8"))
        self.assertEqual(set(payload), EXPECTED_PASS_PAYLOAD_KEYS)
        self.assertEqual(payload["schema"], "agent-controller.private-ci-phase4-target-probe.v1")
        self.assertEqual(payload["status"], "TARGET_PROBE_PASS")
        self.assertEqual(payload["host"].lower(), self.expected_host.lower())
        self.assertEqual(payload["identity"].lower(), f"{self.computer}\\{self.target_name}".lower())
        self.assertIs(payload["admin_sid_present"], False)
        self.assertIs(payload["high_integrity_present"], False)
        self.assertEqual(payload["forbidden_environment_count"], 0)
        self.assertEqual(payload["broker_credential_roots_readable"], 0)
        self.assertIs(payload["gh_authenticated"], False)
        self.assertIs(payload["authority_marker_write_denied"], True)

    def _assert_probe_fails_with(self, run: dict, message: str) -> None:
        detail = f"exit={run['exit']} stdout={run['stdout']!r} stderr={run['stderr']!r}"
        self.assertIsNotNone(run["exit"], "probe did not return: " + detail)
        self.assertNotEqual(run["exit"], 0, detail)
        self.assertNotIn("TARGET_PROBE_PASS", run["stdout"], detail)
        self.assertFalse(run["result_path"].exists(), "failed probe must not write a result: " + detail)
        self.assertIn(message, run["stderr"], detail)
        self.assertNotIn("NativeCommandError", run["stderr"], detail)

    def _stub(self, name: str) -> Path:
        return self.base / "bin" / f"{name}.exe"

    def test_probe_passes_with_unauthenticated_gh_stub(self):
        self._assert_probe_pass(self._run_probe(self._stub("gh-unauthenticated")))

    def test_probe_passes_with_real_unauthenticated_gh(self):
        if not REAL_GH.is_file():
            self.fail(f"runner image has no gh at {REAL_GH}; the real-gh regression cannot run")
        self._assert_probe_pass(self._run_probe(REAL_GH))

    def test_probe_fails_closed_with_authenticated_gh_stub(self):
        self._assert_probe_fails_with(
            self._run_probe(self._stub("gh-authenticated")),
            "target identity unexpectedly has usable gh authentication",
        )

    def test_probe_fails_closed_with_authenticated_gh_stub_that_writes_stderr(self):
        self._assert_probe_fails_with(
            self._run_probe(self._stub("gh-authenticated-noisy")),
            "target identity unexpectedly has usable gh authentication",
        )

    def test_probe_fails_closed_when_target_can_write_authority_marker(self):
        # The authority-marker write-denial check has never run on the real
        # host: the pilot probe died at the gh call first.
        self._assert_probe_fails_with(
            self._run_probe(self._stub("gh-unauthenticated"), marker=self.writable_marker),
            "target identity can acquire write access to protected authority marker",
        )

    def test_probe_fails_closed_when_gh_never_returns(self):
        run = self._run_probe(self._stub("gh-hang"))
        self._assert_probe_fails_with(run, "target probe gh auth check timed out")
        self.assertLess(run["elapsed"], 75, "probe must bound the gh wait well below the launcher timeout")


# ---------------------------------------------------------------------------
# Static guard: no stderr/all-stream redirection on native commands.
# ---------------------------------------------------------------------------

AST_GUARD_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$Findings = New-Object System.Collections.Generic.List[string]
foreach ($Path in @(Get-Content -LiteralPath $env:AC273_GUARD_LIST -Encoding UTF8)) {
    if ([string]::IsNullOrWhiteSpace($Path)) { continue }
    $Tokens = $null
    $Errors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$Tokens, [ref]$Errors)
    if (@($Errors).Count -ne 0) {
        $Findings.Add('PARSE_ERROR|' + $Path)
        continue
    }
    $LocalFunctions = @{}
    foreach ($Definition in @($Ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
        $LocalFunctions[$Definition.Name.ToLowerInvariant()] = $true
    }
    foreach ($Command in @($Ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.CommandAst] }, $true))) {
        $StderrRedirections = @($Command.Redirections | Where-Object {
            $_.FromStream -eq [System.Management.Automation.Language.RedirectionStream]::Error -or
            $_.FromStream -eq [System.Management.Automation.Language.RedirectionStream]::All
        })
        if ($StderrRedirections.Count -eq 0) { continue }
        $Name = $Command.GetCommandName()
        $Native = $true
        if ($null -ne $Name -and $Name -notmatch '\.(exe|com|cmd|bat)$') {
            if ($LocalFunctions.ContainsKey($Name.ToLowerInvariant())) {
                $Native = $false
            }
            elseif ($null -ne (Get-Command -Name $Name -CommandType Cmdlet, Function, Alias -ErrorAction SilentlyContinue)) {
                $Native = $false
            }
        }
        if ($Native) {
            $Findings.Add($Path + '|' + $Command.Extent.StartLineNumber + '|' + ($Command.Extent.Text -replace '\s+', ' '))
        }
    }
}
# One line per finding; ConvertTo-Json serializes arrays differently in 5.1 and 7.
foreach ($Finding in $Findings) {
    Write-Output ('FINDING|' + $Finding)
}
Write-Output ('GUARD_DONE|' + $Findings.Count)
"""

# Existing redirections already evaluated under a local
# ``$ErrorActionPreference = 'Continue'`` (checked by the test): the broker-side
# burned-evidence archive child (#259). Keyed by file name and the command text
# before its ``-c`` payload.
ALLOWED_GUARDED_REDIRECTIONS = {
    ("Archive-PrivateCiBurnedEvidence.ps1", "& $PythonPath -I -S -B"),
}


def _guard_binding():
    from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding

    generation = "ac-pilot-0123456789abcdef"
    return PrivateCiPilotBinding(
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-273",
        workflow_sha="2" * 40,
        workflow_path=".github/workflows/private-ci-windows-pilot.yml",
        runner_id=23,
        runner_name="ac-ci-0123456789abcdef",
        runner_label="private-ci-windows-pilot",
        environment_generation=generation,
        runner_root=rf"C:\ProgramData\agent-controller\private-ci\{generation}\runner",
        work_folder="_work",
        host="WOBBUFFET",
        broker_identity=r"WOBBUFFET\c-admin",
        target_identity="ac-runner",
    )


def _rendered_candidates() -> dict[str, str]:
    from agent_controller.private_ci_phase4_contract import (
        REGISTRATION_HANDOFF_SCHEMA,
        RegistrationHandoffEvidence,
        render_phase4_target_environment_candidate,
    )
    from agent_controller.private_ci_phase5_contract import render_phase5_exactly_one_job_candidate
    from agent_controller.private_ci_phase5_result import (
        PHASE5_RESULT_SCHEMA,
        PHASE5_RESULT_STATUS,
        Phase5ResultEvidence,
        phase5_result_bytes,
    )
    from agent_controller.private_ci_phase6_contract import (
        build_phase6_cleanup_plan,
        render_phase6_cleanup_candidate,
    )

    binding = _guard_binding()
    handoff = RegistrationHandoffEvidence(
        schema=REGISTRATION_HANDOFF_SCHEMA,
        binding=binding,
        phase0_evidence_sha256="3" * 64,
        registration_plan_sha256="4" * 64,
        human_approval_sha256="5" * 64,
        registration_consumption_sha256="6" * 64,
        registration_result_sha256="7" * 64,
        local_runner_settings_sha256="8" * 64,
        runner_generation_snapshot_sha256="9" * 64,
        registration_status="REGISTERED",
    )
    phase5_result = Phase5ResultEvidence(
        schema=PHASE5_RESULT_SCHEMA,
        binding=binding,
        phase5_plan_sha256="1" * 64,
        phase4_result_sha256="2" * 64,
        human_approval_sha256="3" * 64,
        phase5_consumption_sha256="4" * 64,
        candidate_sha256="5" * 64,
        workflow_run_id=9001,
        workflow_run_attempt=1,
        job_id=7001,
        runner_id=binding.runner_id,
        runner_name=binding.runner_name,
        runner_label=binding.runner_label,
        runner_process_id=8123,
        runner_process_owner=r"WOBBUFFET\ac-runner",
        runner_child_exit_code=0,
        security_probe_sha256="6" * 64,
        security_probe_result_sha256="7" * 64,
        security_probe_stdout_sha256="8" * 64,
        security_probe_stderr_sha256="9" * 64,
        runner_stdout_sha256="a" * 64,
        runner_stderr_sha256="b" * 64,
        status=PHASE5_RESULT_STATUS,
        completed_at="2026-09-22T12:00:00+00:00",
    )
    return {
        "phase4-candidate.ps1": render_phase4_target_environment_candidate(
            binding, handoff, target_probe_sha256="b" * 64
        ),
        "phase5-candidate.ps1": render_phase5_exactly_one_job_candidate(
            binding, phase4_result_sha256="b" * 64, target_probe_sha256="c" * 64
        ),
        "phase6-candidate.ps1": render_phase6_cleanup_candidate(
            build_phase6_cleanup_plan(phase5_result_bytes(phase5_result))
        ),
    }


@unittest.skipUnless(os.name == "nt", "real Windows PowerShell 5.1 AST guard")
class NativeStderrRedirectionGuardWindowsTests(_AnnotatedTestCase):
    def _scan(self, paths: list[Path]) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            listing = Path(directory) / "guard-list.txt"
            listing.write_text("\n".join(str(path) for path in paths), encoding="utf-8")
            environment = _powershell_env()
            environment["AC273_GUARD_LIST"] = str(listing)
            script = Path(directory) / "guard.ps1"
            script.write_text(AST_GUARD_SCRIPT, encoding="utf-8-sig")
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
                timeout=300,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        findings = [line[len("FINDING|") :] for line in lines if line.startswith("FINDING|")]
        done = [line for line in lines if line.startswith("GUARD_DONE|")]
        self.assertEqual(done, [f"GUARD_DONE|{len(findings)}"], completed.stdout + completed.stderr)
        return findings

    def test_guard_detects_the_burned_shape(self):
        # Keep the guard honest: it must flag native redirections and ignore cmdlets.
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.ps1"
            sample.write_text(
                "\n".join(
                    [
                        "$ErrorActionPreference = 'Stop'",
                        "& $TrustedGhPath auth status --hostname github.com *> $null",
                        "gh.exe api user 2>&1 | Out-Null",
                        "whoami.exe 2> $null",
                        "Get-Item -LiteralPath 'C:\\' 2> $null",
                        "function Invoke-Local { 'x' }",
                        "Invoke-Local 2>&1 | Out-Null",
                        "hostname.exe | Out-Null",
                    ]
                ),
                encoding="utf-8",
            )
            findings = self._scan([sample])
        lines = sorted(int(item.split("|")[1]) for item in findings)
        self.assertEqual(lines, [2, 3, 4], findings)

    def test_tracked_scripts_and_rendered_candidates_have_no_native_stderr_redirection(self):
        scripts = sorted((REPO_ROOT / "scripts").glob("*.ps1"))
        self.assertIn(PROBE, scripts)
        with tempfile.TemporaryDirectory() as directory:
            rendered = []
            for name, text in _rendered_candidates().items():
                path = Path(directory) / name
                path.write_text(text, encoding="utf-8")
                rendered.append(path)
            findings = self._scan(scripts + rendered)
        remaining = []
        allowed_seen = 0
        for finding in findings:
            path, line, text = finding.split("|", 2)
            name = Path(path).name
            if (name, text.split(" -c ", 1)[0]) in ALLOWED_GUARDED_REDIRECTIONS:
                self._assert_local_continue_guard(Path(path), int(line))
                allowed_seen += 1
                continue
            remaining.append(finding)
        self.assertEqual(remaining, [], "native stderr redirection under Stop (#273): " + "; ".join(remaining))
        # A stale allowlist entry must not silently widen the guard.
        self.assertEqual(allowed_seen, len(ALLOWED_GUARDED_REDIRECTIONS), findings)

    def _assert_local_continue_guard(self, path: Path, line: int) -> None:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        window = [text.strip() for text in lines[max(0, line - 4) : line - 1]]
        self.assertIn(
            "$ErrorActionPreference = 'Continue'",
            window,
            f"{path.name}:{line} redirects native stderr without a local Continue guard",
        )


if __name__ == "__main__":
    unittest.main()
