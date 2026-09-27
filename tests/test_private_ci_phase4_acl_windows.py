"""Real Windows regressions for #265 (Phase 4 ACL preparation and credential gate).

These tests execute the exact candidate blocks rendered by
``render_phase4_target_environment_candidate`` under real Windows PowerShell
5.1, using two throwaway local accounts that are created and deleted by the
test itself:

* a *broker* account that is a plain (non-administrator) user, like the
  non-elevated ``c-admin`` broker that runs the Phase 4 candidate on the owner
  machine; and
* a *target* account standing in for ``ac-runner``.

GitHub-hosted Windows runners execute as an elevated administrator, so running
the ACL block directly would hide the broker self-lockout observed on the real
host. The block is therefore launched as the non-administrator broker account.

The tests need an elevated administrator to create the accounts. They skip on
developer machines without elevation, but fail instead of skipping under CI.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_controller.private_ci_phase4_contract import (
    PHASE4_ACL_BLOCK_BEGIN,
    PHASE4_ACL_BLOCK_END,
    PHASE4_CREDENTIAL_BLOCK_BEGIN,
    PHASE4_CREDENTIAL_BLOCK_END,
    REGISTRATION_HANDOFF_SCHEMA,
    PrivateCiPilotBinding,
    RegistrationHandoffEvidence,
    render_phase4_target_environment_candidate,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
CREDENTIAL_CHECK_SCRIPT = REPO_ROOT / "scripts" / "Test-PrivateCiTargetCredential.ps1"
FULL_CONTROL = 2032127
MODIFY = 197055
SYNCHRONIZE = 1048576


def _powershell_env() -> dict[str, str]:
    # Let Windows PowerShell 5.1 rebuild its own module path (a PowerShell 7
    # PSModulePath breaks Set-Acl and friends).
    env = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    return env


def _run_powershell(script: str, *, directory: Path) -> subprocess.CompletedProcess[str]:
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
            timeout=300,
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


def _binding() -> PrivateCiPilotBinding:
    generation = "ac-pilot-0123456789abcdef"
    return PrivateCiPilotBinding(
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
        workflow_sha="2" * 40,
        workflow_path=".github/workflows/private-ci-windows-pilot.yml",
        runner_id=23,
        runner_name="ac-ci-0123456789abcdef",
        runner_label="private-ci-windows-pilot",
        environment_generation=generation,
        runner_root=(
            r"C:\ProgramData\agent-controller\private-ci"
            rf"\{generation}\runner"
        ),
        work_folder="_work",
        host="WOBBUFFET",
        broker_identity=r"WOBBUFFET\c-admin",
        target_identity="ac-runner",
    )


def _rendered_candidate() -> str:
    binding = _binding()
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
    return render_phase4_target_environment_candidate(
        binding,
        handoff,
        target_probe_sha256="b" * 64,
    )


def _candidate_block(begin: str, end: str) -> str:
    lines = _rendered_candidate().splitlines()
    if begin not in lines or end not in lines:
        raise AssertionError(f"rendered Phase 4 candidate has no block {begin!r}")
    start = lines.index(begin)
    stop = lines.index(end)
    if stop <= start:
        raise AssertionError(f"rendered Phase 4 candidate block {begin!r} is malformed")
    return "\n".join(lines[start : stop + 1])


def _new_password() -> str:
    return "Aa1!" + secrets.token_hex(12)


def _annotate(title: str, message: str) -> None:
    # CI job logs cannot be downloaded from every review surface; surface the
    # failure as a GitHub check-run annotation instead.
    flat = " ".join(str(message).split())[:1500]
    print(f"::error title=issue265-{title}::{flat}", flush=True)


class _AnnotatedTestCase(unittest.TestCase):
    def run(self, result=None):
        failures_before = len(result.failures) + len(result.errors) if result is not None else 0
        outcome = super().run(result)
        if result is not None and len(result.failures) + len(result.errors) > failures_before:
            _test, trace = (result.failures + result.errors)[-1]
            _annotate(self._testMethodName, trace.strip().splitlines()[-1] + " || " + trace[-1200:])
        return outcome


@unittest.skipUnless(os.name == "nt", "real Windows Phase 4 ACL regression")
class PrivateCiPhase4AclWindowsTests(_AnnotatedTestCase):
    @classmethod
    def setUpClass(cls):
        if not _is_elevated_admin():
            if os.environ.get("CI", "").lower() == "true":
                _annotate("setup", "Phase 4 ACL regressions must run elevated under CI")
                raise AssertionError("Phase 4 ACL regressions must run elevated under CI")
            raise unittest.SkipTest("requires an elevated administrator to create test accounts")

        suffix = secrets.token_hex(3)
        cls.broker_name = f"acbrk{suffix}"
        cls.target_name = f"actgt{suffix}"
        cls.broker_password = _new_password()
        cls.target_password = _new_password()
        cls.work = Path(tempfile.mkdtemp(prefix="ac-phase4-acl-"))
        cls.base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / f"ac-phase4-acl-{suffix}"

        created = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Broker = New-LocalUser -Name {_ps_quote(cls.broker_name)} -Password (ConvertTo-SecureString {_ps_quote(cls.broker_password)} -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires",
                    f"$Target = New-LocalUser -Name {_ps_quote(cls.target_name)} -Password (ConvertTo-SecureString {_ps_quote(cls.target_password)} -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires",
                    "foreach ($Member in @($Broker, $Target)) {",
                    "    try { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $Member -ErrorAction Stop }",
                    "    catch [Microsoft.PowerShell.Commands.MemberExistsException] { }",
                    "}",
                    "[ordered]@{ broker_sid = $Broker.SID.Value; target_sid = $Target.SID.Value } | ConvertTo-Json -Compress",
                ]
            ),
            directory=cls.work,
        )
        if created.returncode != 0:
            cls._remove_accounts()
            _annotate("setup", "test account creation failed: " + created.stderr)
            raise AssertionError("test account creation failed: " + created.stderr)
        sids = json.loads(created.stdout.strip().splitlines()[-1])
        cls.broker_sid = sids["broker_sid"]
        cls.target_sid = sids["target_sid"]

    @classmethod
    def tearDownClass(cls):
        base = getattr(cls, "base", None)
        work = getattr(cls, "work", None)
        if base is not None and work is not None and base.exists():
            _run_powershell(
                "\n".join(
                    [
                        f"takeown.exe /F {_ps_quote(str(base))} /R /D Y | Out-Null",
                        f"icacls.exe {_ps_quote(str(base))} /reset /T /C /Q | Out-Null",
                        f"Remove-Item -LiteralPath {_ps_quote(str(base))} -Recurse -Force -ErrorAction SilentlyContinue",
                    ]
                ),
                directory=work,
            )
        cls._remove_accounts()
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)

    @classmethod
    def _remove_accounts(cls):
        work = getattr(cls, "work", None)
        if work is None:
            return
        names = [getattr(cls, "broker_name", None), getattr(cls, "target_name", None)]
        script = ["$ErrorActionPreference = 'Continue'"]
        for name in names:
            if not name:
                continue
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

    def _credential_expression(self, name: str, password: str) -> str:
        return (
            "(New-Object System.Management.Automation.PSCredential("
            f"({_ps_quote(os.environ.get('COMPUTERNAME', '.') + chr(92) + name)}), "
            f"(ConvertTo-SecureString {_ps_quote(password)} -AsPlainText -Force)))"
        )

    def _run_as(self, name: str, password: str, script: str, label: str) -> tuple[int, str, str]:
        """Run ``script`` as a local account through Start-Process -Credential."""
        script_path = self.base / "scripts" / f"{label}.ps1"
        script_path.write_text(script, encoding="utf-8-sig")
        out_path = self.base / "out" / f"{label}.out"
        err_path = self.base / "out" / f"{label}.err"
        launcher = "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$Credential = {self._credential_expression(name, password)}",
                "$Child = Start-Process -FilePath 'powershell.exe' -ArgumentList @("
                "'-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "
                f"{_ps_quote(str(script_path))}) -Credential $Credential "
                f"-WorkingDirectory {_ps_quote(str(self.base / 'scripts'))} "
                f"-RedirectStandardOutput {_ps_quote(str(out_path))} "
                f"-RedirectStandardError {_ps_quote(str(err_path))} -Wait -PassThru",
                "Write-Output ('child_exit=' + $Child.ExitCode)",
            ]
        )
        completed = _run_powershell(launcher, directory=self.work)
        if completed.returncode != 0:
            self.fail(f"launcher for {label} failed: {completed.stderr}")
        exit_line = [line for line in completed.stdout.splitlines() if line.startswith("child_exit=")]
        self.assertEqual(len(exit_line), 1, completed.stdout)
        out = out_path.read_text(encoding="utf-8", errors="replace") if out_path.exists() else ""
        err = err_path.read_text(encoding="utf-8", errors="replace") if err_path.exists() else ""
        return int(exit_line[0].split("=", 1)[1]), out, err

    def _prepare_runner_tree(self) -> Path:
        """Build a runner tree the broker owns, as after a real registration."""
        runner = self.base / "gen" / "runner"
        setup = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Base = {_ps_quote(str(self.base))}",
                    f"$Runner = {_ps_quote(str(runner))}",
                    "if (Test-Path -LiteralPath $Base) {",
                    "    takeown.exe /F $Base /R /D Y | Out-Null",
                    "    icacls.exe $Base /reset /T /C /Q | Out-Null",
                    "    Remove-Item -LiteralPath $Base -Recurse -Force",
                    "}",
                    "New-Item -ItemType Directory -Path (Join-Path $Base 'scripts') | Out-Null",
                    "New-Item -ItemType Directory -Path (Join-Path $Base 'out') | Out-Null",
                    "New-Item -ItemType Directory -Path (Join-Path $Runner 'bin') | Out-Null",
                    "New-Item -ItemType Directory -Path (Join-Path $Runner 'externals\\node\\bin') | Out-Null",
                    "Set-Content -LiteralPath (Join-Path $Runner 'config.cmd') -Value 'rem config' -Encoding ASCII",
                    "Set-Content -LiteralPath (Join-Path $Runner '.runner') -Value '{}' -Encoding ASCII",
                    "Set-Content -LiteralPath (Join-Path $Runner 'bin\\Runner.Listener.exe') -Value 'x' -Encoding ASCII",
                    "Set-Content -LiteralPath (Join-Path $Runner 'externals\\node\\bin\\node.exe') -Value 'x' -Encoding ASCII",
                    # Like a broker-created tree: the broker owns it and holds inherited full control.
                    f"icacls.exe $Base /grant ('*{self.broker_sid}:(OI)(CI)(F)') /T /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'broker grant failed' }",
                    f"icacls.exe $Base /setowner ('*{self.broker_sid}') /T /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'broker owner failed' }",
                ]
            ),
            directory=self.work,
        )
        self.assertEqual(setup.returncode, 0, setup.stderr)
        return runner

    def _effective_rules(self, runner: Path) -> dict[str, object]:
        report = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Root = {_ps_quote(str(runner))}",
                    "$Items = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force)",
                    "$Report = @()",
                    "foreach ($Item in $Items) {",
                    "    $Security = $Item.GetAccessControl('Access')",
                    "    $Rules = @{}",
                    "    $Deny = 0",
                    "    foreach ($Rule in @($Security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {",
                    "        if ($Rule.AccessControlType -ne 'Allow') { $Deny++; continue }",
                    "        if (($Rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }",
                    "        $Sid = $Rule.IdentityReference.Value",
                    "        $Previous = 0; if ($Rules.ContainsKey($Sid)) { $Previous = $Rules[$Sid] }",
                    f"        $Rules[$Sid] = $Previous -bor [int]$Rule.FileSystemRights -bor {SYNCHRONIZE}",
                    "    }",
                    "    $Report += [ordered]@{ path = $Item.FullName; protected = $Security.AreAccessRulesProtected; deny = $Deny; rules = $Rules }",
                    "}",
                    "ConvertTo-Json -InputObject @($Report) -Depth 5 -Compress",
                ]
            ),
            directory=self.work,
        )
        self.assertEqual(report.returncode, 0, report.stderr)
        return json.loads(report.stdout)

    def test_acl_block_as_non_admin_broker_keeps_broker_access_and_exact_rules(self):
        runner = self._prepare_runner_tree()
        block = _candidate_block(PHASE4_ACL_BLOCK_BEGIN, PHASE4_ACL_BLOCK_END)
        script = "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$BridgeRunnerRoot = {_ps_quote(str(runner))}",
                f"$BridgeTargetSid = {_ps_quote(self.target_sid)}",
                f"$BridgeBrokerIdentity = {_ps_quote(os.environ.get('COMPUTERNAME', '.') + chr(92) + self.broker_name)}",
                block,
                "Write-Output 'ACL_BLOCK_COMPLETED'",
            ]
        )
        code, out, err = self._run_as(self.broker_name, self.broker_password, script, "acl-block")
        self.assertEqual(code, 0, out + err)
        self.assertIn("ACL_BLOCK_COMPLETED", out)

        # After Phase 4 the non-elevated broker must still enumerate and read the
        # runner tree and create the probe/runner redirect files (Phase 4 apply
        # read-back and Phase 5 depend on it).
        follow_up = "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$Root = {_ps_quote(str(runner))}",
                "$Count = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction Stop).Count",
                "$Text = Get-Content -LiteralPath (Join-Path $Root 'config.cmd') -Raw -ErrorAction Stop",
                "Set-Content -LiteralPath (Join-Path $Root 'issue225-phase4-target-probe-stdout.log') -Value 'x' -Encoding ASCII -ErrorAction Stop",
                "Write-Output ('BROKER_FOLLOW_UP_OK items=' + $Count)",
            ]
        )
        code, out, err = self._run_as(self.broker_name, self.broker_password, follow_up, "broker-follow-up")
        self.assertEqual(code, 0, "broker lost access to the runner tree after the ACL block: " + out + err)
        self.assertIn("BROKER_FOLLOW_UP_OK", out)

        expected = {
            "S-1-5-18": FULL_CONTROL | SYNCHRONIZE,
            "S-1-5-32-544": FULL_CONTROL | SYNCHRONIZE,
            self.broker_sid: MODIFY | SYNCHRONIZE,
            self.target_sid: MODIFY | SYNCHRONIZE,
        }
        report = self._effective_rules(runner)
        self.assertGreaterEqual(len(report), 7)
        self.assertTrue(report[0]["protected"], report[0])
        for item in report:
            if item["path"].endswith("issue225-phase4-target-probe-stdout.log"):
                continue
            with self.subTest(path=item["path"]):
                self.assertEqual(item["deny"], 0)
                self.assertEqual({key: int(value) for key, value in item["rules"].items()}, expected)

    def test_acl_block_fails_closed_when_the_tree_cannot_be_fully_prepared(self):
        # An item the broker cannot re-ACL (owned by and granted only to
        # SYSTEM/Administrators) must make the block fail instead of passing on
        # icacls exit code 0.
        runner = self._prepare_runner_tree()
        locked = runner / "externals" / "locked"
        lock = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Locked = {_ps_quote(str(locked))}",
                    "New-Item -ItemType Directory -Path $Locked | Out-Null",
                    "Set-Content -LiteralPath (Join-Path $Locked 'x.txt') -Value 'x' -Encoding ASCII",
                    "icacls.exe $Locked /setowner '*S-1-5-32-544' /T /C /Q | Out-Null",
                    "icacls.exe $Locked /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' /T /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'lock failed' }",
                ]
            ),
            directory=self.work,
        )
        self.assertEqual(lock.returncode, 0, lock.stderr)
        block = _candidate_block(PHASE4_ACL_BLOCK_BEGIN, PHASE4_ACL_BLOCK_END)
        script = "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                f"$BridgeRunnerRoot = {_ps_quote(str(runner))}",
                f"$BridgeTargetSid = {_ps_quote(self.target_sid)}",
                f"$BridgeBrokerIdentity = {_ps_quote(os.environ.get('COMPUTERNAME', '.') + chr(92) + self.broker_name)}",
                block,
                "Write-Output 'ACL_BLOCK_COMPLETED'",
            ]
        )
        code, out, err = self._run_as(self.broker_name, self.broker_password, script, "acl-block-locked")
        self.assertNotEqual(code, 0, "ACL block passed although a subtree could not be prepared: " + out)
        self.assertNotIn("ACL_BLOCK_COMPLETED", out)

    def _run_credential_block(self, password: str, label: str) -> subprocess.CompletedProcess[str]:
        block = _candidate_block(PHASE4_CREDENTIAL_BLOCK_BEGIN, PHASE4_CREDENTIAL_BLOCK_END)
        return _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$BridgeTargetCredential = {self._credential_expression(self.target_name, password)}",
                    block,
                    f"Write-Output 'CREDENTIAL_BLOCK_COMPLETED {label}'",
                ]
            ),
            directory=self.work,
        )

    def test_credential_block_rejects_a_wrong_password(self):
        completed = self._run_credential_block(_new_password(), "wrong")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertNotIn("CREDENTIAL_BLOCK_COMPLETED", completed.stdout)

    def test_credential_block_accepts_the_right_password(self):
        completed = self._run_credential_block(self.target_password, "right")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("CREDENTIAL_BLOCK_COMPLETED right", completed.stdout)

    def _run_credential_script(self, password: str) -> subprocess.CompletedProcess[str]:
        self.assertTrue(CREDENTIAL_CHECK_SCRIPT.is_file(), "operator credential check script is missing")
        expected = os.environ.get("COMPUTERNAME", ".") + "\\" + self.target_name
        return _run_powershell(
            "\n".join(
                [
                    f"$Credential = {self._credential_expression(self.target_name, password)}",
                    f"& {_ps_quote(str(CREDENTIAL_CHECK_SCRIPT))} -ExpectedIdentity {_ps_quote(expected)} -Credential $Credential",
                    "exit $LASTEXITCODE",
                ]
            ),
            directory=self.work,
        )

    def test_operator_credential_check_reports_valid_and_invalid(self):
        valid = self._run_credential_script(self.target_password)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        self.assertIn("TARGET_CREDENTIAL_VALID", valid.stdout)
        invalid = self._run_credential_script(_new_password())
        self.assertNotEqual(invalid.returncode, 0, invalid.stdout)
        self.assertIn("TARGET_CREDENTIAL_INVALID", invalid.stdout)
        self.assertNotIn("TARGET_CREDENTIAL_VALID", invalid.stdout)


if __name__ == "__main__":
    unittest.main()
