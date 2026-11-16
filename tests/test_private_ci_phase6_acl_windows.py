"""Real Windows regressions for #327 (Phase 6 ACL lock and read-back).

On #216 the Phase 6 candidate ran, from an elevated console,
``icacls <generation> /inheritance:r /grant:r SY,BA:(OI)(CI)(F) /T /C`` and then
``icacls <generation> /remove:g <target> /T /C``. The first command left files
with an empty protected DACL; the second was denied on 181 target-owned files
and still exited 0, so the candidate went on.

These tests execute the exact ACL block rendered by
``render_phase6_cleanup_candidate`` under Windows PowerShell 5.1 as the
elevated administrator (the Phase 6 context), against a throwaway tree whose
files are owned by a throwaway target account. They need elevation to create
that account: they skip on developer machines without it and fail under CI.
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

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_SCHEMA,
    PHASE5_RESULT_STATUS,
    Phase5ResultEvidence,
    phase5_result_bytes,
)
from agent_controller.private_ci_phase6_contract import (
    PHASE6_ACL_BLOCK_BEGIN,
    PHASE6_ACL_BLOCK_END,
    build_phase6_cleanup_plan,
    render_phase6_cleanup_candidate,
)


FULL_CONTROL = 2032127
SYNCHRONIZE = 1048576


def _powershell_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}


def _run_powershell(script: str, *, directory: Path) -> subprocess.CompletedProcess[str]:
    path = directory / f"step-{secrets.token_hex(6)}.ps1"
    path.write_text(script, encoding="utf-8-sig")
    try:
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
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


def _rendered_acl_block() -> str:
    generation = "ac-pilot-0123456789abcdef"
    binding = PrivateCiPilotBinding(
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-230",
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
    evidence = Phase5ResultEvidence(
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
    candidate = render_phase6_cleanup_candidate(
        build_phase6_cleanup_plan(phase5_result_bytes(evidence))
    )
    lines = candidate.splitlines()
    begin = next(i for i, line in enumerate(lines) if line.startswith(PHASE6_ACL_BLOCK_BEGIN))
    end = next(i for i, line in enumerate(lines) if line.startswith(PHASE6_ACL_BLOCK_END))
    if end <= begin:
        raise AssertionError("rendered Phase 6 ACL block is malformed")
    return "\n".join(lines[begin : end + 1])


def _annotate(title: str, message: str) -> None:
    flat = " ".join(str(message).split())[:1500]
    print(f"::error title=issue327-{title}::{flat}", flush=True)


@unittest.skipUnless(os.name == "nt", "real Windows Phase 6 ACL regression")
class PrivateCiPhase6AclWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _is_elevated_admin():
            if os.environ.get("CI", "").lower() == "true":
                _annotate("setup", "Phase 6 ACL regressions must run elevated under CI")
                raise AssertionError("Phase 6 ACL regressions must run elevated under CI")
            raise unittest.SkipTest("requires an elevated administrator to create a test account")

        suffix = secrets.token_hex(3)
        cls.target_name = f"ac6tg{suffix}"
        cls.work = Path(tempfile.mkdtemp(prefix="ac-phase6-acl-"))
        cls.base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / f"ac-phase6-acl-{suffix}"
        password = "Aa1!" + secrets.token_hex(12)
        created = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Target = New-LocalUser -Name {_ps_quote(cls.target_name)} -Password (ConvertTo-SecureString {_ps_quote(password)} -AsPlainText -Force) -PasswordNeverExpires -AccountNeverExpires",
                    "Write-Output $Target.SID.Value",
                ]
            ),
            directory=cls.work,
        )
        if created.returncode != 0:
            cls._remove_account()
            _annotate("setup", "test account creation failed: " + created.stderr)
            raise AssertionError("test account creation failed: " + created.stderr)
        cls.target_sid = created.stdout.strip().splitlines()[-1]
        cls.block = _rendered_acl_block()

    @classmethod
    def tearDownClass(cls):
        cls._remove_tree()
        cls._remove_account()
        work = getattr(cls, "work", None)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)

    @classmethod
    def _remove_tree(cls):
        base = getattr(cls, "base", None)
        work = getattr(cls, "work", None)
        if base is None or work is None or not base.exists():
            return
        _run_powershell(
            "\n".join(
                [
                    f"takeown.exe /F {_ps_quote(str(base))} /A /R /D Y | Out-Null",
                    f"icacls.exe {_ps_quote(str(base))} /reset /T /C /Q | Out-Null",
                    f"Remove-Item -LiteralPath {_ps_quote(str(base))} -Recurse -Force -ErrorAction SilentlyContinue",
                ]
            ),
            directory=work,
        )

    @classmethod
    def _remove_account(cls):
        work = getattr(cls, "work", None)
        name = getattr(cls, "target_name", None)
        if work is None or not name:
            return
        _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Continue'",
                    f"$User = Get-LocalUser -Name {_ps_quote(name)} -ErrorAction SilentlyContinue",
                    "if ($null -ne $User) { Remove-LocalUser -SID $User.SID -ErrorAction SilentlyContinue }",
                ]
            ),
            directory=work,
        )

    def _qualified_target(self) -> str:
        return os.environ.get("COMPUTERNAME", ".") + "\\" + self.target_name

    def _prepare_generation(self) -> Path:
        """Build a generation tree shaped like #216 after Phase 5."""
        type(self)._remove_tree()
        generation = self.base / "ac-pilot-0123456789abcdef"
        runner = generation / "runner"
        target = f"*{self.target_sid}"
        setup = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Runner = {_ps_quote(str(runner))}",
                    "New-Item -ItemType Directory -Path (Join-Path $Runner 'bin') | Out-Null",
                    "New-Item -ItemType Directory -Path (Join-Path $Runner '_work\\repo\\.git\\objects') | Out-Null",
                    "Set-Content -LiteralPath (Join-Path $Runner 'config.cmd') -Value 'rem' -Encoding ASCII",
                    "Set-Content -LiteralPath (Join-Path $Runner 'bin\\Runner.Listener.exe') -Value 'x' -Encoding ASCII",
                    # Phase 4 shape: runner root protected with inheritable grants
                    # that include the target identity.
                    f"icacls.exe $Runner /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' '{target}:(OI)(CI)(M)' /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'runner root ACL failed' }",
                    # Files the runner job wrote as the target identity.
                    "foreach ($Name in @('issue225-phase5-runner-stdout.log', 'run-helper.cmd', '_work\\repo\\.git\\objects\\pack.idx')) {",
                    "    $Path = Join-Path $Runner $Name",
                    "    Set-Content -LiteralPath $Path -Value 'x' -Encoding ASCII",
                    f"    icacls.exe $Path /setowner '{target}' /C /Q | Out-Null",
                    "    if ($LASTEXITCODE -ne 0) { throw 'target owner failed' }",
                    "}",
                    f"icacls.exe (Join-Path $Runner '_work') /setowner '{target}' /T /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'target owner failed' }",
                    # An explicit target grant and a protected descendant.
                    f"icacls.exe (Join-Path $Runner 'run-helper.cmd') /grant '{target}:(F)' /C /Q | Out-Null",
                    f"icacls.exe (Join-Path $Runner 'bin') /inheritance:d /grant '{target}:(OI)(CI)(F)' /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'explicit target grant failed' }",
                ]
            ),
            directory=self.work,
        )
        self.assertEqual(setup.returncode, 0, setup.stderr)
        return generation

    def _run_block(self, generation: Path) -> subprocess.CompletedProcess[str]:
        return _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$BridgeGenerationRoot = {_ps_quote(str(generation))}",
                    f"$BridgeQualifiedTargetIdentity = {_ps_quote(self._qualified_target())}",
                    self.block,
                    "Write-Output 'ACL_BLOCK_COMPLETED'",
                ]
            ),
            directory=self.work,
        )

    def _rules(self, generation: Path) -> list[dict[str, object]]:
        report = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"$Root = {_ps_quote(str(generation))}",
                    "$Items = @(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force)",
                    "$Report = @()",
                    "foreach ($Item in $Items) {",
                    "    $Security = $Item.GetAccessControl('Access')",
                    "    $Rules = @{}",
                    "    $Deny = 0",
                    "    foreach ($Rule in @($Security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {",
                    "        if ($Rule.AccessControlType -ne 'Allow') { $Deny++; continue }",
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

    def test_acl_block_locks_target_owned_tree_and_proves_it(self):
        # The #216 shape: target-owned files that the old recursive grant
        # turned into empty DACLs and the old /remove could not touch.
        generation = self._prepare_generation()
        completed = self._run_block(generation)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("ACL_BLOCK_COMPLETED", completed.stdout)
        self.assertIn("progress phase=phase6 step=acl-verified stage=pre-stop items=", completed.stdout)

        report = self._rules(generation)
        self.assertGreaterEqual(len(report), 10)
        self.assertTrue(report[0]["protected"], report[0])
        expected = {"S-1-5-18": FULL_CONTROL | SYNCHRONIZE, "S-1-5-32-544": FULL_CONTROL | SYNCHRONIZE}
        for item in report:
            with self.subTest(path=item["path"]):
                self.assertEqual(item["deny"], 0)
                self.assertNotIn(self.target_sid, item["rules"])
                self.assertEqual({key: int(value) for key, value in item["rules"].items()}, expected)
                if item is not report[0]:
                    self.assertFalse(item["protected"], item)

    def test_acl_block_stops_when_an_item_cannot_be_relocked(self):
        # A target-owned file with an empty protected DACL (what the old
        # recursive grant produced on #216): the elevated broker can neither
        # reset nor read it, icacls still exits 0, and the block must stop.
        generation = self._prepare_generation()
        locked = generation / "runner" / "issue225-phase5-runner-stdout.log"
        lock = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"icacls.exe {_ps_quote(str(locked))} /inheritance:r /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'lock failed' }",
                    f"$Sddl = (Get-Acl -LiteralPath {_ps_quote(str(locked))} -ErrorAction SilentlyContinue).Sddl",
                    "Write-Output ('LOCKED_SDDL=' + $Sddl)",
                ]
            ),
            directory=self.work,
        )
        self.assertEqual(lock.returncode, 0, lock.stderr)

        completed = self._run_block(generation)
        self.assertNotEqual(
            completed.returncode,
            0,
            "ACL block passed although an item could not be relocked: " + completed.stdout,
        )
        self.assertNotIn("ACL_BLOCK_COMPLETED", completed.stdout)
        self.assertNotIn("step=acl-verified", completed.stdout)

    def _sddl_and_content(self, paths: list[Path]) -> dict[str, str]:
        read = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    "$Report = [ordered]@{}",
                    *[
                        f"$Report[{_ps_quote(str(path))}] = [string](Get-Acl -LiteralPath {_ps_quote(str(path))}).Sddl"
                        for path in paths
                    ],
                    "ConvertTo-Json -InputObject $Report -Compress",
                ]
            ),
            directory=self.work,
        )
        self.assertEqual(read.returncode, 0, read.stderr)
        return json.loads(read.stdout)

    def test_acl_block_blocks_junction_before_touching_outside_acl(self):
        # Review MAJOR-1: icacls /T follows a directory junction. A junction
        # inside the generation that points at an outside sibling must stop
        # the block before any elevated ACL change, and the outside sentinel
        # must keep its ACL and content.
        generation = self._prepare_generation()
        outside = self.base / "outside-sentinel"
        sentinel = outside / "sentinel.txt"
        junction = generation / "runner" / "_work" / "repo" / "escape"
        target = f"*{self.target_sid}"
        setup = _run_powershell(
            "\n".join(
                [
                    "$ErrorActionPreference = 'Stop'",
                    f"New-Item -ItemType Directory -Path {_ps_quote(str(outside))} | Out-Null",
                    f"Set-Content -LiteralPath {_ps_quote(str(sentinel))} -Value 'sentinel-327' -Encoding ASCII",
                    # A distinctive ACL the block would overwrite if it followed the link.
                    f"icacls.exe {_ps_quote(str(outside))} /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' '{target}:(OI)(CI)(RX)' /C /Q | Out-Null",
                    "if ($LASTEXITCODE -ne 0) { throw 'outside ACL failed' }",
                    f"New-Item -ItemType Junction -Path {_ps_quote(str(junction))} -Target {_ps_quote(str(outside))} | Out-Null",
                ]
            ),
            directory=self.work,
        )
        self.assertEqual(setup.returncode, 0, setup.stderr)
        watched = [outside, sentinel, generation, generation / "runner"]
        before = self._sddl_and_content(watched)
        self.assertIn(self.target_sid, before[str(sentinel)])

        completed = self._run_block(generation)
        output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, "ACL block passed with a junction: " + output)
        self.assertNotIn("ACL_BLOCK_COMPLETED", completed.stdout)
        self.assertNotIn("step=acl-verified", completed.stdout)
        self.assertIn("Phase 6 reparse point blocked before ACL change", " ".join(output.split()))

        after = self._sddl_and_content(watched)
        # Outside the generation nothing changed; inside, the scan stopped
        # before the first icacls, so the root ACLs are unchanged too.
        self.assertEqual(after, before)
        self.assertEqual(sentinel.read_text(encoding="ascii").strip(), "sentinel-327")
        self.assertTrue(junction.exists())


if __name__ == "__main__":
    unittest.main()
