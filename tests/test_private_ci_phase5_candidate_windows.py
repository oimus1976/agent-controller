import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import copy
import re
from pathlib import Path

from agent_controller.operator_step_gate import operator_step_spec_sha256
from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase5_contract import (
    build_phase5_exactly_one_job_spec,
    render_phase5_exactly_one_job_candidate,
)


@unittest.skipUnless(
    os.name == "nt",
    "Windows PowerShell 5.1 Phase 5 candidate regression",
)
class PrivateCiPhase5CandidateWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.producer = (
            cls.repo_root / "scripts" / "Invoke-PrivateCiAstAttestation.ps1"
        )

    def binding(self):
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

    def test_rendered_phase5_candidate_passes_real_ast_shape_requirements(self):
        binding = self.binding()
        phase4_sha = "b" * 64
        spec = build_phase5_exactly_one_job_spec(
            binding,
            phase4_result_sha256=phase4_sha,
        )
        candidate = render_phase5_exactly_one_job_candidate(
            binding,
            phase4_result_sha256=phase4_sha,
            target_probe_sha256="c" * 64,
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate_path = Path(temporary_directory) / "phase5-candidate.ps1"
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
                    operator_step_spec_sha256(spec),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["parsed"], report)
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(
            set(report["observed_effect_families"]),
            {
                "EVIDENCE_OUTPUT_WRITE",
                "HTTP_API_ACCESS",
                "PROCESS_CONTROL",
                "PROCESS_LAUNCH",
                "WORKFLOW_DISPATCH",
            },
        )
        self.assertNotIn(
            "DYNAMIC_OR_UNKNOWN_COMMAND",
            report["observed_effect_families"],
        )
        self.assertEqual(report["automatic_variable_collisions"], [])
        self.assertEqual(report["unresolved_placeholders"], [])
        self.assertEqual(report["forbidden_convenience_paths"], [])
        self.assertTrue(report["heartbeat_or_progress_proven"])
        self.assertTrue(report["child_exit_code_proven"])
        self.assertTrue(report["fail_fast_proven"])
        self.assertEqual(candidate.count("gh.exe api --method POST"), 1)

    def run_predispatch(self, reads, *, read_error=False, local_failure="", exit_after=None,
                        queue_failure=False, dispatch_failure=False, kill_failure=False):
        """Execute the rendered post-creation/pre-dispatch region with no live effects.

        Keep all guards/control flow; replace only external reads, dispatch,
        and clock/process surfaces. The fake clock makes the 30s bound instant.
        """
        candidate = render_phase5_exactly_one_job_candidate(
            self.binding(), phase4_result_sha256="b" * 64, target_probe_sha256="c" * 64)
        start = candidate.index("\n}))", candidate.index("$BridgeChild =")) + len("\n}))")
        end = candidate.index("\nwhile (-not $BridgeChild.HasExited)", start)
        region = candidate[start:end]
        region = re.sub(r"(?m)^(\s*)\$BridgeRunnerReadJson = .*", r"\1$BridgeRunnerReadJson = Read-Runner", region)
        region = re.sub(r"(?m)^(\s*\$Bridge\w+BeforeDispatchJson) = .*", r"\1 = Read-Queue", region)
        region = re.sub(r"(?m)^(\s*)\$BridgeDispatchJson = .*", r"\1$BridgeDispatchJson = Dispatch-Stub", region)
        config = json.dumps(dict(reads=reads, read_error=read_error, local_failure=local_failure,
                                 exit_after=exit_after, queue_failure=queue_failure,
                                 dispatch_failure=dispatch_failure, kill_failure=kill_failure))
        harness = r'''
$ErrorActionPreference = 'Stop'
$Config = '__CONFIG__' | ConvertFrom-Json
$script:Ticks = 0; $script:Reads = 0; $script:Dispatches = 0; $script:Kills = 0
$BridgeRunnerId = 23; $BridgeRunnerName = 'ac-ci-0123456789abcdef'
$BridgeRunnerLabel = 'private-ci-windows-pilot'; $BridgeRunnerRoot = 'fixture-root'
$BridgeQualifiedTargetIdentity = 'fixture-host\fixture-user'
$BridgeStartedAt = [datetime]'2026-01-01'; $BridgeRunnerOnlineTimeoutSeconds = 30
$BridgeChild = [pscustomobject]@{ HasExited = $false; ExitCode = 1 }
$BridgeChild | Add-Member ScriptMethod Kill {
    $script:Kills++; if ($Config.kill_failure) { throw 'kill failed' }; $this.HasExited = $true
}
function Get-Date { [datetime]'2026-01-01' + [timespan]::FromSeconds($script:Ticks) }
function Start-Sleep { param($Seconds)
    $script:Ticks += $Seconds
    if ($null -ne $Config.exit_after -and $script:Ticks -ge $Config.exit_after) { $BridgeChild.HasExited = $true }
}
function Get-CimInstance {
    if ($Config.local_failure -eq 'cim') { throw 'cim failed' }
    if ($Config.local_failure -eq 'absent') { return }
    $item = [pscustomobject]@{ Name = 'Runner.Listener.exe'; CommandLine = 'fixture-root'; ProcessId = 42 }
    $item; if ($Config.local_failure -eq 'multiple') { $item }
}
function Invoke-CimMethod {
    if ($Config.local_failure -eq 'owner') { throw 'owner failed' }
    $user = 'fixture-user'; if ($Config.local_failure -eq 'identity') { $user = 'wrong' }
    [pscustomobject]@{ ReturnValue = 0; Domain = 'fixture-host'; User = $user }
}
function Read-Runner {
    $index = [Math]::Min($script:Reads, $Config.reads.Count - 1); $script:Reads++
    $global:LASTEXITCODE = 0; if ($Config.read_error) { $global:LASTEXITCODE = 1 }
    if ($Config.reads[$index] -is [string]) { return $Config.reads[$index] }
    $Config.reads[$index] | ConvertTo-Json -Depth 10 -Compress
}
function Read-Queue {
    $global:LASTEXITCODE = 0
    if ($Config.queue_failure) { throw 'queue failed' }
    '{"total_count":0}'
}
function Dispatch-Stub {
    $script:Dispatches++; $global:LASTEXITCODE = 0
    if ($Config.dispatch_failure) { $global:LASTEXITCODE = 1 }
    '{"workflow_run_id":123}'
}
$Failure = ''
try {
__REGION__
} catch { $Failure = $_.Exception.Message }
@{ failure=$Failure; reads=$script:Reads; dispatches=$script:Dispatches;
   kills=$script:Kills; ticks=$script:Ticks } | ConvertTo-Json -Compress
'''.replace("__CONFIG__", config.replace("'", "''")).replace("__REGION__", region)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "regression.ps1"
            path.write_text(harness, encoding="utf-8-sig")
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
                                    capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def runner_read(self, status="online"):
        return {"total_count": 1, "runners": [{"id": 23, "name": "ac-ci-0123456789abcdef",
                 "labels": [{"name": "private-ci-windows-pilot"}], "status": status, "busy": False}]}

    def assert_stopped(self, result, *, kills=1):
        self.assertTrue(result["failure"], result)
        self.assertEqual(result["dispatches"], 0, result)
        self.assertEqual(result["kills"], kills, result)

    def test_offline_then_online_waits_before_one_dispatch(self):
        result = self.run_predispatch([self.runner_read("offline"), self.runner_read()])
        self.assertEqual(result["failure"], "", result)
        self.assertEqual(result["reads"], 2, result)
        self.assertEqual(result["dispatches"], 1, result)
        self.assertEqual(result["kills"], 0, result)

    def test_offline_timeout_kills_exact_child_without_dispatch(self):
        result = self.run_predispatch([self.runner_read("offline")])
        self.assert_stopped(result)
        self.assertIn("timeout", result["failure"])
        self.assertLessEqual(result["ticks"], 31)

    def test_online_idle_dispatches_without_readiness_sleep(self):
        result = self.run_predispatch([self.runner_read()])
        self.assertEqual(result["failure"], "", result)
        self.assertEqual(result["dispatches"], 1, result)
        self.assertEqual(result["reads"], 1, result)
        self.assertEqual(result["ticks"], 1, result)  # existing local startup sleep

    def test_listener_exit_while_waiting_prevents_dispatch(self):
        result = self.run_predispatch([self.runner_read("offline"), self.runner_read()], exit_after=2)
        self.assert_stopped(result, kills=0)
        self.assertIn("exited", result["failure"])

    def test_readback_shape_binding_and_busy_fail_closed(self):
        base = self.runner_read()
        invalid = ["", "{invalid-json", {}, {"total_count": 2, "runners": base["runners"]},
                   {"total_count": 0, "runners": []},
                   {"total_count": 2, "runners": base["runners"] * 2},
                   {"total_count": 0, "runners": base["runners"]}]
        for field, value in [("id", 24), ("name", "wrong"), ("labels", []), ("busy", True),
                             ("busy", "false"), ("id", "23"), ("labels", {"name": "private-ci-windows-pilot"}),
                             ("status", "unknown"), ("status", None)]:
            item = copy.deepcopy(base); item["runners"][0][field] = value; invalid.append(item)
        for field in ["busy", "status", "id", "name", "labels"]:
            item = copy.deepcopy(base); del item["runners"][0][field]; invalid.append(item)
        for item in invalid:
            with self.subTest(item=item):
                self.assert_stopped(self.run_predispatch([item]))
        self.assert_stopped(self.run_predispatch([base], read_error=True))

    def test_other_predispatch_failures_cleanup_and_preserve_error(self):
        for failure in ["cim", "absent", "multiple", "owner", "identity"]:
            with self.subTest(failure=failure):
                self.assert_stopped(self.run_predispatch([self.runner_read()], local_failure=failure))
        self.assert_stopped(self.run_predispatch([self.runner_read()], queue_failure=True))
        result = self.run_predispatch([self.runner_read()], read_error=True, kill_failure=True)
        self.assert_stopped(result)
        self.assertIn("readback failed", result["failure"])
        result = self.run_predispatch([self.runner_read()], dispatch_failure=True)
        self.assertEqual(result["dispatches"], 1, result)
        self.assertEqual(result["kills"], 1, result)
        self.assertIn("do not retry", result["failure"])


if __name__ == "__main__":
    unittest.main()
