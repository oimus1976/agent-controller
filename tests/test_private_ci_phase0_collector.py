import json
import subprocess
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from agent_controller.private_ci_phase0_collector import (
    collect_validated_phase0_evidence,
    phase0_state_matches,
)
from agent_controller.private_ci_pilot_identity import (
    PILOT_IDENTITY_FREEZE_SCHEMA,
    PRIVATE_CI_BROKER_IDENTITY,
    PRIVATE_CI_HOST,
    PRIVATE_CI_RUNNER_LABEL,
    PRIVATE_CI_TARGET_IDENTITY,
    PRIVATE_CI_WORK_FOLDER,
    PrivateCiPilotIdentityFreeze,
    canonical_runner_root,
)


CONTROLLER_SHA = "1" * 40
CONTROLLER_TREE = r"C:\Users\c-admin\agent-controller-pilot-225"
TARGET_SHA = "2" * 40
WORKFLOW_SHA = "3" * 40
WORKFLOW_PATH = ".github/workflows/private-ci-windows-pilot.yml"
RUNNER_NAME = "ac-ci-0123456789abcdef"
GENERATION = "ac-pilot-0123456789abcdef"
REPOSITORY = "oimus1976/example-private"
PR_NUMBER = 4


def valid_freeze():
    return PrivateCiPilotIdentityFreeze(
        schema=PILOT_IDENTITY_FREEZE_SCHEMA,
        repository=REPOSITORY,
        pull_request_number=PR_NUMBER,
        target_sha=TARGET_SHA,
        workflow_sha=WORKFLOW_SHA,
        workflow_path=WORKFLOW_PATH,
        runner_name=RUNNER_NAME,
        runner_label=PRIVATE_CI_RUNNER_LABEL,
        environment_generation=GENERATION,
        runner_root=canonical_runner_root(GENERATION),
        work_folder=PRIVATE_CI_WORK_FOLDER,
        controller_main_sha=CONTROLLER_SHA,
        controller_tree=CONTROLLER_TREE,
        host=PRIVATE_CI_HOST,
        broker_identity=PRIVATE_CI_BROKER_IDENTITY,
        target_identity=PRIVATE_CI_TARGET_IDENTITY,
    )


class FakeRunner:
    def __init__(
        self,
        *,
        target_admin=False,
        runner_process_count=0,
        workflow_path_valid=True,
    ):
        self.target_admin = target_admin
        self.runner_process_count = runner_process_count
        self.workflow_path_valid = workflow_path_valid

    def __call__(self, *command, cwd=None):
        freeze = valid_freeze()
        if command[0] == "powershell.exe":
            payload = {
                "host": freeze.host,
                "broker_identity": freeze.broker_identity,
                "target_identity_enabled": True,
                "target_identity_admin": self.target_admin,
                "runner_process_count": self.runner_process_count,
                "runner_service_count": 0,
                "runner_task_count": 0,
                "powershell_version": "5.1.26100.9444",
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:4] == ("git.exe", "-C", freeze.controller_tree, "rev-parse"):
            return subprocess.CompletedProcess(command, 0, freeze.controller_main_sha + "\n", "")
        if command[:4] == ("git.exe", "-C", freeze.controller_tree, "status"):
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ("git.exe", "ls-remote"):
            return subprocess.CompletedProcess(
                command,
                0,
                freeze.controller_main_sha + "\trefs/heads/main\n",
                "",
            )
        if command[0] == r"C:\Program Files\Python312\python.exe":
            return subprocess.CompletedProcess(command, 0, "Python 3.12.10\n", "")
        if command[:3] == ("gh.exe", "api", f"repos/{freeze.repository}"):
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({"visibility": "private", "default_branch": "main"}),
                "",
            )
        if command[:3] == (
            "gh.exe",
            "api",
            f"repos/{freeze.repository}/pulls/{freeze.pull_request_number}",
        ):
            payload = {
                "state": "open",
                "draft": True,
                "head": {
                    "sha": freeze.target_sha,
                    "repo": {"full_name": freeze.repository},
                },
                "base": {"ref": "main"},
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == ("gh.exe", "api", f"repos/{freeze.repository}/branches/main"):
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({"commit": {"sha": freeze.workflow_sha}}),
                "",
            )
        if command[:3] == (
            "gh.exe",
            "api",
            (
                f"repos/{freeze.repository}/contents/{freeze.workflow_path}"
                f"?ref={freeze.workflow_sha}"
            ),
        ):
            payload = (
                {"type": "file", "path": freeze.workflow_path}
                if self.workflow_path_valid
                else {"type": "dir", "path": freeze.workflow_path}
            )
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == (
            "gh.exe",
            "api",
            f"repos/{freeze.repository}/actions/runners?per_page=100",
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({"total_count": 0, "runners": []}),
                "",
            )
        raise AssertionError(f"unexpected command: {command!r}")


class Phase0CollectorTests(unittest.TestCase):
    def test_collects_canonical_fresh_phase0_state(self):
        freeze = valid_freeze()
        evidence = collect_validated_phase0_evidence(
            Path(freeze.controller_tree),
            pilot_freeze=freeze,
            command_runner=FakeRunner(),
            path_exists=lambda path: False,
            now=lambda: datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(evidence.status, "PHASE0_PASS")
        self.assertEqual(evidence.controller_main_sha, freeze.controller_main_sha)
        self.assertEqual(evidence.controller_tree_head_sha, freeze.controller_main_sha)
        self.assertEqual(evidence.repository, freeze.repository)
        self.assertEqual(evidence.pull_request_head_sha, freeze.target_sha)
        self.assertEqual(evidence.workflow_sha, freeze.workflow_sha)
        self.assertEqual(evidence.workflow_path, freeze.workflow_path)
        self.assertEqual(evidence.runner_name, freeze.runner_name)
        self.assertEqual(evidence.runner_label, freeze.runner_label)
        self.assertEqual(evidence.environment_generation, freeze.environment_generation)
        self.assertEqual(evidence.runner_root, freeze.runner_root)
        self.assertEqual(evidence.work_folder, freeze.work_folder)
        self.assertFalse(evidence.runner_root_exists)
        self.assertEqual(evidence.matching_pilot_runner_count, 0)
        self.assertEqual(evidence.runner_process_count, 0)
        self.assertFalse(evidence.target_identity_admin)

    def test_target_admin_drift_is_rejected_by_fresh_collection(self):
        freeze = valid_freeze()
        with self.assertRaisesRegex(ValueError, "TARGET_IDENTITY_ADMIN_MISMATCH"):
            collect_validated_phase0_evidence(
                Path(freeze.controller_tree),
                pilot_freeze=freeze,
                command_runner=FakeRunner(target_admin=True),
                path_exists=lambda path: False,
            )

    def test_runner_process_drift_is_rejected_by_fresh_collection(self):
        freeze = valid_freeze()
        with self.assertRaisesRegex(ValueError, "RUNNER_PROCESS_COUNT_MISMATCH"):
            collect_validated_phase0_evidence(
                Path(freeze.controller_tree),
                pilot_freeze=freeze,
                command_runner=FakeRunner(runner_process_count=1),
                path_exists=lambda path: False,
            )

    def test_workflow_path_readback_must_be_exact_file(self):
        freeze = valid_freeze()
        with self.assertRaisesRegex(ValueError, "workflow path readback"):
            collect_validated_phase0_evidence(
                Path(freeze.controller_tree),
                pilot_freeze=freeze,
                command_runner=FakeRunner(workflow_path_valid=False),
                path_exists=lambda path: False,
            )

    def test_controller_tree_must_match_freeze(self):
        freeze = valid_freeze()
        with self.assertRaisesRegex(ValueError, "controller tree differs"):
            collect_validated_phase0_evidence(
                Path(r"C:\other"),
                pilot_freeze=freeze,
                command_runner=FakeRunner(),
                path_exists=lambda path: False,
            )

    def test_state_match_ignores_only_collection_timestamp(self):
        freeze = valid_freeze()
        first = collect_validated_phase0_evidence(
            Path(freeze.controller_tree),
            pilot_freeze=freeze,
            command_runner=FakeRunner(),
            path_exists=lambda path: False,
            now=lambda: datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc),
        )
        later = replace(first, collected_at="2026-09-19T12:05:00+00:00")
        self.assertTrue(phase0_state_matches(first, later))
        self.assertFalse(
            phase0_state_matches(
                first,
                replace(later, target_identity_admin=True),
            )
        )


if __name__ == "__main__":
    unittest.main()
