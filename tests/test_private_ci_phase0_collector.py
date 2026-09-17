import json
import subprocess
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from agent_controller.private_ci_live_registration import (
    FROZEN_ENVIRONMENT_GENERATION,
    FROZEN_PR_NUMBER,
    FROZEN_REPOSITORY,
    FROZEN_RUNNER_LABEL,
    FROZEN_RUNNER_NAME,
    FROZEN_RUNNER_ROOT,
    FROZEN_TARGET_SHA,
    FROZEN_WORKFLOW_SHA,
)
from agent_controller.private_ci_phase0_collector import (
    collect_validated_phase0_evidence,
    phase0_state_matches,
)
from agent_controller.private_ci_phase0_evidence import EXPECTED_CONTROLLER_TREE


CONTROLLER_SHA = "1" * 40


class FakeRunner:
    def __init__(self, *, target_admin=False, runner_process_count=0):
        self.target_admin = target_admin
        self.runner_process_count = runner_process_count

    def __call__(self, *command, cwd=None):
        if command[0] == "powershell.exe":
            payload = {
                "host": "WOBBUFFET",
                "broker_identity": "WOBBUFFET\\c-admin",
                "target_identity_enabled": True,
                "target_identity_admin": self.target_admin,
                "runner_process_count": self.runner_process_count,
                "runner_service_count": 0,
                "runner_task_count": 0,
                "powershell_version": "5.1.26100.9444",
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:4] == ("git.exe", "-C", EXPECTED_CONTROLLER_TREE, "rev-parse"):
            return subprocess.CompletedProcess(command, 0, CONTROLLER_SHA + "\n", "")
        if command[:4] == ("git.exe", "-C", EXPECTED_CONTROLLER_TREE, "status"):
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ("git.exe", "ls-remote"):
            return subprocess.CompletedProcess(command, 0, CONTROLLER_SHA + "\trefs/heads/main\n", "")
        if command[0] == r"C:\Program Files\Python312\python.exe":
            return subprocess.CompletedProcess(command, 0, "Python 3.12.10\n", "")
        if command[:3] == ("gh.exe", "api", f"repos/{FROZEN_REPOSITORY}"):
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"visibility": "private", "default_branch": "main"}), ""
            )
        if command[:3] == ("gh.exe", "api", f"repos/{FROZEN_REPOSITORY}/pulls/{FROZEN_PR_NUMBER}"):
            payload = {
                "state": "open",
                "draft": True,
                "head": {"sha": FROZEN_TARGET_SHA, "repo": {"full_name": FROZEN_REPOSITORY}},
                "base": {"ref": "main"},
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if command[:3] == ("gh.exe", "api", f"repos/{FROZEN_REPOSITORY}/branches/main"):
            return subprocess.CompletedProcess(
                command, 0, json.dumps({"commit": {"sha": FROZEN_WORKFLOW_SHA}}), ""
            )
        if command[:3] == (
            "gh.exe",
            "api",
            f"repos/{FROZEN_REPOSITORY}/actions/runners?per_page=100",
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
        evidence = collect_validated_phase0_evidence(
            Path(EXPECTED_CONTROLLER_TREE),
            command_runner=FakeRunner(),
            path_exists=lambda path: False,
            now=lambda: datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(evidence.status, "PHASE0_PASS")
        self.assertEqual(evidence.controller_main_sha, CONTROLLER_SHA)
        self.assertEqual(evidence.controller_tree_head_sha, CONTROLLER_SHA)
        self.assertEqual(evidence.repository, FROZEN_REPOSITORY)
        self.assertEqual(evidence.pull_request_head_sha, FROZEN_TARGET_SHA)
        self.assertEqual(evidence.workflow_sha, FROZEN_WORKFLOW_SHA)
        self.assertEqual(evidence.runner_name, FROZEN_RUNNER_NAME)
        self.assertEqual(evidence.runner_label, FROZEN_RUNNER_LABEL)
        self.assertEqual(evidence.environment_generation, FROZEN_ENVIRONMENT_GENERATION)
        self.assertEqual(evidence.runner_root, FROZEN_RUNNER_ROOT)
        self.assertFalse(evidence.runner_root_exists)
        self.assertEqual(evidence.matching_pilot_runner_count, 0)
        self.assertEqual(evidence.runner_process_count, 0)
        self.assertFalse(evidence.target_identity_admin)

    def test_target_admin_drift_is_rejected_by_fresh_collection(self):
        with self.assertRaisesRegex(ValueError, "TARGET_IDENTITY_ADMIN_MISMATCH"):
            collect_validated_phase0_evidence(
                Path(EXPECTED_CONTROLLER_TREE),
                command_runner=FakeRunner(target_admin=True),
                path_exists=lambda path: False,
            )

    def test_runner_process_drift_is_rejected_by_fresh_collection(self):
        with self.assertRaisesRegex(ValueError, "RUNNER_PROCESS_COUNT_MISMATCH"):
            collect_validated_phase0_evidence(
                Path(EXPECTED_CONTROLLER_TREE),
                command_runner=FakeRunner(runner_process_count=1),
                path_exists=lambda path: False,
            )

    def test_state_match_ignores_only_collection_timestamp(self):
        first = collect_validated_phase0_evidence(
            Path(EXPECTED_CONTROLLER_TREE),
            command_runner=FakeRunner(),
            path_exists=lambda path: False,
            now=lambda: datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc),
        )
        later = replace(first, collected_at="2026-09-17T12:05:00+00:00")
        self.assertTrue(phase0_state_matches(first, later))
        self.assertFalse(phase0_state_matches(first, replace(later, target_identity_admin=True)))


if __name__ == "__main__":
    unittest.main()
