import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from agent_controller import cli
from agent_controller.provider_contract import VerificationResult


THREAD_ID = "123e4567-e89b-12d3-a456-426614174000"
SOURCE_HOME = "C:/Users/example/.codex"
CODEX_BIN = "C:/Tools/codex.exe"
START_SHA = "a" * 40


class CliCodexTargetTests(unittest.TestCase):
    def test_verify_codex_target_requires_source_home_before_client_construction(self):
        stderr = io.StringIO()
        with patch.object(
            sys,
            "argv",
            [
                "agent-controller",
                "verify-codex-target",
                "--thread-id",
                THREAD_ID,
            ],
        ), patch.object(cli, "CodexSnapshotReadClient") as client_cls, redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                cli.main()

        self.assertEqual(2, raised.exception.code)
        self.assertIn("verify-codex-target requires --source-codex-home", stderr.getvalue())
        client_cls.assert_not_called()

    def test_verify_codex_target_routes_explicit_controller_target_and_snapshot_observer(self):
        result = Mock()
        result.verification_result = VerificationResult.PASS
        result.to_dict.return_value = {
            "verification_result": "PASS",
            "target_evidence": {
                "repo": "oimus1976/example",
                "target_ref": "feature/task-1",
                "resolved_sha": "b" * 40,
            },
        }
        snapshot_client = object()
        observer = object()
        github = object()
        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "agent-controller",
                "verify-codex-target",
                "--thread-id",
                THREAD_ID,
                "--source-codex-home",
                SOURCE_HOME,
                "--codex-bin",
                CODEX_BIN,
                "--repo",
                "oimus1976/example",
                "--target-ref",
                "feature/task-1",
                "--expected-start-sha",
                START_SHA,
                "--allowed-paths",
                "src/*",
            ],
        ), patch.object(
            cli,
            "CodexSnapshotReadClient",
            return_value=snapshot_client,
        ) as client_cls, patch.object(
            cli,
            "CodexObservationAdapter",
            return_value=observer,
        ) as adapter_cls, patch.object(
            cli,
            "GitHubRestTargetReadClient",
            return_value=github,
        ), patch.object(
            cli,
            "run_objective_target_handoff",
            return_value=result,
        ) as handoff, redirect_stdout(stdout):
            cli.main()

        client_cls.assert_called_once_with(
            source_codex_home=SOURCE_HOME,
            codex_bin=CODEX_BIN,
        )
        adapter_cls.assert_called_once()
        call = handoff.call_args.kwargs
        self.assertIs(observer, call["observer"])
        self.assertIs(github, call["github"])
        self.assertEqual("oimus1976/example", call["task"].repo)
        self.assertEqual(START_SHA, call["task"].expected_start_sha)
        self.assertEqual(("src/*",), call["task"].objective_scope.allowed_paths)
        self.assertEqual("feature/task-1", call["target"].ref)
        self.assertEqual("oimus1976/example", call["target"].repo)
        self.assertEqual(THREAD_ID, call["operation"].provider_operation_id)
        self.assertEqual(
            {
                "verification_result": "PASS",
                "target_evidence": {
                    "repo": "oimus1976/example",
                    "target_ref": "feature/task-1",
                    "resolved_sha": "b" * 40,
                },
            },
            json.loads(stdout.getvalue()),
        )

    def test_verify_codex_target_nonpass_exits_nonzero(self):
        result = Mock()
        result.verification_result = VerificationResult.BLOCKED
        result.to_dict.return_value = {"verification_result": "BLOCKED"}

        with patch.object(
            sys,
            "argv",
            [
                "agent-controller",
                "verify-codex-target",
                "--thread-id",
                THREAD_ID,
                "--source-codex-home",
                SOURCE_HOME,
                "--repo",
                "oimus1976/example",
                "--target-ref",
                "feature/task-1",
                "--expected-start-sha",
                START_SHA,
                "--denied-paths",
                "secrets/*",
            ],
        ), patch.object(cli, "CodexSnapshotReadClient"), patch.object(
            cli, "CodexObservationAdapter"
        ), patch.object(cli, "GitHubRestTargetReadClient"), patch.object(
            cli,
            "run_objective_target_handoff",
            return_value=result,
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                cli.main()

        self.assertEqual(1, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
