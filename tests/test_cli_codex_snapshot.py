import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from agent_controller import cli


THREAD_ID = "123e4567-e89b-12d3-a456-426614174000"
SOURCE_HOME = "C:/Users/example/.codex"
CODEX_BIN = "C:/Tools/codex.exe"


class CliCodexSnapshotTests(unittest.TestCase):
    def test_observe_codex_requires_source_home_before_client_construction(self):
        stderr = io.StringIO()
        with patch.object(
            sys,
            "argv",
            ["agent-controller", "observe-codex", "--thread-id", THREAD_ID],
        ), patch.object(cli, "CodexSnapshotReadClient") as client_cls, redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                cli.main()

        self.assertEqual(2, raised.exception.code)
        self.assertIn("observe-codex requires --source-codex-home", stderr.getvalue())
        client_cls.assert_not_called()

    def test_observe_codex_routes_explicit_source_home_through_snapshot_client(self):
        observation = Mock()
        observation.to_dict.return_value = {
            "provider": "codex",
            "provider_operation_id": THREAD_ID,
            "mapped_state": "UNCERTAIN",
        }
        client = object()
        stdout = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "agent-controller",
                "observe-codex",
                "--thread-id",
                THREAD_ID,
                "--source-codex-home",
                SOURCE_HOME,
                "--codex-bin",
                CODEX_BIN,
            ],
        ), patch.object(cli, "CodexSnapshotReadClient", return_value=client) as client_cls, patch.object(
            cli, "CodexObservationAdapter"
        ) as adapter_cls, redirect_stdout(stdout):
            adapter_cls.return_value.observe.return_value = observation
            cli.main()

        client_cls.assert_called_once_with(
            source_codex_home=SOURCE_HOME,
            codex_bin=CODEX_BIN,
        )
        operation = adapter_cls.return_value.observe.call_args.args[0]
        self.assertEqual("codex", operation.provider)
        self.assertEqual(THREAD_ID, operation.provider_operation_id)
        self.assertEqual(
            {
                "provider": "codex",
                "provider_operation_id": THREAD_ID,
                "mapped_state": "UNCERTAIN",
            },
            json.loads(stdout.getvalue()),
        )


if __name__ == "__main__":
    unittest.main()
