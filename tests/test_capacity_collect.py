import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from agent_controller.capacity_collect import _app_server_argv, main


FIXTURES = Path(__file__).parent / "fixtures"
CLAUDE_FIXTURE = FIXTURES / "claude_code_statusline_rate_limits_synthetic.json"
ANTIGRAVITY_FIXTURE = FIXTURES / "antigravity_statusline_quota.json"
CODEX_STUB = FIXTURES / "codex_app_server_stub.py"
CODEX_HANG_STUB = FIXTURES / "codex_app_server_hang_stub.py"


def run_main(argv):
    stderr = io.StringIO()
    stdout = io.StringIO()
    with redirect_stderr(stderr), redirect_stdout(stdout):
        exit_code = main(argv)
    return exit_code, stdout.getvalue(), stderr.getvalue()


class CapacityCollectTests(unittest.TestCase):
    def test_file_sources_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ai-usage.json"
            exit_code, _, stderr = run_main(
                [
                    "--claude-code-statusline",
                    str(CLAUDE_FIXTURE),
                    "--antigravity-statusline",
                    str(ANTIGRAVITY_FIXTURE),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("claude-code: ok (2 pools)", stderr)
            self.assertIn("codex: skipped (not requested)", stderr)
            self.assertIn("antigravity: ok (2 pools)", stderr)

            document = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(document["document_kind"], "ai-usage-observations")
            self.assertEqual(len(document["observations"]), 4)
            self.assertEqual(
                {record["provider"] for record in document["observations"]},
                {"claude-code", "antigravity"},
            )
            for record in document["observations"]:
                self.assertEqual(record["source"]["data_status"], "confirmed")

    def test_codex_app_server_via_stub(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ai-usage.json"
            exit_code, _, stderr = run_main(
                [
                    "--codex-app-server",
                    "--codex-command",
                    str(CODEX_STUB),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("codex: ok (2 pools)", stderr)

            document = json.loads(out.read_text(encoding="utf-8"))
            pools = {
                record["capacity_pool"] for record in document["observations"]
            }
            self.assertEqual(pools, {"codex-five-hour", "codex-weekly"})
            by_pool = {
                record["capacity_pool"]: record
                for record in document["observations"]
            }
            self.assertEqual(by_pool["codex-five-hour"]["remaining_fraction"], 0.75)
            self.assertEqual(by_pool["codex-weekly"]["remaining_fraction"], 0.4)

    def test_failed_source_does_not_stop_others(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ai-usage.json"
            missing = Path(tmp) / "does-not-exist.json"
            exit_code, _, stderr = run_main(
                [
                    "--claude-code-statusline",
                    str(CLAUDE_FIXTURE),
                    "--antigravity-statusline",
                    str(missing),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("antigravity: failed:", stderr)
            document = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(document["observations"]), 2)
            self.assertEqual(
                {record["provider"] for record in document["observations"]},
                {"claude-code"},
            )

    def test_all_sources_failed_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ai-usage.json"
            missing = Path(tmp) / "does-not-exist.json"
            exit_code, _, stderr = run_main(
                ["--antigravity-statusline", str(missing), "--out", str(out)]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("antigravity: failed:", stderr)
            self.assertFalse(out.exists())

    def test_no_source_requested_fails(self):
        exit_code, stdout, stderr = run_main([])
        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("no source requested", stderr)

    def test_codex_timeout_is_a_source_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ai-usage.json"
            exit_code, _, stderr = run_main(
                [
                    "--codex-app-server",
                    "--codex-command",
                    str(CODEX_HANG_STUB),
                    "--codex-timeout",
                    "1",
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("codex: failed:", stderr)
            self.assertIn("timed out", stderr)
            self.assertFalse(out.exists())

    def test_stdout_output_when_no_out_file(self):
        exit_code, stdout, _ = run_main(
            ["--claude-code-statusline", str(CLAUDE_FIXTURE)]
        )
        self.assertEqual(exit_code, 0)
        document = json.loads(stdout)
        self.assertEqual(len(document["observations"]), 2)

    def test_saved_statusline_preserves_file_capture_time_across_rereads(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = Path(tmp) / "claude-statusline.json"
            saved.write_text(CLAUDE_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
            os.utime(saved, (1794994200, 1794994200))

            first_exit, first_stdout, _ = run_main(
                ["--claude-code-statusline", str(saved)]
            )
            second_exit, second_stdout, _ = run_main(
                ["--claude-code-statusline", str(saved)]
            )

            self.assertEqual(first_exit, 0)
            self.assertEqual(second_exit, 0)
            for stdout in (first_stdout, second_stdout):
                document = json.loads(stdout)
                self.assertEqual(len(document["observations"]), 2)
                for record in document["observations"]:
                    self.assertEqual(record["observed_at"], "2026-11-18T09:30:00.000Z")
                    self.assertEqual(
                        record["source"]["last_verified_at"],
                        "2026-11-18T09:30:00.000Z",
                    )

    def test_empty_pool_source_fails_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty_claude = Path(tmp) / "claude-empty.json"
            empty_claude.write_text(
                json.dumps({"version": "2.1.999-fixture", "rate_limits": {}}),
                encoding="utf-8",
            )
            out = Path(tmp) / "ai-usage.json"
            sentinel = '{"existing": "keep"}\n'
            out.write_text(sentinel, encoding="utf-8")

            exit_code, _, stderr = run_main(
                ["--claude-code-statusline", str(empty_claude), "--out", str(out)]
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("claude-code: failed: no capacity pools observed", stderr)
            self.assertEqual(out.read_text(encoding="utf-8"), sentinel)

            exit_code, _, stderr = run_main(
                [
                    "--claude-code-statusline",
                    str(empty_claude),
                    "--antigravity-statusline",
                    str(ANTIGRAVITY_FIXTURE),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("claude-code: failed: no capacity pools observed", stderr)
            document = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(document["observations"]), 2)
            self.assertEqual(
                {record["provider"] for record in document["observations"]},
                {"antigravity"},
            )

    def test_windows_app_server_argv_resolves_extensionless_command_via_which(self):
        with mock.patch("agent_controller.capacity_collect.sys.platform", "win32"):
            with mock.patch(
                "agent_controller.capacity_collect.shutil.which",
                return_value=r"C:\Users\owner\AppData\Roaming\npm\codex.CMD",
            ) as mock_which:
                self.assertEqual(
                    _app_server_argv("codex"),
                    [
                        "cmd",
                        "/c",
                        r"C:\Users\owner\AppData\Roaming\npm\codex.CMD",
                        "app-server",
                    ],
                )
                mock_which.assert_called_once_with("codex")

            with mock.patch(
                "agent_controller.capacity_collect.shutil.which",
                return_value=r"C:\Program Files\OpenAI\Codex\codex.exe",
            ):
                self.assertEqual(
                    _app_server_argv("codex"),
                    [r"C:\Program Files\OpenAI\Codex\codex.exe", "app-server"],
                )

            with mock.patch(
                "agent_controller.capacity_collect.shutil.which",
                return_value=None,
            ):
                self.assertEqual(
                    _app_server_argv(r"C:\custom\codex.cmd"),
                    ["cmd", "/c", r"C:\custom\codex.cmd", "app-server"],
                )


if __name__ == "__main__":
    unittest.main()
