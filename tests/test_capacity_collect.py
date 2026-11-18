import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from agent_controller.capacity_collect import main


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


if __name__ == "__main__":
    unittest.main()
