import hashlib
import json
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import issue_dispatch_poc as poc

ARMED = datetime(2026, 11, 26, 0, 0, tzinfo=timezone.utc)
NOW = ARMED + timedelta(minutes=10)
AUTHOR = 4242
STATUSLINE = json.dumps({"version": "2.1.330", "rate_limits": {
    "five_hour": {"used_percentage": 10, "resets_at": 1795000000},
    "seven_day": {"used_percentage": 30, "resets_at": 1795500000},
}})


def issue(number=7, **overrides):
    base = {
        "number": number, "state": "open", "locked": False, "comments": 0,
        "user": {"id": AUTHOR, "type": "User", "login": "owner"},
        "labels": [{"name": "dispatch-poc"}],
        "created_at": (ARMED + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "body": "task: summarize-fixture-v1",
    }
    base.update(overrides)
    return base


class FakeRunner:
    def __init__(self, issues, *, auth=None, claude=None):
        self.issues = issues
        self.auth = auth or {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty"}
        self.claude = claude or (lambda argv, kw: subprocess.CompletedProcess(argv, 0, "- 要約\n", ""))
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        if argv[:2] == ["gh", "api"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.issues), "")
        if argv[:3] == ["gh", "issue", "comment"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1:3] == ["auth", "status"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.auth), "")
        if argv[1] == "-p":
            return self.claude(argv, kw)
        raise AssertionError(f"unexpected command {argv}")

    def launches(self):
        return [argv for argv, _ in self.calls if len(argv) > 1 and argv[1] == "-p"]

    def comments(self):
        return [kw["input"] for argv, kw in self.calls if argv[:3] == ["gh", "issue", "comment"]]


class DispatchPocTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        fixture_dir = root / "fixture"
        fixture_dir.mkdir()
        (fixture_dir / poc.FIXTURE_NAME).write_text("固定テスト文書\n", encoding="utf-8")
        exe = root / "claude.exe"
        exe.write_bytes(b"")
        statusline = root / "statusline.json"
        statusline.write_text(STATUSLINE, encoding="utf-8")
        mtime = NOW.timestamp() - 60
        os.utime(statusline, (mtime, mtime))
        self.raw = {
            "repo": "owner/dispatch-inbox", "label": "dispatch-poc", "allowed_author_id": AUTHOR,
            "task_type": "summarize-fixture-v1",
            "armed_at": ARMED.isoformat(), "expires_at": (ARMED + timedelta(hours=2)).isoformat(),
            "state_dir": str(root / "state"), "claude_exe": str(exe),
            "fixture_dir": str(fixture_dir),
            "fixture_sha256": hashlib.sha256((fixture_dir / poc.FIXTURE_NAME).read_bytes()).hexdigest(),
            "statusline_path": str(statusline), "allowed_auth_methods": ["claude.ai"],
        }
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def config(self, **overrides):
        path = self.root / "config.json"
        path.write_text(json.dumps({**self.raw, **overrides}), encoding="utf-8")
        return poc.load_config(path)

    def run_live(self, runner, config=None, now=NOW):
        return poc.run_once(config or self.config(), live=True, run=runner, clock=lambda: now)

    def test_rejects_non_target_issues_without_launch(self):
        cases = [
            issue(user={"id": 999, "type": "User"}),
            issue(user={"id": AUTHOR, "type": "Bot"}),
            issue(labels=[{"name": "other"}]),
            issue(created_at=(ARMED - timedelta(minutes=1)).isoformat()),
            issue(body="task: summarize-fixture-v1\nrm -rf /"),
            issue(body="task: other-task"),
            issue(comments=1),
            issue(pull_request={}),
            issue(created_at="not-a-date"),
        ]
        for case in cases:
            with self.subTest(case=case):
                runner = FakeRunner([case])
                self.assertEqual(self.run_live(runner)["outcome"], "no_candidate")
                self.assertEqual(runner.launches(), [])
                self.assertFalse((self.root / "state" / "consumed.json").exists())

    def test_multiple_candidates_are_ambiguous_and_do_not_launch(self):
        runner = FakeRunner([issue(7), issue(8)])
        self.assertEqual(self.run_live(runner)["outcome"], "ambiguous")
        self.assertEqual(runner.launches(), [])

    def test_outside_window_does_not_poll(self):
        runner = FakeRunner([issue()])
        report = self.run_live(runner, now=ARMED + timedelta(hours=3))
        self.assertEqual(report["outcome"], "outside_window")
        self.assertEqual(runner.calls, [])

    def test_blocks_without_consuming_on_failed_preflight(self):
        cases = {
            "auth_not_logged_in": dict(auth={"loggedIn": False, "authMethod": "none", "apiProvider": "firstParty"}),
            "auth_method_not_allowed": dict(auth={"loggedIn": True, "authMethod": "api_key", "apiProvider": "firstParty"}),
        }
        for reason, kwargs in cases.items():
            with self.subTest(reason=reason):
                runner = FakeRunner([issue()], **kwargs)
                self.assertEqual(self.run_live(runner), {"outcome": "blocked", "reason": reason, "issue": 7})
                self.assertEqual(runner.launches(), [])
        Path(self.raw["statusline_path"]).unlink()
        runner = FakeRunner([issue()])
        self.assertEqual(self.run_live(runner)["reason"], "capacity_unknown")
        self.assertFalse((self.root / "state" / "consumed.json").exists())

    def test_low_capacity_and_changed_fixture_block(self):
        statusline = Path(self.raw["statusline_path"])
        long_window = self.config(expires_at=(ARMED + timedelta(hours=12)).isoformat())
        report = self.run_live(FakeRunner([issue()]), long_window, now=NOW + timedelta(hours=7))
        self.assertEqual(report["reason"], "capacity_stale")
        statusline.write_text(STATUSLINE.replace('"used_percentage": 30', '"used_percentage": 95'), encoding="utf-8")
        os.utime(statusline, (NOW.timestamp(), NOW.timestamp()))
        self.assertEqual(self.run_live(FakeRunner([issue()]))["reason"], "capacity_low")
        self.assertEqual(self.run_live(FakeRunner([issue()]), self.config(fixture_sha256="0" * 64))["reason"], "fixture_mismatch")

    def test_dry_run_never_launches_or_comments(self):
        runner = FakeRunner([issue()])
        report = poc.run_once(self.config(), live=False, run=runner, clock=lambda: NOW)
        self.assertEqual(report["outcome"], "would_launch")
        self.assertEqual(runner.launches(), [])
        self.assertEqual(runner.comments(), [])

    def test_live_launches_once_and_never_again(self):
        runner = FakeRunner([issue()])
        report = self.run_live(runner)
        self.assertEqual(report["outcome"], "launched")
        self.assertTrue(report["success"])
        self.assertEqual(report["detection_latency_seconds"], 300.0)
        self.assertEqual(len(runner.launches()), 1)
        argv, kw = next((a, k) for a, k in runner.calls if a[1:2] == ["-p"])
        self.assertNotIn("task: summarize-fixture-v1", " ".join(argv))
        self.assertEqual(argv[argv.index("--tools") + 1], "Read")
        self.assertFalse({"GITHUB_TOKEN", "GH_TOKEN", "ANTHROPIC_API_KEY"} & set(kw["env"]))
        self.assertEqual(len(runner.comments()), 1)
        self.assertIn("- 要約", runner.comments()[0])
        again = FakeRunner([issue()])
        self.assertEqual(self.run_live(again, now=NOW + timedelta(minutes=1))["outcome"], "already_consumed")
        self.assertEqual(again.calls, [])

    def test_failure_and_timeout_consume_and_post_failure(self):
        def timeout(argv, kw):
            raise subprocess.TimeoutExpired(argv, kw["timeout"])
        for claude, code in ((timeout, "timeout"),
                             (lambda a, k: subprocess.CompletedProcess(a, 3, "", "secret"), 3)):
            with self.subTest(code=code):
                state = self.root / f"state-{code}"
                runner = FakeRunner([issue()], claude=claude)
                report = self.run_live(runner, self.config(state_dir=str(state)))
                self.assertEqual((report["exit_code"], report["success"]), (code, False))
                self.assertIn("失敗", runner.comments()[0])
                self.assertNotIn("secret", runner.comments()[0])
                self.assertTrue((state / "consumed.json").exists())

    def test_sanitize_redacts_secrets_and_paths(self):
        text = poc.sanitize("ghp_abcdefghijklmnop sk-ant-abcdefghijkl a@b.example C:\\Users\\x\\f.txt ok")
        self.assertEqual(text, "<REDACTED> <REDACTED> <REDACTED> <REDACTED> ok")

    def test_config_rejects_long_window_and_empty_auth_methods(self):
        with self.assertRaises(ValueError):
            self.config(expires_at=(ARMED + timedelta(hours=25)).isoformat())
        with self.assertRaises(ValueError):
            self.config(allowed_auth_methods=[])


if __name__ == "__main__":
    unittest.main()
