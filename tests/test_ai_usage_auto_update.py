import copy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import ai_usage_auto_update as update


OLD = "2026-11-18T11:00:00.000Z"
NEW = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)


def observation(provider, remaining, observed_at=OLD):
    return {
        "provider": provider, "capacity_pool": "weekly", "remaining_fraction": remaining,
        "reset_at": "2026-11-23T00:00:00.000Z", "availability": "AVAILABLE",
        "capacity_unit": "fraction", "observed_at": observed_at,
        "source": {"last_verified_at": observed_at},
    }


def document(*rows):
    return {"version": "1.0", "document_kind": "ai-usage-observations", "observations": list(rows)}


class ObservationMergeTests(unittest.TestCase):
    def test_timestamp_only_does_not_publish(self):
        old = document(observation("codex", 0.25))
        self.assertIsNone(update.merge_observations(old, old, {"codex": NEW}))

    def test_new_usage_keeps_missing_providers_and_capture_time(self):
        claude = observation("claude-code", 0.66)
        antigravity = observation("antigravity", 0.9)
        old = document(claude, antigravity, observation("codex", 0.25))
        new = document(observation("codex", 0.1, "2026-11-18T14:00:00.000Z"))
        result = update.merge_observations(old, new, {"codex": NEW})
        rows = {row["provider"]: row for row in result["observations"]}
        self.assertEqual(rows["claude-code"], claude)
        self.assertEqual(rows["antigravity"], antigravity)
        self.assertEqual(rows["codex"]["remaining_fraction"], 0.1)
        self.assertEqual(rows["codex"]["observed_at"], "2026-11-18T12:00:00.000Z")
        self.assertEqual(rows["codex"]["source"]["last_verified_at"], rows["codex"]["observed_at"])

    def test_older_statusline_cannot_revert_published_data(self):
        old = document(observation("claude-code", 0.25, update.timestamp(NEW)))
        fresh = document(observation("claude-code", 0.9))
        old_capture = datetime(2026, 11, 18, 11, tzinfo=timezone.utc)
        self.assertIsNone(update.merge_observations(old, fresh, {"claude-code": old_capture}))


class PublicationTests(unittest.TestCase):
    def test_build_output_cannot_include_auth_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "assets").mkdir()
            (root / "fixtures").mkdir()
            (root / "index.html").touch()
            (root / "assets" / ".htpasswd").touch()
            with self.assertRaisesRegex(RuntimeError, "unsupported name"):
                update.files_for_upload(root)

    def test_permission_change_stops_before_index_upload(self):
        remote = "/home/test/www/dashboard"
        def listing(*items):
            return "\n".join(
                [f"Remote working directory: {remote}"]
                + [f"{mode} 1 owner group {size} Nov 18 12:00 {name}" for name, mode, size in items]
            )

        auth = ((".htaccess", "-rw-r--r--", 104), (".htpasswd", "-rw-r--r--", 64))
        previous = update.mode_map(listing(*auth, ("index.html", "-rw-r--r--", 100)), remote)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "assets").mkdir()
            (directory / "assets" / "test.js").write_bytes(b"abc")
            with patch.object(update, "sftp_commands", side_effect=[
                "", listing(("test.js", "-rw-r--r--", 3)),
                listing(), listing(*auth, ("assets", "drwx------", 512)),
            ]) as sftp:
                with self.assertRaisesRegex(RuntimeError, "before index publish"):
                    update.publish_files({"sftp_dashboard_dir": remote}, directory,
                                         ["assets/test.js", "index.html"], copy.deepcopy(previous))
            commands = [command for call in sftp.call_args_list for command in call.args[2]]
            self.assertEqual([command for command in commands if command.startswith("put")],
                             ['put "assets/test.js" "assets/test.js"'])


if __name__ == "__main__":
    unittest.main()
