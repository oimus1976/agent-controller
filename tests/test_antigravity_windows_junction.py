import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from agent_controller.antigravity_review import parse_antigravity_stream_json


def strict_realpath(path):
    return os.path.realpath(path, strict=True)


def init_event(workspace):
    return json.dumps(
        {
            "event": "init",
            "conversation_id": "c1",
            "init": {"cwd": str(workspace)},
        },
        separators=(",", ":"),
    )


def active_view_file(target):
    return json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "conversation_id": "c1",
                "step_index": 0,
                "state": "ACTIVE",
                "step_type": "tool",
                "tool_name": "view_file",
                "tool_info": {
                    "name": "view_file",
                    "parameters": {"AbsolutePath": str(target)},
                },
            },
        },
        separators=(",", ":"),
    )


def result_event():
    return json.dumps(
        {
            "event": "result",
            "result": {
                "conversation_id": "c1",
                "status": "SUCCESS",
                "response": "NO_FINDINGS",
                "denied_actions": [],
            },
        },
        separators=(",", ":"),
    )


def create_junction(junction, target):
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        raise AssertionError(
            f"mklink /J failed: stdout={created.stdout!r} stderr={created.stderr!r}"
        )


@unittest.skipUnless(os.name == "nt", "Windows junction regression")
class AntigravityWindowsJunctionTests(unittest.TestCase):
    def test_real_junction_escape_fails_closed_after_strict_canonical_resolution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "repo"
            outside = root / "outside"
            junction = workspace / "junction"
            secret = outside / "secret.txt"
            workspace.mkdir()
            outside.mkdir()
            secret.write_text("outside", encoding="utf-8")
            create_junction(junction, outside)

            try:
                escaped = junction / "secret.txt"
                resolved_workspace = strict_realpath(str(workspace))
                resolved_target = strict_realpath(str(escaped))
                self.assertNotEqual(
                    os.path.commonpath((resolved_workspace, resolved_target)),
                    resolved_workspace,
                    msg="test setup did not resolve the junction outside the workspace",
                )

                with self.assertRaisesRegex(ValueError, "within the expected workspace"):
                    parse_antigravity_stream_json(
                        [init_event(workspace), active_view_file(escaped), result_event()],
                        expected_workspace=str(workspace),
                        canonical_path_resolver=strict_realpath,
                    )
            finally:
                if os.path.lexists(junction):
                    os.rmdir(junction)

    def test_unresolvable_junction_target_fails_closed_under_strict_resolution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "repo"
            outside = root / "outside"
            junction = workspace / "junction"
            workspace.mkdir()
            outside.mkdir()
            create_junction(junction, outside)

            outside.rmdir()
            escaped = junction / "missing.txt"
            try:
                with self.assertRaisesRegex(ValueError, "canonical resolution failed"):
                    parse_antigravity_stream_json(
                        [init_event(workspace), active_view_file(escaped), result_event()],
                        expected_workspace=str(workspace),
                        canonical_path_resolver=strict_realpath,
                    )
            finally:
                if os.path.lexists(junction):
                    os.rmdir(junction)


if __name__ == "__main__":
    unittest.main()
