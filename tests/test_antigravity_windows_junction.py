import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from agent_controller.antigravity_review import parse_antigravity_stream_json


@unittest.skipUnless(os.name == "nt", "Windows junction regression")
class AntigravityWindowsJunctionTests(unittest.TestCase):
    def test_real_junction_escape_fails_closed_after_canonical_resolution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "repo"
            outside = root / "outside"
            junction = workspace / "junction"
            secret = outside / "secret.txt"
            workspace.mkdir()
            outside.mkdir()
            secret.write_text("outside", encoding="utf-8")

            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                created.returncode,
                0,
                msg=f"mklink /J failed: stdout={created.stdout!r} stderr={created.stderr!r}",
            )

            try:
                escaped = junction / "secret.txt"
                resolved_workspace = os.path.realpath(str(workspace))
                resolved_target = os.path.realpath(str(escaped))
                self.assertNotEqual(
                    os.path.commonpath((resolved_workspace, resolved_target)),
                    resolved_workspace,
                    msg="test setup did not resolve the junction outside the workspace",
                )

                init_event = json.dumps(
                    {
                        "event": "init",
                        "conversation_id": "c1",
                        "init": {"cwd": str(workspace)},
                    },
                    separators=(",", ":"),
                )
                active_tool = json.dumps(
                    {
                        "event": "step_update",
                        "step_update": {
                            "conversation_id": "c1",
                            "step_index": 1,
                            "state": "ACTIVE",
                            "step_type": "tool",
                            "tool_name": "view_file",
                            "tool_info": {
                                "name": "view_file",
                                "parameters": {"AbsolutePath": str(escaped)},
                            },
                        },
                    },
                    separators=(",", ":"),
                )
                result_event = json.dumps(
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

                with self.assertRaisesRegex(ValueError, "within the expected workspace"):
                    parse_antigravity_stream_json(
                        [init_event, active_tool, result_event],
                        expected_workspace=str(workspace),
                        canonical_path_resolver=os.path.realpath,
                    )
            finally:
                if junction.exists():
                    os.rmdir(junction)


if __name__ == "__main__":
    unittest.main()
