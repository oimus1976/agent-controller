import json
import os
import tempfile
import unittest
from unittest.mock import patch

from agent_controller.watcher import watch_pr_once


class WatcherActionsCiTests(unittest.TestCase):
    @patch("agent_controller.watcher.inspect_pr")
    def test_ci_status_change_is_explicit_transition(self, mock_inspect):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_file = os.path.join(temp_dir, "state.json")
            with open(state_file, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "repo": "owner/repo",
                        "pr": 1,
                        "head_sha": "same-head",
                        "classification": "NEEDS_REVIEW",
                        "draft": True,
                        "merged": False,
                        "state_enum": "open",
                        "graphql_error": False,
                        "actions_ci_status": "PENDING",
                        "check_runs_error": False,
                        "scope_status": "SATISFIED",
                    },
                    handle,
                )

            mock_inspect.return_value = {
                "head_sha": "same-head",
                "classification": "NEEDS_REVIEW",
                "draft": True,
                "merged": False,
                "state": "open",
                "graphql_error": False,
                "actions_ci_status": "PASS",
                "check_runs_error": False,
                "scope_status": "SATISFIED",
            }

            observation = watch_pr_once("owner", "repo", 1, state_file)

            self.assertTrue(observation["transition"])
            self.assertEqual(observation["actions_ci_status"], "PASS")
            self.assertIn("CI_STATUS_CHANGED", observation["transition_reasons"])
            self.assertNotIn("HEAD_CHANGED", observation["transition_reasons"])
            self.assertNotIn("CLASSIFICATION_CHANGED", observation["transition_reasons"])


if __name__ == "__main__":
    unittest.main()
