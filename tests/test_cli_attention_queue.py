import argparse
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from agent_controller import cli


class CliAttentionQueueTests(unittest.TestCase):
    def test_existing_commands_still_require_repo_and_pr(self):
        parser = argparse.ArgumentParser()
        args = argparse.Namespace(command="inspect-pr", repo=None, pr=None)
        with self.assertRaises(SystemExit):
            cli._require_single_pr_target(parser, args)

    def test_attention_queue_needs_no_repo_or_pr(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            targets_file = os.path.join(temp_dir, "targets.json")
            with open(targets_file, "w", encoding="utf-8") as handle:
                json.dump([{"repo": "a/repo", "pr": 1, "state_file": "a.json"}], handle)

            expected = (
                {
                    "repo": "a/repo",
                    "pr": 1,
                    "category": "HUMAN_ACTION",
                },
            )
            stdout = io.StringIO()
            with patch.object(sys, "argv", ["agent-controller", "attention-queue", "--targets-file", targets_file]), patch.object(
                cli, "run_attention_watch", return_value=expected
            ) as mocked, redirect_stdout(stdout):
                cli.main()

            mocked.assert_called_once()
            self.assertEqual([dict(expected[0])], json.loads(stdout.getvalue()))


if __name__ == "__main__":
    unittest.main()
