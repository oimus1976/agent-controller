import inspect
import unittest
from pathlib import Path

import scripts.run_jules_issue_task as runner


class JulesIssueTaskRunnerTests(unittest.TestCase):
    def test_runner_has_fixed_spec_path_and_no_cli_surface(self):
        self.assertEqual(runner.SPEC_FILE, Path(".jules_issue_task_spec.json"))
        self.assertEqual(tuple(inspect.signature(runner.main).parameters), ())
        source = inspect.getsource(runner)
        self.assertNotIn("argparse", source)
        self.assertNotIn("--retry", source)
        self.assertNotIn("--state", source)
        self.assertNotIn("--effect", source)
        self.assertNotIn("mark_pull_request_ready", source)
        self.assertNotIn("merge_pull_request", source)

    def test_publication_metadata_is_issue_bound_and_human_final(self):
        class Spec:
            issue_number = 55

        captured = {}

        original = runner.publish_jules_changeset_to_draft_pr
        try:
            def fake_publish(**kwargs):
                captured.update(kwargs)
                return "ok"

            runner.publish_jules_changeset_to_draft_pr = fake_publish
            result = runner._publication_with_issue_metadata(Spec())(sentinel=True)
        finally:
            runner.publish_jules_changeset_to_draft_pr = original

        self.assertEqual(result, "ok")
        self.assertTrue(captured["sentinel"])
        self.assertEqual(captured["pr_title"], "Issue #55: Jules implementation")
        self.assertIn("Implements #55", captured["pr_body"])
        self.assertIn("Ready and merge remain human-final", captured["pr_body"])

    def test_spec_and_task_state_patterns_are_gitignored(self):
        ignore = Path(".gitignore").read_text(encoding="utf-8")
        self.assertIn(".jules_issue_task_spec.json", ignore)
        self.assertIn(".jules_issue_task_*_state.json", ignore)


if __name__ == "__main__":
    unittest.main()
