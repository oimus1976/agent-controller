import inspect
import unittest
from pathlib import Path
from types import SimpleNamespace

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

    def test_complete_spec_evidence_is_canonical_and_prompt_sensitive(self):
        spec = SimpleNamespace(
            schema_version=1,
            issue_number=55,
            repo="oimus1976/agent-controller",
            expected_start_ref="main",
            expected_start_sha="a" * 40,
            controller_task_id="task-jules-issue-55-aaaaaaaaaaaa",
            operation_id="op-jules-issue-55-aaaaaaaaaaaa",
            workstream_id="jules-issue-55-aaaaaaaaaaaa",
            destination_branch="controller/jules-issue-55-aaaaaaaaaaaa",
            prompt="Implement Issue #55 slice A",
            allowed_paths=("agent_controller/resource_meter.py",),
            denied_paths=(".github/**",),
            requested_capability="JULES_BOUNDED_ISSUE_IMPLEMENTATION",
            allowed_effects=("SESSION_CREATE", "DRAFT_PR_CREATE"),
            forbidden_effects=("AUTO_CREATE_PR", "PLAN_APPROVAL", "READY", "MERGE"),
            approval_policy_id="adr-90-human-final",
        )
        payload, digest = runner._spec_evidence(spec)
        self.assertEqual(len(digest), 64)
        self.assertEqual(payload["prompt"], spec.prompt)
        self.assertEqual(payload["denied_paths"], [".github/**"])
        self.assertEqual(payload["forbidden_effects"], list(spec.forbidden_effects))

        changed = SimpleNamespace(**{**vars(spec), "prompt": "Implement Issue #55 slice B"})
        _, changed_digest = runner._spec_evidence(changed)
        self.assertNotEqual(digest, changed_digest)

    def test_spec_and_task_state_patterns_are_gitignored(self):
        ignore = Path(".gitignore").read_text(encoding="utf-8")
        self.assertIn(".jules_issue_task_spec.json", ignore)
        self.assertIn(".jules_issue_task_*_state.json", ignore)


if __name__ == "__main__":
    unittest.main()
