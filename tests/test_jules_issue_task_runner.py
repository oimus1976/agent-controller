import inspect
import unittest.mock
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



    @unittest.mock.patch("scripts.run_jules_e2e_smoke._wait_for_human")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._replace_state")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._write_once")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._verify_local_checkout")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._now")
    @unittest.mock.patch("scripts.run_jules_issue_task.run_operator_assisted_smoke")
    @unittest.mock.patch("scripts.run_jules_issue_task.JulesApiClient")
    @unittest.mock.patch("scripts.run_jules_issue_task.GitHubRestDraftPublicationBackend")
    @unittest.mock.patch("scripts.run_jules_issue_task._publication_with_issue_metadata")
    @unittest.mock.patch("scripts.run_jules_issue_task._spec_evidence")
    @unittest.mock.patch("scripts.run_jules_issue_task._load_spec")
    @unittest.mock.patch("scripts.run_jules_issue_task.build_issue_task")
    @unittest.mock.patch("time.monotonic_ns")
    @unittest.mock.patch("uuid.uuid4")
    def test_runner_records_resource_usage_on_success(
        self,
        mock_uuid4,
        mock_monotonic_ns,
        mock_build_issue_task,
        mock_load_spec,
        mock_spec_evidence,
        mock_publication,
        mock_github,
        mock_api_client,
        mock_run_operator,
        mock_now,
        mock_verify,
        mock_write_once,
        mock_replace_state,
        mock_wait,
    ):
        mock_uuid4.return_value = unittest.mock.MagicMock(hex="run-1234", __str__=lambda self: "run-1234")
        mock_monotonic_ns.side_effect = [1_000_000_000, 3_500_000_000] # start, end (2500ms elapsed)
        mock_now.return_value = "2023-01-01T00:00:00Z"
        
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
            state_filename=".state",
        )
        mock_load_spec.return_value = (spec, 1024) # 1024 bytes
        mock_spec_evidence.return_value = ({"spec": "data"}, "digest123")
        
        task = SimpleNamespace(
            repo="oimus1976/agent-controller",
            expected_start_ref="main",
            expected_start_sha="a"*40,
            controller_task_id="task-jules-issue-55-aaaaaaaaaaaa",
            operation_id="op-jules-issue-55-aaaaaaaaaaaa",
        )
        workstream = SimpleNamespace(workstream_id="jules-issue-55-aaaaaaaaaaaa")
        mock_build_issue_task.return_value = (task, workstream, "dest-branch", "adapter", "change_reader", "github")
        
        mock_result = unittest.mock.MagicMock()
        mock_result.status = "PASS"
        mock_result.to_dict.return_value = {"status": "PASS", "data": "yes"}
        mock_run_operator.return_value = mock_result
        
        # Patch sys.stdout to prevent noise and path.exists
        with unittest.mock.patch("sys.stdout"), unittest.mock.patch("pathlib.Path.exists", return_value=False):
            result = runner.main()
            
        self.assertEqual(result, 0)
        
        # Verify the final state replace call includes resource_usage
        final_call = mock_replace_state.call_args_list[-1]
        state_dict = final_call[0][1]
        self.assertIn("resource_usage", state_dict)
        usage = state_dict["resource_usage"]
        
        self.assertEqual(usage["controller_task_id"], "task-jules-issue-55-aaaaaaaaaaaa")
        self.assertEqual(usage["operation_id"], "op-jules-issue-55-aaaaaaaaaaaa")
        self.assertEqual(usage["operation_version"], "1")
        self.assertEqual(usage["provider"], "jules")
        self.assertEqual(usage["controller_run_id"], "run-1234")
        self.assertEqual(usage["source"], "CONTROLLER_MEASURED")
        self.assertEqual(usage["bytes_read"], 1024)
        self.assertEqual(usage["elapsed_ms"], 2500)
        
        # Uncached and tokens should not be present (they are Optional but shouldn't be added explicitly as None in dict if not provided or left out depending on asdict, asdict includes None but we can check values)
        self.assertIsNone(usage.get("uncached_input_tokens"))

    @unittest.mock.patch("scripts.run_jules_e2e_smoke._wait_for_human")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._replace_state")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._write_once")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._verify_local_checkout")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._now")
    @unittest.mock.patch("scripts.run_jules_issue_task.run_operator_assisted_smoke")
    @unittest.mock.patch("scripts.run_jules_issue_task.JulesApiClient")
    @unittest.mock.patch("scripts.run_jules_issue_task.GitHubRestDraftPublicationBackend")
    @unittest.mock.patch("scripts.run_jules_issue_task._publication_with_issue_metadata")
    @unittest.mock.patch("scripts.run_jules_issue_task._spec_evidence")
    @unittest.mock.patch("scripts.run_jules_issue_task._load_spec")
    @unittest.mock.patch("scripts.run_jules_issue_task.build_issue_task")
    @unittest.mock.patch("time.monotonic_ns")
    @unittest.mock.patch("uuid.uuid4")
    def test_runner_records_resource_usage_on_exception(
        self,
        mock_uuid4,
        mock_monotonic_ns,
        mock_build_issue_task,
        mock_load_spec,
        mock_spec_evidence,
        mock_publication,
        mock_github,
        mock_api_client,
        mock_run_operator,
        mock_now,
        mock_verify,
        mock_write_once,
        mock_replace_state,
        mock_wait,
    ):
        mock_uuid4.return_value = unittest.mock.MagicMock(hex="run-1234", __str__=lambda self: "run-1234")
        mock_monotonic_ns.side_effect = [1_000_000_000, 3_500_000_000] # start, end (2500ms elapsed)
        mock_now.return_value = "2023-01-01T00:00:00Z"
        
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
            state_filename=".state",
        )
        mock_load_spec.return_value = (spec, 1024)
        mock_spec_evidence.return_value = ({"spec": "data"}, "digest123")
        
        task = SimpleNamespace(
            repo="oimus1976/agent-controller",
            expected_start_ref="main",
            expected_start_sha="a"*40,
            controller_task_id="task-jules-issue-55-aaaaaaaaaaaa",
            operation_id="op-jules-issue-55-aaaaaaaaaaaa",
        )
        workstream = SimpleNamespace(workstream_id="jules-issue-55-aaaaaaaaaaaa")
        mock_build_issue_task.return_value = (task, workstream, "dest-branch", "adapter", "change_reader", "github")
        
        mock_run_operator.side_effect = RuntimeError("Something bad happened")
        
        # Patch sys.stdout and sys.stderr to prevent noise and path.exists
        with unittest.mock.patch("sys.stdout"), unittest.mock.patch("sys.stderr"), unittest.mock.patch("pathlib.Path.exists", return_value=False):
            result = runner.main()
            
        self.assertEqual(result, 1)
        
        final_call = mock_replace_state.call_args_list[-1]
        state_dict = final_call[0][1]
        self.assertEqual(state_dict["state"], "UNCAUGHT_UNCERTAINTY")
        self.assertIn("resource_usage", state_dict)
        usage = state_dict["resource_usage"]
        self.assertEqual(usage["elapsed_ms"], 2500)


if __name__ == "__main__":
    unittest.main()
