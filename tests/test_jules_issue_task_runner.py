import inspect
import io
import json
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
        class SpecV1:
            issue_number = 55
            schema_version = 1

        class SpecV2:
            issue_number = 56
            schema_version = 2
            pr_title = "#56 Test PR Title"

        captured = {}

        original = runner.publish_jules_changeset_to_draft_pr
        try:
            def fake_publish(**kwargs):
                captured.update(kwargs)
                return "ok"

            runner.publish_jules_changeset_to_draft_pr = fake_publish
            
            # Test V1
            result = runner._publication_with_issue_metadata(SpecV1())(sentinel=True)
            self.assertEqual(result, "ok")
            self.assertTrue(captured["sentinel"])
            self.assertEqual(captured["pr_title"], "Issue #55: Jules implementation")
            self.assertIn("Draft PR", captured["pr_body"])
            self.assertIn("human-final", captured["pr_body"])
            
            captured.clear()
            
            # Test V2
            result = runner._publication_with_issue_metadata(SpecV2())(sentinel=True)
            self.assertEqual(result, "ok")
            self.assertTrue(captured["sentinel"])
            self.assertEqual(captured["pr_title"], "#56 Test PR Title")
            self.assertIn("Draft PR", captured["pr_body"])
            self.assertIn("human-final", captured["pr_body"])
        finally:
            runner.publish_jules_changeset_to_draft_pr = original

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
        self.assertNotIn("pr_title", payload)

        changed = SimpleNamespace(**{**vars(spec), "prompt": "Implement Issue #55 slice B"})
        _, changed_digest = runner._spec_evidence(changed)
        self.assertNotEqual(digest, changed_digest)
        
        # Test V2 schema includes pr_title
        spec.schema_version = 2
        spec.pr_title = "#55 Feature PR"
        payload_v2, digest_v2 = runner._spec_evidence(spec)
        self.assertNotEqual(digest, digest_v2)
        self.assertIn("pr_title", payload_v2)
        self.assertEqual(payload_v2["pr_title"], "#55 Feature PR")

    def test_spec_and_task_state_patterns_are_gitignored(self):
        ignore = Path(".gitignore").read_text(encoding="utf-8")
        self.assertIn(".jules_issue_task_spec.json", ignore)
        self.assertIn(".jules_issue_task_*_state.json", ignore)

    def test_load_spec_measures_actual_bytes_read(self):
        raw_bytes = json.dumps(
            {
                "schema_version": 1,
                "issue_number": 55,
            }
        ).encode("utf-8")
        parsed_spec = object()
        path = unittest.mock.Mock()
        path.read_bytes.return_value = raw_bytes

        with unittest.mock.patch.object(
            runner.JulesIssueTaskSpec, "from_mapping", return_value=parsed_spec
        ) as from_mapping:
            spec, bytes_read = runner._load_spec(path)

        self.assertIs(spec, parsed_spec)
        self.assertEqual(bytes_read, len(raw_bytes))
        path.read_bytes.assert_called_once_with()
        from_mapping.assert_called_once_with(json.loads(raw_bytes))


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
        self.assertEqual(usage["operation_version"], "mvp-v1")
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
        
        stdout = io.StringIO()
        with (
            unittest.mock.patch("sys.stdout", stdout),
            unittest.mock.patch("sys.stderr"),
            unittest.mock.patch("pathlib.Path.exists", return_value=False),
        ):
            result = runner.main()
            
        self.assertEqual(result, 1)
        
        final_call = mock_replace_state.call_args_list[-1]
        state_dict = final_call[0][1]
        self.assertEqual(state_dict["state"], "UNCAUGHT_UNCERTAINTY")
        self.assertIn("resource_usage", state_dict)
        usage = state_dict["resource_usage"]
        self.assertEqual(usage["elapsed_ms"], 2500)
        self.assertEqual(json.loads(stdout.getvalue())["resource_usage"], usage)

    @unittest.mock.patch("scripts.run_jules_e2e_smoke._replace_state")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._write_once")
    @unittest.mock.patch("scripts.run_jules_e2e_smoke._verify_local_checkout")
    @unittest.mock.patch(
        "scripts.run_jules_e2e_smoke._now", return_value="2023-01-01T00:00:00Z"
    )
    @unittest.mock.patch(
        "scripts.run_jules_issue_task.run_operator_assisted_smoke",
        side_effect=KeyboardInterrupt,
    )
    @unittest.mock.patch("scripts.run_jules_issue_task.JulesApiClient")
    @unittest.mock.patch("scripts.run_jules_issue_task.GitHubRestDraftPublicationBackend")
    @unittest.mock.patch("scripts.run_jules_issue_task._publication_with_issue_metadata")
    @unittest.mock.patch(
        "scripts.run_jules_issue_task._spec_evidence",
        return_value=({"spec": "data"}, "digest"),
    )
    @unittest.mock.patch("scripts.run_jules_issue_task._load_spec")
    @unittest.mock.patch("scripts.run_jules_issue_task.build_issue_task")
    @unittest.mock.patch("time.monotonic_ns", side_effect=[1_000_000_000, 2_000_000_000])
    @unittest.mock.patch("uuid.uuid4", return_value="run-1234")
    def test_runner_persists_and_emits_usage_on_interrupt(
        self,
        _uuid,
        _clock,
        build,
        load,
        _evidence,
        _publication,
        _github,
        _api_client,
        _run,
        _now,
        _verify,
        _write,
        replace,
    ):
        spec = SimpleNamespace(
            schema_version=1, issue_number=55, state_filename=".state"
        )
        load.return_value = (spec, 17)
        task = SimpleNamespace(
            repo="oimus1976/agent-controller",
            expected_start_ref="main",
            expected_start_sha="a" * 40,
            controller_task_id="task-55",
            operation_id="op-55",
        )
        workstream = SimpleNamespace(workstream_id="workstream-55")
        build.return_value = (task, workstream, "branch", "adapter", "reader", "github")
        stdout = io.StringIO()

        with (
            unittest.mock.patch("sys.stdout", stdout),
            unittest.mock.patch("sys.stderr"),
            unittest.mock.patch("pathlib.Path.exists", return_value=False),
        ):
            result = runner.main()

        self.assertEqual(result, 130)
        state = replace.call_args.args[1]
        self.assertEqual(state["state"], "INTERRUPTED_UNCERTAINTY")
        self.assertEqual(state["resource_usage"]["bytes_read"], 17)
        self.assertEqual(
            json.loads(stdout.getvalue())["resource_usage"], state["resource_usage"]
        )


if __name__ == "__main__":
    unittest.main()
