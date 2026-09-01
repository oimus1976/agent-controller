import unittest

from agent_controller.jules_issue_task import (
    ALLOWED_EFFECTS,
    APPROVAL_POLICY_ID,
    FORBIDDEN_EFFECTS,
    REQUESTED_CAPABILITY,
    JulesIssueTaskSpec,
    build_issue_task,
)


SHA = "a" * 40
ISSUE = 55
SUFFIX = SHA[:12]


def valid_raw(**overrides):
    raw = {
        "schema_version": 1,
        "issue_number": ISSUE,
        "repo": "oimus1976/agent-controller",
        "expected_start_ref": "main",
        "expected_start_sha": SHA,
        "controller_task_id": f"task-jules-issue-{ISSUE}-{SUFFIX}",
        "operation_id": f"op-jules-issue-{ISSUE}-{SUFFIX}",
        "workstream_id": f"jules-issue-{ISSUE}-{SUFFIX}",
        "destination_branch": f"controller/jules-issue-{ISSUE}-{SUFFIX}",
        "prompt": "Implement the bounded resource-usage slice for GitHub Issue #55.",
        "allowed_paths": ["agent_controller/resource_meter.py", "tests/test_resource_meter.py"],
        "denied_paths": [".github/**", "scripts/**"],
        "requested_capability": REQUESTED_CAPABILITY,
        "allowed_effects": list(ALLOWED_EFFECTS),
        "forbidden_effects": list(FORBIDDEN_EFFECTS),
        "approval_policy_id": APPROVAL_POLICY_ID,
    }
    raw.update(overrides)
    return raw


class FakeGitHub:
    def __init__(self, sha):
        self.sha = sha
        self.calls = []

    def get_ref_sha(self, repo, ref):
        self.calls.append((repo, ref))
        return self.sha


class JulesIssueTaskSpecTests(unittest.TestCase):
    def test_valid_spec_freezes_exact_identity_scope_and_state(self):
        spec = JulesIssueTaskSpec.from_mapping(valid_raw())
        self.assertEqual(spec.issue_number, 55)
        self.assertEqual(spec.allowed_paths, (
            "agent_controller/resource_meter.py",
            "tests/test_resource_meter.py",
        ))
        self.assertEqual(
            spec.state_filename,
            ".jules_issue_task_55_aaaaaaaaaaaa_state.json",
        )
        task = spec.to_task_binding()
        self.assertEqual(task.provider, "jules")
        self.assertEqual(task.expected_start_sha, SHA)
        self.assertEqual(task.objective_scope.allowed_paths, spec.allowed_paths)
        self.assertEqual(task.allowed_effects, ALLOWED_EFFECTS)
        self.assertEqual(task.forbidden_effects, FORBIDDEN_EFFECTS)
        workstream = spec.to_workstream_binding()
        self.assertEqual(workstream.root_work_item_ref, "github:issue:55")
        self.assertEqual(workstream.branch_refs, (spec.destination_branch,))

    def test_unknown_missing_and_identity_mismatch_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "unknown task spec fields"):
            JulesIssueTaskSpec.from_mapping(valid_raw(extra="nope"))
        missing = valid_raw()
        missing.pop("prompt")
        with self.assertRaisesRegex(ValueError, "missing task spec fields"):
            JulesIssueTaskSpec.from_mapping(missing)
        with self.assertRaisesRegex(ValueError, "operation_id must equal"):
            JulesIssueTaskSpec.from_mapping(valid_raw(operation_id="op-other"))
        with self.assertRaisesRegex(ValueError, "destination_branch must equal"):
            JulesIssueTaskSpec.from_mapping(valid_raw(destination_branch="main"))

    def test_scope_is_explicit_exact_and_not_overbroad(self):
        with self.assertRaisesRegex(ValueError, "exact paths"):
            JulesIssueTaskSpec.from_mapping(valid_raw(allowed_paths=["agent_controller/**"]))
        with self.assertRaisesRegex(ValueError, "repository-relative"):
            JulesIssueTaskSpec.from_mapping(valid_raw(allowed_paths=["/etc/passwd"]))
        with self.assertRaisesRegex(ValueError, "unsafe traversal"):
            JulesIssueTaskSpec.from_mapping(valid_raw(allowed_paths=["../secrets.txt"]))
        with self.assertRaisesRegex(ValueError, "all-repository wildcard"):
            JulesIssueTaskSpec.from_mapping(valid_raw(denied_paths=["**"]))

    def test_effects_and_policy_cannot_be_widened(self):
        with self.assertRaisesRegex(ValueError, "allowed_effects cannot differ"):
            JulesIssueTaskSpec.from_mapping(
                valid_raw(allowed_effects=["SESSION_CREATE", "DRAFT_PR_CREATE", "MERGE"])
            )
        with self.assertRaisesRegex(ValueError, "forbidden_effects cannot differ"):
            JulesIssueTaskSpec.from_mapping(
                valid_raw(forbidden_effects=["AUTO_CREATE_PR", "PLAN_APPROVAL"])
            )
        with self.assertRaisesRegex(ValueError, "approval_policy_id must equal"):
            JulesIssueTaskSpec.from_mapping(valid_raw(approval_policy_id="none"))

    def test_prompt_must_bind_issue_and_sha_must_be_exact(self):
        with self.assertRaisesRegex(ValueError, "issue number"):
            JulesIssueTaskSpec.from_mapping(valid_raw(prompt="Implement this task."))
        with self.assertRaisesRegex(ValueError, "lowercase 40-hex"):
            JulesIssueTaskSpec.from_mapping(valid_raw(expected_start_sha="A" * 40))

    def test_base_drift_stops_before_jules_adapter_construction(self):
        spec = JulesIssueTaskSpec.from_mapping(valid_raw())
        github = FakeGitHub("b" * 40)
        with self.assertRaisesRegex(RuntimeError, "ISSUE_TASK_EXPECTED_BASE_DRIFT"):
            build_issue_task(spec, github=github, api_client=object())
        self.assertEqual(github.calls, [("oimus1976/agent-controller", "main")])


if __name__ == "__main__":
    unittest.main()
