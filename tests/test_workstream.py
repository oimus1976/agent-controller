import unittest
from unittest.mock import patch

from agent_controller.attention_queue import (
    AttentionCategory,
    build_attention_queue,
    select_attention_for_workstream,
)
from agent_controller.executor import execute_workstream_action
from agent_controller.multi_watch import run_attention_watch, validate_targets
from agent_controller.provider_contract import (
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
)
from agent_controller.workstream import (
    WorkstreamBinding,
    validate_branch_workstream,
    validate_dependency_reference,
    validate_operation_workstream,
    validate_pr_workstream,
    validate_task_workstream,
)


class WorkstreamContractTests(unittest.TestCase):
    def setUp(self):
        self.a = WorkstreamBinding(
            workstream_id="jules-integration",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:116",
            task_ids=("issue-116-live",),
            github_prs=(117,),
            branch_refs=("refs/heads/feat/live-jules",),
        )
        self.b = WorkstreamBinding(
            workstream_id="closeout-rollout",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:118",
            task_ids=("issue-118-rollout",),
            github_prs=(119,),
            branch_refs=("refs/heads/chore/post-merge-local-closeout",),
            depends_on_workstream_ids=("starter-closeout",),
        )

    def _task(self, task_id="issue-116-live", repo="oimus1976/agent-controller"):
        return TaskBinding(
            controller_task_id=task_id,
            operation_id="op-1",
            provider="jules",
            repo=repo,
            expected_start_ref="refs/heads/main",
            expected_start_sha="a" * 40,
            objective_scope=ObjectiveScope(),
            requested_capability="IMPLEMENT",
            allowed_effects=("SESSION_CREATE",),
            forbidden_effects=(),
            approval_policy_id="policy-1",
            created_at="2026-08-31T00:00:00Z",
        )

    def test_binding_rejects_malformed_or_self_dependency(self):
        with self.assertRaises(ValueError):
            WorkstreamBinding("", "o/r", "github:issue:1")
        with self.assertRaises(ValueError):
            WorkstreamBinding("a", "bad-repo", "github:issue:1")
        with self.assertRaises(ValueError):
            WorkstreamBinding(
                "a",
                "o/r",
                "github:issue:1",
                depends_on_workstream_ids=("a",),
            )

    def test_task_membership_is_explicit_not_same_repo_heuristic(self):
        self.assertTrue(validate_task_workstream(binding=self.a, task=self._task()).valid)
        wrong_task = validate_task_workstream(
            binding=self.a, task=self._task(task_id="issue-118-rollout")
        )
        self.assertFalse(wrong_task.valid)
        self.assertEqual("TASK_NOT_IN_WORKSTREAM", wrong_task.reason)

        wrong_repo = validate_task_workstream(
            binding=self.a, task=self._task(repo="other/repo")
        )
        self.assertFalse(wrong_repo.valid)
        self.assertEqual("TASK_REPO_MISMATCH", wrong_repo.reason)

    def test_provider_operation_membership_uses_bound_controller_task(self):
        good = ProviderOperationRef(
            provider="jules",
            provider_operation_id="session-a",
            provider_url=None,
            controller_task_id="issue-116-live",
            operation_id="op-1",
        )
        other = ProviderOperationRef(
            provider="jules",
            provider_operation_id="session-b",
            provider_url=None,
            controller_task_id="issue-118-rollout",
            operation_id="op-2",
        )
        self.assertTrue(validate_operation_workstream(binding=self.a, operation=good).valid)
        result = validate_operation_workstream(binding=self.a, operation=other)
        self.assertFalse(result.valid)
        self.assertEqual("OPERATION_TASK_NOT_IN_WORKSTREAM", result.reason)

    def test_pr_branch_and_dependency_require_explicit_membership(self):
        self.assertTrue(
            validate_pr_workstream(
                binding=self.a, repo="OIMUS1976/AGENT-CONTROLLER", pr=117
            ).valid
        )
        wrong_pr = validate_pr_workstream(
            binding=self.a, repo="oimus1976/agent-controller", pr=119
        )
        self.assertFalse(wrong_pr.valid)
        self.assertEqual("PR_NOT_IN_WORKSTREAM", wrong_pr.reason)

        self.assertTrue(
            validate_branch_workstream(
                binding=self.a,
                repo="oimus1976/agent-controller",
                branch_ref="refs/heads/feat/live-jules",
            ).valid
        )
        self.assertFalse(
            validate_branch_workstream(
                binding=self.a,
                repo="oimus1976/agent-controller",
                branch_ref="refs/heads/chore/post-merge-local-closeout",
            ).valid
        )

        self.assertTrue(
            validate_dependency_reference(
                binding=self.b, related_workstream_id="starter-closeout"
            ).valid
        )
        self.assertFalse(
            validate_dependency_reference(
                binding=self.b, related_workstream_id="jules-integration"
            ).valid
        )


class WorkstreamIncidentRegressionTests(unittest.TestCase):
    @staticmethod
    def _observation(repo, pr, *, classification, draft=False, merged=False, state="open"):
        return {
            "repo": repo,
            "pr": pr,
            "current_head_sha": f"sha-{pr}",
            "current_classification": classification,
            "current_draft": draft,
            "current_merged": merged,
            "current_state_enum": state,
            "scope_status": "SATISFIED",
            "graphql_error": False,
            "actions_ci_status": "PASS",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["CLASSIFICATION_CHANGED"],
        }

    def test_117_completion_does_not_promote_119_into_lane_a(self):
        observations = [
            {
                **self._observation(
                    "oimus1976/agent-controller",
                    117,
                    classification="CLOSED",
                    merged=True,
                    state="closed",
                ),
                "workstream_id": "jules-integration",
            },
            {
                **self._observation(
                    "oimus1976/agent-controller",
                    119,
                    classification="REVIEW_READY",
                    draft=True,
                ),
                "workstream_id": "closeout-rollout",
            },
        ]

        global_queue = build_attention_queue(observations)
        self.assertEqual(119, global_queue[0].pr)
        self.assertEqual(AttentionCategory.HUMAN_ACTION, global_queue[0].category)

        lane_a = select_attention_for_workstream(global_queue, "jules-integration")
        lane_b = select_attention_for_workstream(global_queue, "closeout-rollout")
        self.assertEqual([117], [item.pr for item in lane_a])
        self.assertEqual([119], [item.pr for item in lane_b])
        self.assertEqual(AttentionCategory.DONE, lane_a[0].category)
        self.assertEqual("MARK_READY_FOR_REVIEW", lane_b[0].human_action)

    def test_multi_watch_controller_binding_overrides_observation_prose(self):
        def fake_watch(owner, repo, pr, state_file, scope_policy):
            observation = self._observation(
                f"{owner}/{repo}",
                pr,
                classification="IMPLEMENTATION_READY",
            )
            observation["workstream_id"] = "provider-guessed-lane"
            return observation

        queue = run_attention_watch(
            [
                {
                    "repo": "oimus1976/agent-controller",
                    "pr": 117,
                    "state_file": "a.json",
                    "workstream_id": "jules-integration",
                },
                {
                    "repo": "oimus1976/agent-controller",
                    "pr": 119,
                    "state_file": "b.json",
                    "workstream_id": "closeout-rollout",
                },
            ],
            watch_once=fake_watch,
        )
        self.assertEqual(
            {"jules-integration", "closeout-rollout"},
            {item["workstream_id"] for item in queue},
        )
        self.assertNotIn("provider-guessed-lane", {item["workstream_id"] for item in queue})

    def test_partial_lane_configuration_fails_before_any_watch(self):
        calls = []

        def fake_watch(*args):
            calls.append(args)
            return self._observation("o/r", 1, classification="IMPLEMENTATION_READY")

        with self.assertRaises(ValueError):
            run_attention_watch(
                [
                    {
                        "repo": "o/r",
                        "pr": 1,
                        "state_file": "a.json",
                        "workstream_id": "lane-a",
                    },
                    {"repo": "o/r", "pr": 2, "state_file": "b.json"},
                ],
                watch_once=fake_watch,
            )
        self.assertEqual([], calls)

    @patch("agent_controller.executor.convert_pull_request_to_draft")
    @patch("agent_controller.executor.get_pr_details")
    def test_cross_lane_mutation_is_blocked_before_github_read_or_mutator(
        self, mock_get_pr_details, mock_mutator
    ):
        lane_a = WorkstreamBinding(
            workstream_id="jules-integration",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:116",
            github_prs=(117,),
        )
        plan = {
            "repo": "oimus1976/agent-controller",
            "pr": 119,
            "requested_action": "ENSURE_DRAFT",
            "decision": "EXECUTABLE",
            "reason": "READY_FOR_DRAFT_CONVERSION",
            "head_sha": "sha-119",
        }

        result = execute_workstream_action(
            plan,
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=lane_a,
            apply=True,
        )
        self.assertEqual("BLOCKED", result["final_outcome"])
        self.assertEqual("PR_NOT_IN_WORKSTREAM", result["failure_reason"])
        self.assertFalse(result["mutation_attempted"])
        mock_get_pr_details.assert_not_called()
        mock_mutator.assert_not_called()

    @patch("agent_controller.executor.get_pr_details")
    def test_matching_lane_reaches_existing_dry_run_boundary(self, mock_get_pr_details):
        lane_b = WorkstreamBinding(
            workstream_id="closeout-rollout",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:118",
            github_prs=(119,),
        )
        plan = {
            "repo": "oimus1976/agent-controller",
            "pr": 119,
            "requested_action": "ENSURE_DRAFT",
            "decision": "EXECUTABLE",
            "reason": "READY_FOR_DRAFT_CONVERSION",
            "head_sha": "sha-119",
        }
        result = execute_workstream_action(
            plan,
            "oimus1976",
            "agent-controller",
            119,
            workstream_binding=lane_b,
            apply=False,
        )
        self.assertEqual("DRY_RUN", result["final_outcome"])
        self.assertEqual("APPLY_FLAG_NOT_SET", result["failure_reason"])
        mock_get_pr_details.assert_not_called()

    def test_lane_mode_validation_is_all_or_none(self):
        validated = validate_targets(
            [
                {
                    "repo": "o/r",
                    "pr": 1,
                    "state_file": "a.json",
                    "workstream_id": "lane-a",
                },
                {
                    "repo": "o/r",
                    "pr": 2,
                    "state_file": "b.json",
                    "workstream_id": "lane-b",
                },
            ]
        )
        self.assertEqual("lane-a", validated[0]["workstream_id"])
        self.assertEqual("lane-b", validated[1]["workstream_id"])


if __name__ == "__main__":
    unittest.main()
