import unittest

from agent_controller.workstream import WorkstreamBinding, validate_workstream_set


class WorkstreamSetTests(unittest.TestCase):
    def _binding(
        self,
        workstream_id,
        *,
        repo="oimus1976/agent-controller",
        tasks=(),
        issues=(),
        prs=(),
        branches=(),
        depends=(),
    ):
        return WorkstreamBinding(
            workstream_id=workstream_id,
            repo=repo,
            root_work_item_ref=f"github:issue:{issues[0] if issues else 1}",
            task_ids=tasks,
            github_issues=issues,
            github_prs=prs,
            branch_refs=branches,
            depends_on_workstream_ids=depends,
        )

    def test_independent_117_and_119_lanes_are_valid_concurrently(self):
        lane_a = self._binding(
            "jules-integration",
            tasks=("issue-116",),
            issues=(116,),
            prs=(117,),
            branches=("refs/heads/feat/live-jules",),
        )
        lane_b = self._binding(
            "closeout-rollout",
            tasks=("issue-118",),
            issues=(118,),
            prs=(119,),
            branches=("refs/heads/chore/post-merge-local-closeout",),
        )
        self.assertTrue(validate_workstream_set((lane_a, lane_b)).valid)

    def test_same_task_cannot_be_claimed_by_two_lanes(self):
        a = self._binding("a", tasks=("task-1",))
        b = self._binding("b", tasks=("task-1",))
        result = validate_workstream_set((a, b))
        self.assertFalse(result.valid)
        self.assertEqual("TASK_BOUND_TO_MULTIPLE_WORKSTREAMS", result.reason)

    def test_same_issue_pr_or_branch_cannot_be_claimed_twice(self):
        cases = [
            (
                self._binding("a", issues=(116,)),
                self._binding("b", issues=(116,)),
                "ISSUE_BOUND_TO_MULTIPLE_WORKSTREAMS",
            ),
            (
                self._binding("a", prs=(119,)),
                self._binding("b", prs=(119,)),
                "PR_BOUND_TO_MULTIPLE_WORKSTREAMS",
            ),
            (
                self._binding("a", branches=("refs/heads/topic",)),
                self._binding("b", branches=("refs/heads/topic",)),
                "BRANCH_BOUND_TO_MULTIPLE_WORKSTREAMS",
            ),
        ]
        for a, b, reason in cases:
            with self.subTest(reason=reason):
                result = validate_workstream_set((a, b))
                self.assertFalse(result.valid)
                self.assertEqual(reason, result.reason)

    def test_same_pr_number_in_different_repositories_is_not_a_collision(self):
        a = self._binding("a", repo="o/r1", prs=(7,))
        b = self._binding("b", repo="o/r2", prs=(7,))
        self.assertTrue(validate_workstream_set((a, b)).valid)

    def test_duplicate_workstream_id_fails_closed(self):
        result = validate_workstream_set((self._binding("a"), self._binding("a")))
        self.assertFalse(result.valid)
        self.assertEqual("DUPLICATE_WORKSTREAM_ID", result.reason)

    def test_dependency_must_reference_an_active_explicit_workstream(self):
        a = self._binding("a", depends=("b",))
        result = validate_workstream_set((a,))
        self.assertFalse(result.valid)
        self.assertEqual("UNKNOWN_WORKSTREAM_DEPENDENCY", result.reason)

        b = self._binding("b")
        self.assertTrue(validate_workstream_set((a, b)).valid)

    def test_malformed_set_fails_closed(self):
        self.assertFalse(validate_workstream_set("not-a-sequence-of-bindings").valid)
        self.assertFalse(validate_workstream_set((self._binding("a"), object())).valid)


if __name__ == "__main__":
    unittest.main()
