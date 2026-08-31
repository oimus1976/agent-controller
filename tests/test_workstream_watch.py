import unittest

from agent_controller.workstream import WorkstreamBinding
from agent_controller.workstream_watch import run_workstream_attention_watch


class WorkstreamWatchTests(unittest.TestCase):
    def setUp(self):
        self.a = WorkstreamBinding(
            workstream_id="jules-integration",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:116",
            github_issues=(116,),
            github_prs=(117,),
        )
        self.b = WorkstreamBinding(
            workstream_id="closeout-rollout",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:118",
            github_issues=(118,),
            github_prs=(119,),
        )

    @staticmethod
    def _observation(owner, repo, pr):
        return {
            "repo": f"{owner}/{repo}",
            "pr": pr,
            "current_head_sha": f"sha-{pr}",
            "current_classification": "IMPLEMENTATION_READY",
            "current_draft": False,
            "current_merged": False,
            "current_state_enum": "open",
            "scope_status": "SATISFIED",
            "graphql_error": False,
            "actions_ci_status": "PASS",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["CLASSIFICATION_CHANGED"],
        }

    def test_117_and_119_can_be_observed_concurrently_without_mixing(self):
        calls = []

        def fake_watch(owner, repo, pr, state_file, scope_policy):
            calls.append((owner, repo, pr))
            return self._observation(owner, repo, pr)

        queue = run_workstream_attention_watch(
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
            bindings=(self.a, self.b),
            watch_once=fake_watch,
        )
        self.assertEqual(2, len(calls))
        by_pr = {item["pr"]: item["workstream_id"] for item in queue}
        self.assertEqual("jules-integration", by_pr[117])
        self.assertEqual("closeout-rollout", by_pr[119])

    def test_mislabeled_119_as_lane_a_fails_before_first_watch(self):
        calls = []

        def fake_watch(*args):
            calls.append(args)
            return self._observation("oimus1976", "agent-controller", 119)

        with self.assertRaisesRegex(ValueError, "PR_NOT_IN_WORKSTREAM"):
            run_workstream_attention_watch(
                [
                    {
                        "repo": "oimus1976/agent-controller",
                        "pr": 119,
                        "state_file": "wrong.json",
                        "workstream_id": "jules-integration",
                    }
                ],
                bindings=(self.a, self.b),
                watch_once=fake_watch,
            )
        self.assertEqual([], calls)

    def test_unknown_or_missing_lane_fails_before_watch(self):
        calls = []

        def fake_watch(*args):
            calls.append(args)
            return {}

        with self.assertRaises(ValueError):
            run_workstream_attention_watch(
                [
                    {
                        "repo": "oimus1976/agent-controller",
                        "pr": 117,
                        "state_file": "a.json",
                        "workstream_id": "unknown",
                    }
                ],
                bindings=(self.a, self.b),
                watch_once=fake_watch,
            )
        with self.assertRaises(ValueError):
            run_workstream_attention_watch(
                [
                    {
                        "repo": "oimus1976/agent-controller",
                        "pr": 117,
                        "state_file": "a.json",
                    }
                ],
                bindings=(self.a, self.b),
                watch_once=fake_watch,
            )
        self.assertEqual([], calls)

    def test_overlapping_binding_set_fails_before_watch(self):
        calls = []
        overlap = WorkstreamBinding(
            workstream_id="bad-overlap",
            repo="oimus1976/agent-controller",
            root_work_item_ref="github:issue:999",
            github_prs=(119,),
        )

        def fake_watch(*args):
            calls.append(args)
            return {}

        with self.assertRaisesRegex(ValueError, "PR_BOUND_TO_MULTIPLE_WORKSTREAMS"):
            run_workstream_attention_watch(
                [
                    {
                        "repo": "oimus1976/agent-controller",
                        "pr": 119,
                        "state_file": "b.json",
                        "workstream_id": "closeout-rollout",
                    }
                ],
                bindings=(self.a, self.b, overlap),
                watch_once=fake_watch,
            )
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
