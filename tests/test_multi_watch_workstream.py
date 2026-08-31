import unittest

from agent_controller.multi_watch import run_attention_watch, validate_targets


class MultiWatchWorkstreamTests(unittest.TestCase):
    def test_lane_mode_requires_every_target_to_have_workstream_id(self):
        calls = []

        def fake_watch(*args):
            calls.append(args)
            return {}

        targets = [
            {
                "repo": "o/r",
                "pr": 1,
                "state_file": "a.json",
                "workstream_id": "lane-a",
            },
            {"repo": "o/r", "pr": 2, "state_file": "b.json"},
        ]
        with self.assertRaises(ValueError):
            run_attention_watch(targets, watch_once=fake_watch)
        self.assertEqual([], calls)

    def test_controller_owned_workstream_id_is_preserved_over_watch_output(self):
        def fake_watch(owner, repo, pr, state_file, scope_policy):
            return {
                "repo": f"{owner}/{repo}",
                "pr": pr,
                "workstream_id": "provider-guessed-lane",
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

        queue = run_attention_watch(
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
            ],
            watch_once=fake_watch,
        )
        self.assertEqual({"lane-a", "lane-b"}, {item["workstream_id"] for item in queue})

    def test_legacy_multi_watch_remains_compatible_without_lane_mode(self):
        validated = validate_targets(
            [
                {"repo": "o/r", "pr": 1, "state_file": "a.json"},
                {"repo": "o/r", "pr": 2, "state_file": "b.json"},
            ]
        )
        self.assertIsNone(validated[0]["workstream_id"])
        self.assertIsNone(validated[1]["workstream_id"])


if __name__ == "__main__":
    unittest.main()
