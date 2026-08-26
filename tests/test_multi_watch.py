import unittest

from agent_controller.multi_watch import run_attention_watch, validate_targets


class MultiWatchTests(unittest.TestCase):
    def test_validates_all_targets_before_first_watch_call(self):
        calls = []

        def fake_watch(owner, repo, pr, state_file, scope_policy):
            calls.append((owner, repo, pr))
            return _observation(f"{owner}/{repo}", pr)

        targets = [
            {"repo": "owner/good", "pr": 1, "state_file": "good.json"},
            {"repo": "bad-shape", "pr": 2, "state_file": "bad.json"},
        ]
        with self.assertRaises(ValueError):
            run_attention_watch(targets, watch_once=fake_watch)
        self.assertEqual([], calls)

    def test_each_valid_target_is_watched_once_and_queue_is_prioritized(self):
        calls = []

        def fake_watch(owner, repo, pr, state_file, scope_policy):
            calls.append((owner, repo, pr, state_file, scope_policy))
            if pr == 2:
                return _observation(
                    f"{owner}/{repo}",
                    pr,
                    classification="REVIEW_READY",
                )
            return _observation(f"{owner}/{repo}", pr)

        targets = [
            {"repo": "z/repo", "pr": 1, "state_file": "z.json"},
            {
                "repo": "a/repo",
                "pr": 2,
                "state_file": "a.json",
                "allowed_paths": ["src/**"],
                "denied_paths": ["secrets/**"],
                "allow_docs_only": True,
            },
        ]
        queue = run_attention_watch(targets, watch_once=fake_watch)

        self.assertEqual(2, len(calls))
        self.assertEqual("HUMAN_ACTION", queue[0]["category"])
        self.assertEqual("a/repo", queue[0]["repo"])
        self.assertEqual("IN_PROGRESS", queue[1]["category"])
        self.assertEqual(["src/**"], calls[1][4]["allowed_paths"])
        self.assertTrue(calls[1][4]["allow_docs_only"])

    def test_evidence_unavailable_target_does_not_hide_other_targets(self):
        def fake_watch(owner, repo, pr, state_file, scope_policy):
            if pr == 1:
                return _observation(
                    f"{owner}/{repo}",
                    pr,
                    runtime_status="EVIDENCE_UNAVAILABLE",
                )
            return _observation(
                f"{owner}/{repo}",
                pr,
                classification="REVIEW_READY",
            )

        queue = run_attention_watch(
            [
                {"repo": "a/repo", "pr": 1, "state_file": "a.json"},
                {"repo": "b/repo", "pr": 2, "state_file": "b.json"},
            ],
            watch_once=fake_watch,
        )
        self.assertEqual(2, len(queue))
        self.assertEqual("HUMAN_ACTION", queue[0]["category"])
        self.assertEqual("NEEDS_ATTENTION", queue[1]["category"])

    def test_validation_rejects_bad_optional_types(self):
        with self.assertRaises(TypeError):
            validate_targets(
                [{"repo": "a/repo", "pr": 1, "state_file": "a.json", "allowed_paths": "src/**"}]
            )
        with self.assertRaises(ValueError):
            validate_targets(
                [{"repo": "a/repo", "pr": 1, "state_file": "a.json", "allow_docs_only": "yes"}]
            )


def _observation(
    repo,
    pr,
    *,
    classification="IMPLEMENTATION_READY",
    runtime_status="OK",
):
    return {
        "repo": repo,
        "pr": pr,
        "current_head_sha": f"sha-{pr}",
        "current_classification": classification,
        "runtime_status": runtime_status,
        "transition": True,
        "transition_reasons": ["CLASSIFICATION_CHANGED"],
    }


if __name__ == "__main__":
    unittest.main()
