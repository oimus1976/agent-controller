import os
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
                    draft=True,
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
        self.assertEqual("MARK_READY_FOR_REVIEW", queue[0]["human_action"])
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
                    draft=None,
                    merged=None,
                    state=None,
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
        self.assertEqual("MERGE", queue[0]["human_action"])
        self.assertEqual("NEEDS_ATTENTION", queue[1]["category"])
        self.assertIsNone(queue[1]["human_action"])

    def test_validation_rejects_bad_optional_types(self):
        with self.assertRaises(TypeError):
            validate_targets(
                [{"repo": "a/repo", "pr": 1, "state_file": "a.json", "allowed_paths": "src/**"}]
            )
        with self.assertRaises(ValueError):
            validate_targets(
                [{"repo": "a/repo", "pr": 1, "state_file": "a.json", "allow_docs_only": "yes"}]
            )

    def test_unknown_keys_fail_closed_before_watch(self):
        calls = []

        def fake_watch(*args):
            calls.append(args)
            return _observation("a/repo", 1)

        targets = [
            {
                "repo": "a/repo",
                "pr": 1,
                "state_file": "a.json",
                "deneid_paths": ["secrets/**"],
            }
        ]
        with self.assertRaises(ValueError):
            run_attention_watch(targets, watch_once=fake_watch)
        self.assertEqual([], calls)

    def test_duplicate_repo_pr_fails_closed_before_watch(self):
        calls = []

        def fake_watch(*args):
            calls.append(args)
            return _observation("a/repo", 1)

        targets = [
            {"repo": "a/repo", "pr": 1, "state_file": "one.json"},
            {"repo": "A/REPO", "pr": 1, "state_file": "two.json"},
        ]
        with self.assertRaises(ValueError):
            run_attention_watch(targets, watch_once=fake_watch)
        self.assertEqual([], calls)

    def test_state_file_alias_fails_closed_before_watch(self):
        calls = []

        def fake_watch(*args):
            calls.append(args)
            return _observation("a/repo", 1)

        shared = os.path.join("state", "pr.json")
        alias = os.path.join("state", ".", "pr.json")
        targets = [
            {"repo": "a/repo", "pr": 1, "state_file": shared},
            {"repo": "b/repo", "pr": 2, "state_file": alias},
        ]
        with self.assertRaises(ValueError):
            run_attention_watch(targets, watch_once=fake_watch)
        self.assertEqual([], calls)


def _observation(
    repo,
    pr,
    *,
    classification="IMPLEMENTATION_READY",
    runtime_status="OK",
    draft=False,
    merged=False,
    state="open",
):
    return {
        "repo": repo,
        "pr": pr,
        "current_head_sha": f"sha-{pr}",
        "current_classification": classification,
        "current_draft": draft,
        "current_merged": merged,
        "current_state_enum": state,
        "runtime_status": runtime_status,
        "transition": True,
        "transition_reasons": ["CLASSIFICATION_CHANGED"],
    }


if __name__ == "__main__":
    unittest.main()
