import unittest

from agent_controller.attention_queue import (
    AttentionCategory,
    build_attention_queue,
    classify_attention,
)


def observation(
    *,
    repo="oimus1976/agent-controller",
    pr=1,
    classification="IMPLEMENTATION_READY",
    runtime_status="OK",
    transition=True,
    reasons=("CLASSIFICATION_CHANGED",),
    head_sha="abc123",
    actions_ci_status=None,
):
    result = {
        "repo": repo,
        "pr": pr,
        "current_head_sha": head_sha,
        "current_classification": classification,
        "runtime_status": runtime_status,
        "transition": transition,
        "transition_reasons": list(reasons),
    }
    if actions_ci_status is not None:
        result["actions_ci_status"] = actions_ci_status
    return result


class AttentionQueueTests(unittest.TestCase):
    def test_review_ready_is_human_action_not_authorization(self):
        item = classify_attention(observation(classification="REVIEW_READY", actions_ci_status="PASS"))
        self.assertEqual(AttentionCategory.HUMAN_ACTION, item.category)
        self.assertEqual("VERIFIED_REVIEW_READY_HUMAN_GATE_CANDIDATE", item.reason)

    def test_pending_ci_is_in_progress_not_human_attention(self):
        item = classify_attention(
            observation(classification="NEEDS_REVIEW", actions_ci_status="PENDING")
        )
        self.assertEqual(AttentionCategory.IN_PROGRESS, item.category)
        self.assertEqual("CI_RUNNING_FOR_EXACT_HEAD", item.reason)

    def test_invalid_ci_status_is_rejected(self):
        with self.assertRaises(ValueError):
            classify_attention(observation(actions_ci_status="MAYBE"))

    def test_evidence_unavailable_never_becomes_done_or_safe(self):
        item = classify_attention(
            observation(
                classification="CLOSED",
                runtime_status="EVIDENCE_UNAVAILABLE",
            )
        )
        self.assertEqual(AttentionCategory.NEEDS_ATTENTION, item.category)

    def test_closed_is_done_when_runtime_evidence_is_valid(self):
        item = classify_attention(observation(classification="CLOSED"))
        self.assertEqual(AttentionCategory.DONE, item.category)

    def test_implementation_ready_transition_is_in_progress(self):
        item = classify_attention(observation(classification="IMPLEMENTATION_READY"))
        self.assertEqual(AttentionCategory.IN_PROGRESS, item.category)

    def test_stable_implementation_ready_is_no_change(self):
        item = classify_attention(
            observation(classification="IMPLEMENTATION_READY", transition=False, reasons=())
        )
        self.assertEqual(AttentionCategory.NO_CHANGE, item.category)

    def test_needs_review_requires_attention_even_when_stable(self):
        item = classify_attention(
            observation(classification="NEEDS_REVIEW", transition=False, reasons=())
        )
        self.assertEqual(AttentionCategory.NEEDS_ATTENTION, item.category)

    def test_unknown_classification_fails_closed_to_attention(self):
        item = classify_attention(observation(classification="NEW_PROVIDER_STATE"))
        self.assertEqual(AttentionCategory.NEEDS_ATTENTION, item.category)

    def test_queue_is_stable_and_human_action_first(self):
        observations = [
            observation(repo="z/repo", pr=2, classification="CLOSED"),
            observation(repo="b/repo", pr=5, classification="NEEDS_REVIEW"),
            observation(repo="a/repo", pr=3, classification="REVIEW_READY"),
            observation(repo="a/repo", pr=1, classification="REVIEW_READY"),
            observation(repo="x/repo", pr=1, classification="IMPLEMENTATION_READY"),
        ]
        first = build_attention_queue(observations)
        second = build_attention_queue(observations)
        self.assertEqual(first, second)
        self.assertEqual(
            [
                AttentionCategory.HUMAN_ACTION,
                AttentionCategory.HUMAN_ACTION,
                AttentionCategory.NEEDS_ATTENTION,
                AttentionCategory.IN_PROGRESS,
                AttentionCategory.DONE,
            ],
            [item.category for item in first],
        )
        self.assertEqual([1, 3], [first[0].pr, first[1].pr])

    def test_invalid_core_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            classify_attention(observation(repo=""))
        with self.assertRaises(ValueError):
            classify_attention(observation(pr=0))
        bad = observation()
        bad["transition"] = "yes"
        with self.assertRaises(ValueError):
            classify_attention(bad)


if __name__ == "__main__":
    unittest.main()
