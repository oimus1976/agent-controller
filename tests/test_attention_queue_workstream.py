import unittest

from agent_controller.attention_queue import (
    AttentionCategory,
    build_attention_queue,
    select_attention_for_workstream,
)


def _observation(workstream_id, pr, classification, *, draft=False, merged=False, state="open"):
    head_sha = f"{pr:040x}"
    value = {
        "repo": "oimus1976/agent-controller",
        "pr": pr,
        "workstream_id": workstream_id,
        "current_head_sha": head_sha,
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
    if classification == "REVIEW_READY":
        value["canonical_review_evidence"] = {
            "schema": "agent-controller/review-evidence/v1",
            "repo": "oimus1976/agent-controller",
            "pr": pr,
            "observed_head_sha": head_sha,
            "collection_complete": True,
            "verdict": "CLEAN",
            "surfaces": [
                {"surface": name, "status": "COMPLETE", "pagination_exhausted": True, "error": None}
                for name in ("formal_reviews", "issue_comments", "inline_threads", "reactions")
            ],
            "provider_reviews": [],
            "errors": [],
        }
    return value


class AttentionQueueWorkstreamTests(unittest.TestCase):
    def test_unbound_legacy_item_is_not_selected_into_named_lane(self):
        unbound = _observation("lane-a", 1, "IMPLEMENTATION_READY")
        unbound.pop("workstream_id")
        queue = build_attention_queue([unbound])
        self.assertIsNone(queue[0].workstream_id)
        self.assertEqual((), select_attention_for_workstream(queue, "lane-a"))

    def test_global_human_action_priority_does_not_override_lane_selection(self):
        queue = build_attention_queue(
            [
                _observation("lane-a", 117, "CLOSED", merged=True, state="closed"),
                _observation("lane-b", 119, "REVIEW_READY", draft=True),
            ]
        )
        self.assertEqual(119, queue[0].pr)
        self.assertEqual(AttentionCategory.HUMAN_ACTION, queue[0].category)
        lane_a = select_attention_for_workstream(queue, "lane-a")
        self.assertEqual([117], [item.pr for item in lane_a])
        self.assertEqual(AttentionCategory.DONE, lane_a[0].category)

    def test_malformed_workstream_identity_fails_closed(self):
        bad = _observation("lane-a", 1, "IMPLEMENTATION_READY")
        bad["workstream_id"] = ""
        with self.assertRaises(ValueError):
            build_attention_queue([bad])


if __name__ == "__main__":
    unittest.main()
