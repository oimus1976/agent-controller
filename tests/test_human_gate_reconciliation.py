import os
import tempfile
import unittest
from unittest.mock import patch

from agent_controller.attention_queue import AttentionCategory, classify_attention
from agent_controller.watcher import watch_pr_once


class HumanGateReconciliationTests(unittest.TestCase):
    def _attention(self, **overrides):
        observation = {
            "repo": "owner/repo",
            "pr": 7,
            "current_head_sha": "head-1",
            "current_classification": "REVIEW_READY",
            "current_draft": True,
            "current_merged": False,
            "current_state_enum": "open",
            "actions_ci_status": "PASS",
            "runtime_status": "OK",
            "transition": True,
            "transition_reasons": ["PR_STATE_CHANGED"],
        }
        observation.update(overrides)
        return classify_attention(observation)

    def test_closed_draft_without_merge_is_valid_done_state(self):
        item = self._attention(
            current_classification="CLOSED",
            current_draft=True,
            current_merged=False,
            current_state_enum="closed",
        )
        self.assertEqual(AttentionCategory.DONE, item.category)
        self.assertEqual("TARGET_CLOSED_WITHOUT_MERGE", item.reason)
        self.assertIsNone(item.human_action)

    def test_human_gate_advances_from_mark_ready_to_merge_from_fresh_state(self):
        mark_ready = self._attention(current_draft=True)
        merge = self._attention(current_draft=False)
        self.assertEqual("MARK_READY_FOR_REVIEW", mark_ready.human_action)
        self.assertEqual("MERGE", merge.human_action)

    @patch("agent_controller.watcher.inspect_pr")
    def test_watcher_exposes_fresh_authoritative_pr_state(self, mock_inspect):
        mock_inspect.return_value = {
            "head_sha": "head-1",
            "classification": "REVIEW_READY",
            "draft": False,
            "merged": False,
            "state": "open",
            "graphql_error": False,
            "actions_ci_status": "PASS",
            "check_runs_error": False,
            "scope_status": "SATISFIED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            state_file = os.path.join(tmp, "state.json")
            observation = watch_pr_once("owner", "repo", 7, state_file)
        self.assertFalse(observation["current_draft"])
        self.assertFalse(observation["current_merged"])
        self.assertEqual("open", observation["current_state_enum"])

    @patch("agent_controller.watcher.inspect_pr")
    def test_inspection_failure_does_not_reuse_stale_state_for_human_action(self, mock_inspect):
        mock_inspect.side_effect = RuntimeError("network unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            state_file = os.path.join(tmp, "state.json")
            with open(state_file, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"head_sha":"head-1","classification":"REVIEW_READY",'
                    '"draft":false,"merged":false,"state_enum":"open",'
                    '"graphql_error":false,"actions_ci_status":"PASS",'
                    '"check_runs_error":false,"scope_status":"SATISFIED"}'
                )
            observation = watch_pr_once("owner", "repo", 7, state_file)
        self.assertEqual("EVIDENCE_UNAVAILABLE", observation["runtime_status"])
        self.assertIsNone(observation["current_draft"])
        self.assertIsNone(observation["current_merged"])
        self.assertIsNone(observation["current_state_enum"])
        item = classify_attention(observation)
        self.assertEqual(AttentionCategory.NEEDS_ATTENTION, item.category)
        self.assertIsNone(item.human_action)


if __name__ == "__main__":
    unittest.main()
