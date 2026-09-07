from pathlib import Path
import json
import unittest

from agent_controller.antigravity_review import (
    AntigravityReviewEvidence,
    AntigravityReviewStatus,
    classify_antigravity_review,
    parse_antigravity_stream_json,
)


FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_WORKSPACE = r"C:\fixture\repo"
EXPECTED_SHA = "5f78ba0c1bbedbeb0f11463861c621e6b2d5a372"
EXPECTED_REVIEW_INPUT_SHA256 = (
    "C72C6CE7B21B0CBB9A1AD37D8E6CE8129FD2C3509E5408B9D5CCD25DE95ACAAC"
)
OTHER_REVIEW_INPUT_SHA256 = "0" * 64


def load_fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def parse(lines, *, expected_workspace=FIXTURE_WORKSPACE):
    return parse_antigravity_stream_json(
        lines,
        expected_workspace=expected_workspace,
    )


def success_stream():
    return parse(load_fixture("antigravity_review_success.jsonl"))


def tool_event(tool_name, path_parameter, path_value):
    return json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "conversation_id": "c1",
                "step_index": 1,
                "state": "ACTIVE",
                "step_type": "tool",
                "tool_name": tool_name,
                "tool_info": {
                    "name": tool_name,
                    "parameters": {path_parameter: path_value},
                },
            },
        },
        separators=(",", ":"),
    )


def result_event():
    return (
        '{"event":"result","result":{"conversation_id":"c1",'
        '"status":"SUCCESS","response":"NO_FINDINGS","denied_actions":[]}}'
    )


def evidence(**overrides):
    values = {
        "expected_reviewed_sha": EXPECTED_SHA,
        "before_head_sha": EXPECTED_SHA,
        "after_head_sha": EXPECTED_SHA,
        "expected_review_input_sha256": EXPECTED_REVIEW_INPUT_SHA256,
        "before_review_input_sha256": EXPECTED_REVIEW_INPUT_SHA256,
        "after_review_input_sha256": EXPECTED_REVIEW_INPUT_SHA256,
        "process_exit_code": 0,
        "stream_result": success_stream(),
        "before_tracked_delta": (),
        "after_tracked_delta": (),
        "before_untracked": ("review-input.diff",),
        "after_untracked": ("review-input.diff",),
    }
    values.update(overrides)
    return AntigravityReviewEvidence(**values)


class AntigravityStreamParserTests(unittest.TestCase):
    def test_characterized_success_fixture_preserves_provider_evidence(self):
        result = success_stream()
        self.assertEqual(result.conversation_id, "fixture-review-1")
        self.assertEqual(result.top_level_status, "SUCCESS")
        self.assertEqual(result.response, "NO_FINDINGS")
        self.assertEqual(result.denied_actions, ())
        self.assertEqual(result.event_count, 13)

    def test_denied_action_can_coexist_with_top_level_success(self):
        result = parse(load_fixture("antigravity_review_denied_success.jsonl"))
        self.assertEqual(result.top_level_status, "SUCCESS")
        self.assertEqual(result.response, "")
        self.assertEqual(len(result.denied_actions), 1)
        self.assertEqual(result.denied_actions[0].action, "write_file")

    def test_expected_workspace_must_be_absolute_windows_path(self):
        with self.assertRaisesRegex(ValueError, "absolute Windows path"):
            parse(
                ['{"event":"init","conversation_id":"c1","init":{}}'],
                expected_workspace="relative/repo",
            )

    def test_malformed_stream_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "malformed Antigravity stream-json"):
            parse(["{not-json}"])

    def test_missing_terminal_result_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing terminal result"):
            parse(['{"event":"init","conversation_id":"c1","init":{}}'])

    def test_missing_init_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "first Antigravity stream event must be init"):
            parse([result_event()])

    def test_conversation_identity_change_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "conversation identity changed"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    '{"event":"result","result":{"conversation_id":"c2",'
                    '"status":"SUCCESS","response":"NO_FINDINGS",'
                    '"denied_actions":[]}}',
                ]
            )

    def test_step_update_conversation_identity_change_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "conversation identity changed"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    '{"event":"step_update","step_update":{"conversation_id":"c2",'
                    '"step_index":1,"state":"DONE","step_type":"agent_response"}}',
                    result_event(),
                ]
            )

    def test_event_after_terminal_result_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "events after terminal result are not allowed"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    result_event(),
                    '{"event":"step_update","step_update":{"conversation_id":"c1",'
                    '"step_index":2,"state":"DONE","step_type":"agent_response"}}',
                ]
            )

    def test_unknown_event_fails_closed_even_if_result_would_succeed(self):
        with self.assertRaisesRegex(ValueError, "unsupported Antigravity review event"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    '{"event":"tool_call","tool_call":{"name":"write_to_file",'
                    '"status":"SUCCESS"}}',
                    result_event(),
                ]
            )

    def test_non_characterized_step_type_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported Antigravity review step type"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    '{"event":"step_update","step_update":{"conversation_id":"c1",'
                    '"step_index":1,"state":"DONE","step_type":"question"}}',
                    result_event(),
                ]
            )

    def test_forbidden_tool_steps_fail_closed(self):
        for tool_name in ("write_to_file", "browser_subagent", "invoke_subagent", "run_command"):
            with self.subTest(tool_name=tool_name):
                forbidden = json.dumps(
                    {
                        "event": "step_update",
                        "step_update": {
                            "conversation_id": "c1",
                            "step_index": 1,
                            "state": "ACTIVE",
                            "step_type": "tool",
                            "tool_name": tool_name,
                            "tool_info": {"name": tool_name, "parameters": {}},
                        },
                    },
                    separators=(",", ":"),
                )
                with self.assertRaisesRegex(ValueError, "unsupported Antigravity review tool"):
                    parse(
                        [
                            '{"event":"init","conversation_id":"c1","init":{}}',
                            forbidden,
                            result_event(),
                        ]
                    )

    def test_tool_identity_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "tool identity changed"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    '{"event":"step_update","step_update":{"conversation_id":"c1",'
                    '"step_index":1,"state":"ACTIVE","step_type":"tool",'
                    '"tool_name":"view_file","tool_info":{"name":"list_dir",'
                    '"parameters":{"AbsolutePath":"C:/fixture/repo/file.txt"}}}}',
                    result_event(),
                ]
            )

    def test_each_characterized_read_tool_accepts_workspace_descendant(self):
        cases = (
            ("find_by_name", "SearchDirectory", r"C:\fixture\repo\tests"),
            ("view_file", "AbsolutePath", r"C:\fixture\repo\README.md"),
            ("grep_search", "SearchPath", r"C:\fixture\repo\agent_controller"),
            ("list_dir", "DirectoryPath", r"C:\fixture\repo"),
        )
        for tool_name, parameter, target in cases:
            with self.subTest(tool_name=tool_name):
                result = parse(
                    [
                        '{"event":"init","conversation_id":"c1","init":{}}',
                        tool_event(tool_name, parameter, target),
                        result_event(),
                    ]
                )
                self.assertEqual(result.top_level_status, "SUCCESS")

    def test_each_characterized_read_tool_rejects_workspace_escape(self):
        cases = (
            ("find_by_name", "SearchDirectory"),
            ("view_file", "AbsolutePath"),
            ("grep_search", "SearchPath"),
            ("list_dir", "DirectoryPath"),
        )
        for tool_name, parameter in cases:
            for target in (
                r"C:\fixture\outside",
                r"C:\fixture\repo\..\outside",
                r"D:\fixture\repo",
            ):
                with self.subTest(tool_name=tool_name, target=target):
                    with self.assertRaisesRegex(ValueError, "within the expected workspace"):
                        parse(
                            [
                                '{"event":"init","conversation_id":"c1","init":{}}',
                                tool_event(tool_name, parameter, target),
                                result_event(),
                            ]
                        )

    def test_read_tool_rejects_relative_or_missing_path_parameter(self):
        with self.assertRaisesRegex(ValueError, "absolute Windows path"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    tool_event("view_file", "AbsolutePath", "review-input.diff"),
                    result_event(),
                ]
            )
        missing = json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "conversation_id": "c1",
                    "step_index": 1,
                    "state": "ACTIVE",
                    "step_type": "tool",
                    "tool_name": "view_file",
                    "tool_info": {"name": "view_file", "parameters": {}},
                },
            },
            separators=(",", ":"),
        )
        with self.assertRaisesRegex(ValueError, "must be a nonempty string"):
            parse(
                [
                    '{"event":"init","conversation_id":"c1","init":{}}',
                    missing,
                    result_event(),
                ]
            )


class AntigravityReviewClassifierTests(unittest.TestCase):
    def test_exact_sha_review_with_no_mutation_passes(self):
        decision = classify_antigravity_review(evidence())
        self.assertEqual(decision.status, AntigravityReviewStatus.PASS)
        self.assertEqual(
            decision.reason_codes,
            ("EXACT_SHA_REVIEW_COMPLETE_NO_MUTATION",),
        )

    def test_same_frozen_evidence_is_deterministic(self):
        item = evidence()
        first = classify_antigravity_review(item)
        second = classify_antigravity_review(item)
        self.assertEqual(first, second)

    def test_denied_action_blocks_despite_top_level_success_and_exit_zero(self):
        stream = parse(load_fixture("antigravity_review_denied_success.jsonl"))
        decision = classify_antigravity_review(evidence(stream_result=stream))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("DENIED_ACTION_PRESENT", decision.reason_codes)
        self.assertIn("EMPTY_REVIEW_RESPONSE", decision.reason_codes)

    def test_empty_response_blocks(self):
        stream = success_stream()
        empty = type(stream)(
            conversation_id=stream.conversation_id,
            top_level_status=stream.top_level_status,
            response="   ",
            denied_actions=stream.denied_actions,
            event_count=stream.event_count,
        )
        decision = classify_antigravity_review(evidence(stream_result=empty))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("EMPTY_REVIEW_RESPONSE", decision.reason_codes)

    def test_nonzero_exit_blocks(self):
        decision = classify_antigravity_review(evidence(process_exit_code=1))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("PROCESS_EXIT_NONZERO", decision.reason_codes)

    def test_provider_status_must_be_success(self):
        stream = success_stream()
        failed = type(stream)(
            conversation_id=stream.conversation_id,
            top_level_status="ERROR",
            response=stream.response,
            denied_actions=stream.denied_actions,
            event_count=stream.event_count,
        )
        decision = classify_antigravity_review(evidence(stream_result=failed))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("PROVIDER_STATUS_NOT_SUCCESS", decision.reason_codes)

    def test_start_sha_mismatch_blocks(self):
        decision = classify_antigravity_review(evidence(before_head_sha="other"))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("START_SHA_MISMATCH", decision.reason_codes)

    def test_end_sha_mismatch_and_head_mutation_block(self):
        decision = classify_antigravity_review(evidence(after_head_sha="other"))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("END_SHA_MISMATCH", decision.reason_codes)
        self.assertIn("HEAD_MUTATED", decision.reason_codes)

    def test_review_input_digest_mismatch_blocks_even_when_head_matches(self):
        decision = classify_antigravity_review(
            evidence(before_review_input_sha256=OTHER_REVIEW_INPUT_SHA256)
        )
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("START_REVIEW_INPUT_DIGEST_MISMATCH", decision.reason_codes)

    def test_review_input_mutation_blocks(self):
        decision = classify_antigravity_review(
            evidence(after_review_input_sha256=OTHER_REVIEW_INPUT_SHA256)
        )
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("END_REVIEW_INPUT_DIGEST_MISMATCH", decision.reason_codes)
        self.assertIn("REVIEW_INPUT_MUTATED", decision.reason_codes)

    def test_malformed_review_input_digest_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 digest"):
            classify_antigravity_review(evidence(expected_review_input_sha256="not-a-digest"))

    def test_tracked_baseline_mutation_blocks(self):
        decision = classify_antigravity_review(
            evidence(after_tracked_delta=("M agent_controller/example.py",))
        )
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("TRACKED_BASELINE_MUTATED", decision.reason_codes)

    def test_untracked_baseline_mutation_blocks(self):
        decision = classify_antigravity_review(
            evidence(after_untracked=("review-input.diff", "unexpected.txt"))
        )
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("UNTRACKED_BASELINE_MUTATED", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
