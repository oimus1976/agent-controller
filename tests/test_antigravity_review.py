from pathlib import Path
import json
import ntpath
import unittest

from agent_controller.antigravity_review import (
    AntigravityReviewEvidence,
    AntigravityReviewStatus,
    AntigravityStreamResult,
    classify_antigravity_review,
    parse_antigravity_stream_json,
)


FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_WORKSPACE = r"C:\fixture\repo"
EXPECTED_SHA = "5f78ba0c1bbedbeb0f11463861c621e6b2d5a372"
OTHER_SHA = "0" * 40
EXPECTED_REVIEW_INPUT_SHA256 = (
    "C72C6CE7B21B0CBB9A1AD37D8E6CE8129FD2C3509E5408B9D5CCD25DE95ACAAC"
)
OTHER_REVIEW_INPUT_SHA256 = "0" * 64


def load_fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


def lexical_resolver(path):
    return path


def parse(lines, *, expected_workspace=FIXTURE_WORKSPACE, resolver=lexical_resolver):
    return parse_antigravity_stream_json(
        lines,
        expected_workspace=expected_workspace,
        canonical_path_resolver=resolver,
    )


def init_event(*, cwd=FIXTURE_WORKSPACE, conversation_id="c1"):
    return json.dumps(
        {
            "event": "init",
            "conversation_id": conversation_id,
            "init": {"cwd": cwd},
        },
        separators=(",", ":"),
    )


def result_event(*, conversation_id="c1", include_denied_actions=True):
    result = {
        "conversation_id": conversation_id,
        "status": "SUCCESS",
        "response": "NO_FINDINGS",
    }
    if include_denied_actions:
        result["denied_actions"] = []
    return json.dumps({"event": "result", "result": result}, separators=(",", ":"))


def step_event(step_type, *, step_index=0, state="DONE", **extra):
    payload = {
        "conversation_id": "c1",
        "step_index": step_index,
        "state": state,
        "step_type": step_type,
    }
    payload.update(extra)
    return json.dumps(
        {"event": "step_update", "step_update": payload},
        separators=(",", ":"),
    )


def tool_event(tool_name, path_parameter, path_value, *, step_index=0, state="ACTIVE"):
    return step_event(
        "tool",
        step_index=step_index,
        state=state,
        tool_name=tool_name,
        tool_info={
            "name": tool_name,
            "parameters": {path_parameter: path_value},
        },
    )


def tool_pair(tool_name, path_parameter, path_value, *, step_index=0):
    return (
        tool_event(
            tool_name,
            path_parameter,
            path_value,
            step_index=step_index,
            state="ACTIVE",
        ),
        tool_event(
            tool_name,
            path_parameter,
            path_value,
            step_index=step_index,
            state="DONE",
        ),
    )


def success_stream():
    return parse(load_fixture("antigravity_review_success.jsonl"))


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

    def test_denied_actions_evidence_is_required(self):
        with self.assertRaisesRegex(ValueError, "denied_actions evidence is required"):
            parse([init_event(), result_event(include_denied_actions=False)])

    def test_expected_workspace_must_be_absolute_windows_path(self):
        with self.assertRaisesRegex(ValueError, "absolute Windows path"):
            parse([init_event()], expected_workspace="relative/repo")

    def test_init_cwd_must_equal_expected_workspace(self):
        with self.assertRaisesRegex(ValueError, "init cwd must equal the expected workspace"):
            parse([init_event(cwd=r"C:\fixture\outside"), result_event()])

    def test_init_cwd_is_required_and_absolute(self):
        missing_cwd = json.dumps(
            {"event": "init", "conversation_id": "c1", "init": {}},
            separators=(",", ":"),
        )
        with self.assertRaisesRegex(ValueError, "must be a nonempty string"):
            parse([missing_cwd, result_event()])
        with self.assertRaisesRegex(ValueError, "absolute Windows path"):
            parse([init_event(cwd="relative/repo"), result_event()])

    def test_canonical_resolver_failure_fails_closed(self):
        def failing_resolver(_):
            raise OSError("cannot resolve")

        with self.assertRaisesRegex(ValueError, "canonical resolution failed"):
            parse([init_event(), result_event()], resolver=failing_resolver)

    def test_malformed_stream_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "malformed Antigravity stream-json"):
            parse(["{not-json}"])

    def test_missing_terminal_result_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing terminal result"):
            parse([init_event()])

    def test_missing_init_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "first Antigravity stream event must be init"):
            parse([result_event()])

    def test_conversation_identity_change_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "conversation identity changed"):
            parse([init_event(), result_event(conversation_id="c2")])

    def test_step_update_conversation_identity_change_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "conversation identity changed"):
            parse(
                [
                    init_event(),
                    json.dumps(
                        {
                            "event": "step_update",
                            "step_update": {
                                "conversation_id": "c2",
                                "step_index": 0,
                                "state": "DONE",
                                "step_type": "agent_response",
                            },
                        }
                    ),
                    result_event(),
                ]
            )

    def test_event_after_terminal_result_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "events after terminal result are not allowed"):
            parse([init_event(), result_event(), step_event("agent_response", step_index=0)])

    def test_unknown_event_fails_closed_even_if_result_would_succeed(self):
        with self.assertRaisesRegex(ValueError, "unsupported Antigravity review event"):
            parse(
                [
                    init_event(),
                    '{"event":"tool_call","tool_call":{"name":"write_to_file",'
                    '"status":"SUCCESS"}}',
                    result_event(),
                ]
            )

    def test_non_characterized_step_type_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported Antigravity review step type"):
            parse([init_event(), step_event("question"), result_event()])

    def test_missing_or_unknown_step_state_fails_closed(self):
        missing_state = json.dumps(
            {
                "event": "step_update",
                "step_update": {
                    "conversation_id": "c1",
                    "step_index": 0,
                    "step_type": "agent_response",
                },
            },
            separators=(",", ":"),
        )
        with self.assertRaisesRegex(ValueError, "state must be a nonempty string"):
            parse([init_event(), missing_state, result_event()])
        with self.assertRaisesRegex(ValueError, "unsupported Antigravity review step state"):
            parse([init_event(), step_event("agent_response", state="UNKNOWN"), result_event()])

    def test_non_tool_step_cannot_disguise_forbidden_tool_metadata(self):
        disguised = step_event(
            "agent_response",
            tool_name="run_command",
            tool_info={"name": "run_command", "parameters": {}},
        )
        with self.assertRaisesRegex(ValueError, "non-tool step must not contain tool metadata"):
            parse([init_event(), disguised, result_event()])

    def test_step_indices_must_be_contiguous_from_zero(self):
        with self.assertRaisesRegex(ValueError, "indices must be contiguous from zero"):
            parse(
                [
                    init_event(),
                    step_event("agent_response", step_index=0),
                    step_event("agent_response", step_index=2),
                    result_event(),
                ]
            )

    def test_active_tool_must_finish_before_result(self):
        active = tool_event(
            "view_file", "AbsolutePath", r"C:\fixture\repo\README.md", state="ACTIVE"
        )
        with self.assertRaisesRegex(ValueError, "active tool step"):
            parse([init_event(), active, result_event()])

    def test_tool_done_requires_matching_active(self):
        done = tool_event(
            "view_file", "AbsolutePath", r"C:\fixture\repo\README.md", state="DONE"
        )
        with self.assertRaisesRegex(ValueError, "DONE must match a preceding ACTIVE"):
            parse([init_event(), done, result_event()])

    def test_forbidden_tool_steps_fail_closed(self):
        for tool_name in ("write_to_file", "browser_subagent", "invoke_subagent", "run_command"):
            with self.subTest(tool_name=tool_name):
                forbidden = step_event(
                    "tool",
                    state="ACTIVE",
                    tool_name=tool_name,
                    tool_info={"name": tool_name, "parameters": {}},
                )
                with self.assertRaisesRegex(ValueError, "unsupported Antigravity review tool"):
                    parse([init_event(), forbidden, result_event()])

    def test_tool_identity_mismatch_fails_closed(self):
        mismatch = step_event(
            "tool",
            state="ACTIVE",
            tool_name="view_file",
            tool_info={
                "name": "list_dir",
                "parameters": {"AbsolutePath": r"C:\fixture\repo\file.txt"},
            },
        )
        with self.assertRaisesRegex(ValueError, "tool identity changed"):
            parse([init_event(), mismatch, result_event()])

    def test_each_characterized_read_tool_accepts_workspace_descendant(self):
        cases = (
            ("find_by_name", "SearchDirectory", r"C:\fixture\repo\tests"),
            ("view_file", "AbsolutePath", r"C:\fixture\repo\README.md"),
            ("grep_search", "SearchPath", r"C:\fixture\repo\agent_controller"),
            ("list_dir", "DirectoryPath", r"C:\fixture\repo"),
        )
        for tool_name, parameter, target in cases:
            with self.subTest(tool_name=tool_name):
                active, done = tool_pair(tool_name, parameter, target)
                result = parse([init_event(), active, done, result_event()])
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
                        parse([init_event(), tool_event(tool_name, parameter, target), result_event()])

    def test_canonical_resolution_blocks_in_workspace_junction_escape(self):
        junction = ntpath.normcase(ntpath.normpath(r"C:\fixture\repo\junction"))

        def junction_resolver(path):
            normalized = ntpath.normcase(ntpath.normpath(path))
            if normalized == junction or normalized.startswith(junction + "\\"):
                suffix = normalized[len(junction):].lstrip("\\")
                outside = ntpath.normcase(ntpath.normpath(r"C:\fixture\outside"))
                return ntpath.join(outside, suffix) if suffix else outside
            return normalized

        with self.assertRaisesRegex(ValueError, "within the expected workspace"):
            parse(
                [
                    init_event(),
                    tool_event(
                        "view_file",
                        "AbsolutePath",
                        r"C:\fixture\repo\junction\secret.txt",
                    ),
                    result_event(),
                ],
                resolver=junction_resolver,
            )

    def test_read_tool_rejects_relative_or_missing_path_parameter(self):
        with self.assertRaisesRegex(ValueError, "absolute Windows path"):
            parse(
                [
                    init_event(),
                    tool_event("view_file", "AbsolutePath", "review-input.diff"),
                    result_event(),
                ]
            )
        missing = step_event(
            "tool",
            state="ACTIVE",
            tool_name="view_file",
            tool_info={"name": "view_file", "parameters": {}},
        )
        with self.assertRaisesRegex(ValueError, "must be a nonempty string"):
            parse([init_event(), missing, result_event()])


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
        self.assertEqual(
            classify_antigravity_review(item),
            classify_antigravity_review(item),
        )

    def test_denied_action_blocks_despite_top_level_success_and_exit_zero(self):
        stream = parse(load_fixture("antigravity_review_denied_success.jsonl"))
        decision = classify_antigravity_review(evidence(stream_result=stream))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("DENIED_ACTION_PRESENT", decision.reason_codes)
        self.assertIn("EMPTY_REVIEW_RESPONSE", decision.reason_codes)

    def test_empty_response_blocks(self):
        stream = success_stream()
        empty = AntigravityStreamResult(
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
        failed = AntigravityStreamResult(
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
        decision = classify_antigravity_review(evidence(before_head_sha=OTHER_SHA))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("START_SHA_MISMATCH", decision.reason_codes)

    def test_end_sha_mismatch_and_head_mutation_block(self):
        decision = classify_antigravity_review(evidence(after_head_sha=OTHER_SHA))
        self.assertEqual(decision.status, AntigravityReviewStatus.BLOCKED)
        self.assertIn("END_SHA_MISMATCH", decision.reason_codes)
        self.assertIn("HEAD_MUTATED", decision.reason_codes)

    def test_malformed_or_abbreviated_git_sha_fails_closed(self):
        for bad_sha in ("x", "a99b16cb0d", "g" * 40, "a" * 39, "a" * 41):
            with self.subTest(bad_sha=bad_sha):
                with self.assertRaisesRegex(ValueError, "full 40-character hexadecimal Git object ID"):
                    classify_antigravity_review(
                        evidence(
                            expected_reviewed_sha=bad_sha,
                            before_head_sha=bad_sha,
                            after_head_sha=bad_sha,
                        )
                    )

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

    def test_malformed_runtime_evidence_cannot_pass(self):
        stream = success_stream()
        malformed_cases = (
            {"process_exit_code": False},
            {
                "stream_result": AntigravityStreamResult(
                    conversation_id="",
                    top_level_status=stream.top_level_status,
                    response=stream.response,
                    denied_actions=stream.denied_actions,
                    event_count=stream.event_count,
                )
            },
            {
                "stream_result": AntigravityStreamResult(
                    conversation_id=stream.conversation_id,
                    top_level_status=stream.top_level_status,
                    response=stream.response,
                    denied_actions=None,
                    event_count=stream.event_count,
                )
            },
            {
                "stream_result": AntigravityStreamResult(
                    conversation_id=stream.conversation_id,
                    top_level_status=stream.top_level_status,
                    response=stream.response,
                    denied_actions=stream.denied_actions,
                    event_count=0,
                )
            },
            {"before_tracked_delta": None, "after_tracked_delta": None},
            {"before_untracked": None, "after_untracked": None},
        )
        for overrides in malformed_cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    classify_antigravity_review(evidence(**overrides))

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
