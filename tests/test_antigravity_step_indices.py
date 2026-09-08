import json
import unittest

from agent_controller.antigravity_review import parse_antigravity_stream_json


WORKSPACE = r"C:\fixture\repo"


def _parse(lines):
    return parse_antigravity_stream_json(
        lines,
        expected_workspace=WORKSPACE,
        canonical_path_resolver=lambda path: path,
    )


def _init():
    return json.dumps(
        {
            "event": "init",
            "conversation_id": "c1",
            "init": {"cwd": WORKSPACE},
        },
        separators=(",", ":"),
    )


def _step(index):
    return json.dumps(
        {
            "event": "step_update",
            "step_update": {
                "conversation_id": "c1",
                "step_index": index,
                "state": "DONE",
                "step_type": "agent_response",
            },
        },
        separators=(",", ":"),
    )


def _result():
    return json.dumps(
        {
            "event": "result",
            "result": {
                "conversation_id": "c1",
                "status": "SUCCESS",
                "response": "NO_FINDINGS",
                "denied_actions": [],
            },
        },
        separators=(",", ":"),
    )


class AntigravityStepIndexTests(unittest.TestCase):
    def test_first_step_index_must_be_zero(self):
        with self.assertRaisesRegex(ValueError, "contiguous from zero"):
            _parse([_init(), _step(99), _result()])

    def test_internal_step_index_gap_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "contiguous from zero"):
            _parse([_init(), _step(0), _step(2), _result()])

    def test_contiguous_step_indices_are_accepted(self):
        result = _parse([_init(), _step(0), _step(1), _result()])
        self.assertEqual(result.top_level_status, "SUCCESS")


if __name__ == "__main__":
    unittest.main()
