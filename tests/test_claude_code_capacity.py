import json
from pathlib import Path
import unittest

from agent_controller.claude_code_capacity import parse_claude_code_statusline_capacity
from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
)


FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "claude_code_statusline_rate_limits_synthetic.json"
)
BINDING = {
    "controller_task_id": "task-claude-code-capacity",
    "workstream_id": "claude-code-capacity",
    "operation_id": "parse-statusline-rate-limits",
    "operation_version": "1",
    "observed_at": "2026-11-18T09:00:00Z",
}


def parse(payload):
    return parse_claude_code_statusline_capacity(payload, **BINDING)


def payload_with_rate_limits(rate_limits, **extra):
    root = {"version": "2.1.999-fixture", "rate_limits": rate_limits}
    root.update(extra)
    return json.dumps(root)


class ClaudeCodeCapacityParserTests(unittest.TestCase):
    def fixture_text(self):
        return FIXTURE.read_text(encoding="utf-8")

    def test_preserves_both_windows_without_aggregation(self):
        observations = parse(self.fixture_text())
        self.assertEqual(
            [item.capacity_pool for item in observations],
            ["five-hour", "weekly"],
        )
        self.assertEqual(len(observations), 2)

    def test_used_percentage_reset_and_provenance_are_preserved(self):
        observations = parse(self.fixture_text())
        five_hour, weekly = observations

        self.assertEqual(five_hour.observation.provider, "claude-code")
        self.assertEqual(five_hour.observation.remaining_capacity, 0.75)
        self.assertEqual(five_hour.observation.capacity_unit, "fraction")
        self.assertEqual(five_hour.observation.availability, ProviderAvailability.AVAILABLE)
        self.assertEqual(five_hour.observation.reset_at, "2026-11-18T12:00:00Z")
        self.assertEqual(
            five_hour.observation.source, CapacityObservationSource.PROVIDER_TELEMETRY
        )
        self.assertEqual(five_hour.provenance, "claude-code-statusline/2.1.999-fixture")

        self.assertEqual(weekly.observation.remaining_capacity, 0.4)
        self.assertEqual(weekly.observation.availability, ProviderAvailability.AVAILABLE)
        self.assertEqual(weekly.observation.reset_at, "2026-11-23T09:00:00Z")

    def test_unknown_extra_fields_are_tolerated(self):
        observations = parse(self.fixture_text())
        self.assertEqual(len(observations), 2)

    def test_same_fixture_is_deterministic(self):
        first = parse(self.fixture_text())
        second = parse(self.fixture_text())
        self.assertEqual(first, second)

    def test_absent_window_yields_no_observation_for_that_pool(self):
        payload = payload_with_rate_limits(
            {"five_hour": {"used_percentage": 25, "resets_at": 1795003200}}
        )
        observations = parse(payload)
        self.assertEqual([item.capacity_pool for item in observations], ["five-hour"])

    def test_empty_rate_limits_yields_no_observations(self):
        self.assertEqual(parse(payload_with_rate_limits({})), ())

    def test_missing_rate_limits_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "rate_limits"):
            parse(json.dumps({"version": "2.1.999-fixture"}))

    def test_non_object_rate_limits_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "rate_limits"):
            parse(payload_with_rate_limits([1, 2, 3]))

    def test_malformed_json_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse("{not-json")

    def test_non_object_root_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "root must be an object"):
            parse("[1, 2, 3]")

    def test_duplicate_keys_fail_closed(self):
        payload = (
            '{"version":"2.1.999-fixture","version":"2.1.999-fixture",'
            '"rate_limits":{"five_hour":{"used_percentage":25,"resets_at":1795003200}}}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: version"):
            parse(payload)

    def test_missing_used_percentage_fails_closed(self):
        payload = payload_with_rate_limits({"five_hour": {"resets_at": 1795003200}})
        with self.assertRaisesRegex(ValueError, "used_percentage"):
            parse(payload)

    def test_invalid_used_percentage_fails_closed(self):
        for value in (-1, 100.5, True, "25"):
            with self.subTest(value=value):
                payload = payload_with_rate_limits(
                    {"five_hour": {"used_percentage": value, "resets_at": 1795003200}}
                )
                with self.assertRaises(ValueError):
                    parse(payload)

    def test_used_percentage_boundaries(self):
        for used, remaining, availability in (
            (100, 0.0, ProviderAvailability.EXHAUSTED),
            (0, 1.0, ProviderAvailability.AVAILABLE),
        ):
            with self.subTest(used=used):
                payload = payload_with_rate_limits(
                    {"five_hour": {"used_percentage": used, "resets_at": 1795003200}}
                )
                (observation,) = parse(payload)
                self.assertEqual(observation.observation.remaining_capacity, remaining)
                self.assertEqual(observation.observation.availability, availability)

    def test_invalid_resets_at_fails_closed(self):
        for value in ("soon", -5, True, 1.5):
            with self.subTest(value=value):
                payload = payload_with_rate_limits(
                    {"five_hour": {"used_percentage": 25, "resets_at": value}}
                )
                with self.assertRaises(ValueError):
                    parse(payload)

    def test_absent_resets_at_yields_no_reset(self):
        payload = payload_with_rate_limits({"five_hour": {"used_percentage": 25}})
        (observation,) = parse(payload)
        self.assertIsNone(observation.observation.reset_at)

    def test_non_object_window_fails_closed(self):
        payload = payload_with_rate_limits({"five_hour": 25})
        with self.assertRaisesRegex(ValueError, "must be an object"):
            parse(payload)

    def test_absent_version_uses_bare_provenance(self):
        payload = json.dumps(
            {"rate_limits": {"five_hour": {"used_percentage": 25, "resets_at": 1795003200}}}
        )
        (observation,) = parse(payload)
        self.assertEqual(observation.provenance, "claude-code-statusline")

    def test_parser_has_no_command_or_mutation_dependency(self):
        observations = parse(self.fixture_text())
        self.assertTrue(observations)
        self.assertTrue(
            all(
                item.observation.operation_id == "parse-statusline-rate-limits"
                for item in observations
            )
        )


if __name__ == "__main__":
    unittest.main()
