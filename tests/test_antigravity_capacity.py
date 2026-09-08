import json
from pathlib import Path
import unittest

from agent_controller.antigravity_capacity import parse_antigravity_statusline_capacity
from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
)


FIXTURE = Path(__file__).parent / "fixtures" / "antigravity_statusline_quota.json"
BINDING = {
    "controller_task_id": "task-177",
    "workstream_id": "antigravity-capacity",
    "operation_id": "parse-statusline-quota",
    "operation_version": "1",
    "observed_at": "2026-09-08T07:00:00Z",
}


def parse(payload):
    return parse_antigravity_statusline_capacity(payload, **BINDING)


class AntigravityCapacityParserTests(unittest.TestCase):
    def fixture_text(self):
        return FIXTURE.read_text(encoding="utf-8")

    def test_preserves_multiple_quota_pools_without_aggregation(self):
        observations = parse(self.fixture_text())
        self.assertEqual(
            [item.capacity_pool for item in observations],
            ["claude-five-hour", "gemini-weekly"],
        )
        self.assertEqual(len(observations), 2)

    def test_finite_fraction_zero_reset_and_provenance_are_preserved(self):
        observations = parse(self.fixture_text())
        exhausted, available = observations

        self.assertEqual(exhausted.observation.provider, "antigravity")
        self.assertEqual(exhausted.observation.remaining_capacity, 0.0)
        self.assertEqual(exhausted.observation.capacity_unit, "fraction")
        self.assertEqual(exhausted.observation.availability, ProviderAvailability.EXHAUSTED)
        self.assertEqual(exhausted.observation.reset_at, "2026-09-08T08:00:00Z")
        self.assertEqual(exhausted.observation.source, CapacityObservationSource.PROVIDER_TELEMETRY)
        self.assertEqual(exhausted.provenance, "antigravity-cli-statusline/1.1.27")

        self.assertEqual(available.observation.remaining_capacity, 0.625)
        self.assertEqual(available.observation.availability, ProviderAvailability.AVAILABLE)
        self.assertEqual(available.observation.reset_at, "2026-09-14T02:00:00Z")

    def test_unknown_extra_fields_are_tolerated(self):
        observations = parse(self.fixture_text())
        self.assertEqual(len(observations), 2)

    def test_same_fixture_is_deterministic(self):
        first = parse(self.fixture_text())
        second = parse(self.fixture_text())
        self.assertEqual(first, second)

    def test_malformed_json_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse("{not-json")

    def test_error_envelope_is_not_capacity_success(self):
        payload = json.dumps({"status": "ERROR", "error": "quota unavailable"})
        with self.assertRaises(ValueError):
            parse(payload)

    def test_missing_or_empty_quota_fails_closed(self):
        for quota in (None, {}):
            with self.subTest(quota=quota):
                payload = json.dumps(
                    {"product": "antigravity", "version": "1.1.27", "quota": quota}
                )
                with self.assertRaisesRegex(ValueError, "quota object"):
                    parse(payload)

    def test_missing_remaining_fraction_fails_closed(self):
        payload = json.dumps(
            {
                "product": "antigravity",
                "version": "1.1.27",
                "quota": {"gemini-weekly": {"reset_time": "2026-09-14T02:00:00Z"}},
            }
        )
        with self.assertRaisesRegex(ValueError, "remaining_fraction"):
            parse(payload)

    def test_invalid_fraction_fails_closed(self):
        for value in (-0.1, 1.1, True, "0.5"):
            with self.subTest(value=value):
                payload = json.dumps(
                    {
                        "product": "antigravity",
                        "version": "1.1.27",
                        "quota": {"gemini-weekly": {"remaining_fraction": value}},
                    }
                )
                with self.assertRaises(ValueError):
                    parse(payload)

    def test_reset_time_must_satisfy_provider_neutral_timestamp_contract(self):
        payload = json.dumps(
            {
                "product": "antigravity",
                "version": "1.1.27",
                "quota": {
                    "gemini-weekly": {
                        "remaining_fraction": 0.5,
                        "reset_time": "2026-09-14T02:00:00"
                    }
                },
            }
        )
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            parse(payload)

    def test_parser_has_no_command_or_mutation_dependency(self):
        observations = parse(self.fixture_text())
        self.assertTrue(observations)
        self.assertTrue(all(item.observation.operation_id == "parse-statusline-quota" for item in observations))


if __name__ == "__main__":
    unittest.main()
