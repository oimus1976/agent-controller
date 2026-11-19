import json
from pathlib import Path
import unittest

from agent_controller.codex_capacity import parse_codex_rate_limits_capacity
from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
)


FIXTURE = (
    Path(__file__).parent / "fixtures" / "codex_app_server_rate_limits_synthetic.json"
)
BINDING = {
    "controller_task_id": "task-codex-capacity",
    "workstream_id": "codex-capacity",
    "operation_id": "parse-rate-limits-read",
    "operation_version": "1",
    "observed_at": "2026-11-18T09:00:00Z",
}


def parse(payload):
    return parse_codex_rate_limits_capacity(payload, **BINDING)


def bucket(primary=None, secondary=None, **extra):
    result = {"limitId": "codex", "primary": primary, "secondary": secondary}
    result.update(extra)
    return result


def window(used, minutes=300, resets=1795005000):
    return {"usedPercent": used, "windowDurationMins": minutes, "resetsAt": resets}


class CodexCapacityParserTests(unittest.TestCase):
    def fixture_text(self):
        return FIXTURE.read_text(encoding="utf-8")

    def test_preserves_multiple_buckets_without_aggregation_or_double_counting(self):
        observations = parse(self.fixture_text())
        self.assertEqual(
            [item.capacity_pool for item in observations],
            ["codex-five-hour", "codex-weekly", "codex_other-window-60m"],
        )
        self.assertEqual(len(observations), 3)

    def test_window_values_reset_and_provenance_are_preserved(self):
        observations = parse(self.fixture_text())
        five_hour, weekly, other = observations

        self.assertEqual(five_hour.observation.provider, "codex")
        self.assertEqual(five_hour.observation.remaining_capacity, 0.75)
        self.assertEqual(five_hour.observation.capacity_unit, "fraction")
        self.assertEqual(five_hour.observation.availability, ProviderAvailability.AVAILABLE)
        self.assertEqual(five_hour.observation.reset_at, "2026-11-18T12:30:00Z")
        self.assertEqual(
            five_hour.observation.source, CapacityObservationSource.PROVIDER_TELEMETRY
        )
        self.assertEqual(
            five_hour.provenance, "codex-app-server/account/rateLimits/read"
        )

        self.assertEqual(weekly.observation.remaining_capacity, 0.4)
        self.assertEqual(weekly.observation.reset_at, "2026-11-24T00:00:00Z")

        self.assertEqual(other.observation.remaining_capacity, 0.5)
        self.assertEqual(other.observation.reset_at, "2026-11-18T10:00:00Z")

    def test_credits_and_plan_type_are_tolerated_but_not_modeled(self):
        observations = parse(self.fixture_text())
        self.assertEqual(len(observations), 3)
        self.assertTrue(
            all("credit" not in item.capacity_pool for item in observations)
        )

    def test_unknown_extra_fields_are_tolerated(self):
        observations = parse(self.fixture_text())
        self.assertEqual(len(observations), 3)

    def test_same_fixture_is_deterministic(self):
        first = parse(self.fixture_text())
        second = parse(self.fixture_text())
        self.assertEqual(first, second)

    def test_single_bucket_fallback_without_multi_bucket_view(self):
        payload = json.dumps({"rateLimits": bucket(window(25), window(60, 10080, 1795478400))})
        observations = parse(payload)
        self.assertEqual(
            [item.capacity_pool for item in observations],
            ["codex-five-hour", "codex-weekly"],
        )

    def test_empty_multi_bucket_view_falls_back_to_single_bucket(self):
        payload = json.dumps(
            {
                "rateLimits": bucket(window(25)),
                "rateLimitsByLimitId": {},
            }
        )
        observations = parse(payload)
        self.assertEqual([item.capacity_pool for item in observations], ["codex-five-hour"])

    def test_missing_buckets_fail_closed(self):
        for payload in ("{}", json.dumps({"rateLimitsByLimitId": {}})):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "no buckets"):
                    parse(payload)

    def test_malformed_json_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse("{not-json")

    def test_non_object_root_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "root must be an object"):
            parse("[1, 2, 3]")

    def test_error_envelope_is_not_capacity_success(self):
        payload = json.dumps(
            {"error": {"code": -32000, "message": "not signed in"}, "rateLimits": bucket(window(25))}
        )
        with self.assertRaisesRegex(ValueError, "error envelope"):
            parse(payload)

    def test_duplicate_keys_fail_closed(self):
        payload = (
            '{"rateLimits":{"limitId":"codex","limitId":"codex",'
            '"primary":{"usedPercent":25,"windowDurationMins":300,"resetsAt":1795005000},'
            '"secondary":null}}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: limitId"):
            parse(payload)

    def test_null_window_yields_no_observation_for_that_slot(self):
        payload = json.dumps({"rateLimits": bucket(window(25), None)})
        observations = parse(payload)
        self.assertEqual([item.capacity_pool for item in observations], ["codex-five-hour"])

    def test_missing_used_percent_fails_closed(self):
        bad = {"windowDurationMins": 300, "resetsAt": 1795005000}
        payload = json.dumps({"rateLimits": bucket(bad)})
        with self.assertRaisesRegex(ValueError, "usedPercent"):
            parse(payload)

    def test_invalid_used_percent_fails_closed(self):
        for value in (-5, True, "25"):
            with self.subTest(value=value):
                payload = json.dumps({"rateLimits": bucket(window(value))})
                with self.assertRaises(ValueError):
                    parse(payload)

    def test_used_percent_boundaries_and_clamping(self):
        for used, remaining, availability in (
            (100, 0.0, ProviderAvailability.EXHAUSTED),
            (137, 0.0, ProviderAvailability.EXHAUSTED),
            (0, 1.0, ProviderAvailability.AVAILABLE),
        ):
            with self.subTest(used=used):
                payload = json.dumps({"rateLimits": bucket(window(used))})
                (observation,) = parse(payload)
                self.assertEqual(observation.observation.remaining_capacity, remaining)
                self.assertEqual(observation.observation.availability, availability)

    def test_unclassified_duration_keeps_neutral_pool_name(self):
        payload = json.dumps({"rateLimits": bucket(window(25, 60, 1794996000))})
        (observation,) = parse(payload)
        self.assertEqual(observation.capacity_pool, "codex-window-60m")

    def test_missing_duration_falls_back_to_slot_pool_name(self):
        no_duration = {"usedPercent": 25, "resetsAt": 1795005000}
        payload = json.dumps({"rateLimits": bucket(no_duration)})
        (observation,) = parse(payload)
        self.assertEqual(observation.capacity_pool, "codex-primary")

    def test_invalid_duration_fails_closed(self):
        for value in (0, -300, "300", True):
            with self.subTest(value=value):
                payload = json.dumps({"rateLimits": bucket(window(25, value))})
                with self.assertRaises(ValueError):
                    parse(payload)

    def test_invalid_resets_at_fails_closed(self):
        for value in ("soon", -5, True, 1.5):
            with self.subTest(value=value):
                payload = json.dumps({"rateLimits": bucket(window(25, 300, value))})
                with self.assertRaises(ValueError):
                    parse(payload)

    def test_absent_resets_at_yields_no_reset(self):
        no_reset = {"usedPercent": 25, "windowDurationMins": 300}
        payload = json.dumps({"rateLimits": bucket(no_reset)})
        (observation,) = parse(payload)
        self.assertIsNone(observation.observation.reset_at)

    def test_non_object_bucket_or_window_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "must be an object"):
            parse(json.dumps({"rateLimits": 25}))
        with self.assertRaisesRegex(ValueError, "must be an object"):
            parse(json.dumps({"rateLimits": bucket(25)}))

    def test_bucket_limit_id_mismatch_fails_closed(self):
        payload = json.dumps({"rateLimitsByLimitId": {"codex": bucket(window(25), limitId="other")}})
        with self.assertRaisesRegex(ValueError, "does not match"):
            parse(payload)

    def test_parser_has_no_command_or_mutation_dependency(self):
        observations = parse(self.fixture_text())
        self.assertTrue(observations)
        self.assertTrue(
            all(
                item.observation.operation_id == "parse-rate-limits-read"
                for item in observations
            )
        )


if __name__ == "__main__":
    unittest.main()
