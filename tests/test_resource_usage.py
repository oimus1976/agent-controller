import dataclasses
import inspect
import unittest

from agent_controller.resource_usage import (
    ResourceUsageObservation,
    ResourceUsageSource,
    same_usage_identity,
)


def observation(**changes):
    values = dict(
        controller_task_id="task-usage-1",
        operation_id="op-usage-1",
        operation_version="v1",
        provider="codex",
        controller_run_id="run-usage-1",
        source=ResourceUsageSource.ACCOUNT_TELEMETRY,
    )
    values.update(changes)
    return ResourceUsageObservation(**values)


class ResourceUsageObservationTests(unittest.TestCase):
    def test_unknown_is_none_not_zero(self):
        item = observation(source=ResourceUsageSource.UNKNOWN)
        self.assertIsNone(item.uncached_input_tokens)
        self.assertIsNone(item.cached_input_tokens)
        self.assertIsNone(item.output_tokens)
        measured_zero = observation(uncached_input_tokens=0)
        self.assertEqual(0, measured_zero.uncached_input_tokens)

    def test_negative_or_boolean_counters_rejected(self):
        for field_name in (
            "uncached_input_tokens",
            "cached_input_tokens",
            "cache_write_tokens",
            "output_tokens",
            "reasoning_tokens",
            "tool_call_count",
            "provider_turn_count",
            "retry_count",
            "files_read_count",
            "bytes_read",
            "elapsed_ms",
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(ValueError):
                    observation(**{field_name: -1})
                with self.assertRaises(ValueError):
                    observation(**{field_name: True})

    def test_allowance_units_nonnegative_and_normalized(self):
        self.assertEqual(2.0, observation(allowance_units=2).allowance_units)
        with self.assertRaises(ValueError):
            observation(allowance_units=-0.1)
        with self.assertRaises(ValueError):
            observation(allowance_units=True)

    def test_agent_reported_is_advisory_not_measured(self):
        self.assertFalse(observation(source=ResourceUsageSource.AGENT_REPORTED).measured_source)
        self.assertFalse(observation(source=ResourceUsageSource.UNKNOWN).measured_source)
        for source in (
            ResourceUsageSource.ACCOUNT_TELEMETRY,
            ResourceUsageSource.PROVIDER_TELEMETRY,
            ResourceUsageSource.CONTROLLER_MEASURED,
        ):
            self.assertTrue(observation(source=source).measured_source)

    def test_frozen_and_serialization_preserves_unknowns(self):
        item = observation(model="gpt-example", reasoning_setting="high")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            item.provider = "jules"  # type: ignore[misc]
        payload = item.to_mapping()
        self.assertIsNone(payload["cached_input_tokens"])
        self.assertEqual(ResourceUsageSource.ACCOUNT_TELEMETRY, payload["source"])
        with self.assertRaises(TypeError):
            payload["provider"] = "attacker"  # type: ignore[index]

    def test_identity_is_exact_operation_provider_binding(self):
        base = observation(controller_run_id="run-a")
        same_operation_other_run = observation(controller_run_id="run-b")
        self.assertTrue(same_usage_identity(base, same_operation_other_run))
        for field_name, value in (
            ("controller_task_id", "task-other"),
            ("operation_id", "op-other"),
            ("operation_version", "v2"),
            ("provider", "jules"),
        ):
            self.assertFalse(same_usage_identity(base, observation(**{field_name: value})))

    def test_required_binding_and_optional_strings_are_strict(self):
        for field_name in (
            "controller_task_id",
            "operation_id",
            "operation_version",
            "provider",
            "controller_run_id",
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(ValueError):
                    observation(**{field_name: ""})
        with self.assertRaises(ValueError):
            observation(model="")
        with self.assertRaises(ValueError):
            observation(reasoning_setting="")

    def test_contract_has_no_routing_or_throttling_effect_api(self):
        public = {
            name
            for name, value in inspect.getmembers(ResourceUsageObservation)
            if callable(value) and not name.startswith("_")
        }
        forbidden = {
            "select_model",
            "set_reasoning",
            "throttle",
            "truncate_prompt",
            "dispatch",
            "execute",
        }
        self.assertTrue(public.isdisjoint(forbidden))

    def test_no_fake_total_token_helper(self):
        self.assertFalse(hasattr(ResourceUsageObservation, "known_token_total"))
        self.assertFalse(hasattr(ResourceUsageObservation, "total_tokens"))


if __name__ == "__main__":
    unittest.main()
