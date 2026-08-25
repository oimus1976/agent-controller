import inspect
import unittest
from unittest.mock import patch

from agent_controller.resource_meter import ControllerResourceMeter, ResourceMeterBinding
from agent_controller.resource_usage import ResourceUsageSource


def binding(**changes):
    values = dict(
        controller_task_id="task-1",
        operation_id="op-1",
        operation_version="v1",
        provider="codex",
        controller_run_id="run-1",
    )
    values.update(changes)
    return ResourceMeterBinding(**values)


class ControllerResourceMeterTests(unittest.TestCase):
    def test_zero_is_measured_and_token_fields_remain_unknown(self):
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[1_000_000_000, 1_000_000_000]):
            observed = ControllerResourceMeter(binding=binding()).snapshot()
        self.assertIs(observed.source, ResourceUsageSource.CONTROLLER_MEASURED)
        self.assertEqual(0, observed.tool_call_count)
        self.assertEqual(0, observed.retry_count)
        self.assertEqual(0, observed.files_read_count)
        self.assertEqual(0, observed.bytes_read)
        self.assertEqual(0, observed.elapsed_ms)
        for name in (
            "uncached_input_tokens",
            "cached_input_tokens",
            "cache_write_tokens",
            "output_tokens",
            "reasoning_tokens",
            "allowance_units",
            "provider_turn_count",
        ):
            self.assertIsNone(getattr(observed, name))

    def test_explicit_events_increment_only_exact_counters(self):
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[0, 7_500_000]):
            meter = ControllerResourceMeter(binding=binding())
            meter.record_tool_call()
            meter.record_tool_call()
            meter.record_retry()
            meter.record_file_read(byte_count=10)
            meter.record_file_read(byte_count=0)
            observed = meter.snapshot()
        self.assertEqual(2, observed.tool_call_count)
        self.assertEqual(1, observed.retry_count)
        self.assertEqual(2, observed.files_read_count)
        self.assertEqual(10, observed.bytes_read)
        self.assertEqual(7, observed.elapsed_ms)

    def test_invalid_file_byte_count_rejected_without_partial_increment(self):
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[0, 0]):
            meter = ControllerResourceMeter(binding=binding())
            for value in (-1, True, 1.5, "1"):
                with self.assertRaises(ValueError):
                    meter.record_file_read(byte_count=value)
            observed = meter.snapshot()
        self.assertEqual(0, observed.files_read_count)
        self.assertEqual(0, observed.bytes_read)

    def test_binding_is_exactly_preserved(self):
        expected = binding(operation_id="op-x", operation_version="v9", provider="provider-x", controller_run_id="run-x")
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[0, 0]):
            observed = ControllerResourceMeter(binding=expected).snapshot()
        self.assertEqual(expected.controller_task_id, observed.controller_task_id)
        self.assertEqual(expected.operation_id, observed.operation_id)
        self.assertEqual(expected.operation_version, observed.operation_version)
        self.assertEqual(expected.provider, observed.provider)
        self.assertEqual(expected.controller_run_id, observed.controller_run_id)

    def test_finalize_is_idempotent_and_freezes_elapsed_and_counters(self):
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[0, 5_900_000]):
            meter = ControllerResourceMeter(binding=binding())
            meter.record_tool_call()
            first = meter.finalize()
            second = meter.finalize()
        self.assertEqual(first, second)
        self.assertEqual(5, first.elapsed_ms)
        with self.assertRaisesRegex(RuntimeError, "RESOURCE_METER_FINALIZED"):
            meter.record_tool_call()
        with self.assertRaisesRegex(RuntimeError, "RESOURCE_METER_FINALIZED"):
            meter.record_retry()
        with self.assertRaisesRegex(RuntimeError, "RESOURCE_METER_FINALIZED"):
            meter.record_file_read(byte_count=1)

    def test_snapshot_does_not_mutate_counters(self):
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[0, 1_000_000, 2_000_000]):
            meter = ControllerResourceMeter(binding=binding())
            meter.record_file_read(byte_count=4)
            first = meter.snapshot()
            second = meter.snapshot()
        self.assertEqual(first.files_read_count, second.files_read_count)
        self.assertEqual(first.bytes_read, second.bytes_read)
        self.assertLessEqual(first.elapsed_ms, second.elapsed_ms)

    def test_monotonic_clock_reversal_fails_closed(self):
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[10, 9]):
            meter = ControllerResourceMeter(binding=binding())
            with self.assertRaisesRegex(RuntimeError, "MONOTONIC_CLOCK_REVERSED"):
                meter.snapshot()

    def test_independent_meters_do_not_share_counts(self):
        with patch("agent_controller.resource_meter.time.monotonic_ns", side_effect=[0, 0, 0, 0]):
            left = ControllerResourceMeter(binding=binding(controller_run_id="left"))
            right = ControllerResourceMeter(binding=binding(controller_run_id="right"))
            left.record_tool_call()
            left_observed = left.snapshot()
            right_observed = right.snapshot()
        self.assertEqual(1, left_observed.tool_call_count)
        self.assertEqual(0, right_observed.tool_call_count)

    def test_public_api_has_no_counter_overwrite_or_token_estimation_surface(self):
        names = set(dir(ControllerResourceMeter))
        for forbidden in (
            "set_tool_call_count",
            "set_retry_count",
            "set_bytes_read",
            "set_tokens",
            "estimate_tokens",
            "select_model",
            "downgrade_model",
            "throttle",
            "truncate_prompt",
            "execute",
            "deploy",
        ):
            self.assertNotIn(forbidden, names)
        self.assertEqual({"self"}, set(inspect.signature(ControllerResourceMeter.record_tool_call).parameters))
        self.assertEqual({"self"}, set(inspect.signature(ControllerResourceMeter.record_retry).parameters))
        self.assertEqual({"self", "byte_count"}, set(inspect.signature(ControllerResourceMeter.record_file_read).parameters))


if __name__ == "__main__":
    unittest.main()
