from __future__ import annotations

import time
from dataclasses import dataclass

from .resource_usage import ResourceUsageObservation, ResourceUsageSource


@dataclass(frozen=True)
class ResourceMeterBinding:
    controller_task_id: str
    operation_id: str
    operation_version: str
    provider: str
    controller_run_id: str

    def __post_init__(self) -> None:
        for name in (
            "controller_task_id",
            "operation_id",
            "operation_version",
            "provider",
            "controller_run_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be nonempty")


class ControllerResourceMeter:
    """Operation-scoped Controller-measured counters.

    The public API only records concrete Controller-observed events. It does not
    accept arbitrary counter replacement, token estimates, or provider prose.
    """

    __slots__ = (
        "_binding",
        "_start_ns",
        "_final_elapsed_ms",
        "_tool_call_count",
        "_retry_count",
        "_files_read_count",
        "_bytes_read",
    )

    def __init__(self, *, binding: ResourceMeterBinding) -> None:
        if not isinstance(binding, ResourceMeterBinding):
            raise TypeError("binding must be ResourceMeterBinding")
        self._binding = binding
        self._start_ns = time.monotonic_ns()
        self._final_elapsed_ms: int | None = None
        self._tool_call_count = 0
        self._retry_count = 0
        self._files_read_count = 0
        self._bytes_read = 0

    def _require_active(self) -> None:
        if self._final_elapsed_ms is not None:
            raise RuntimeError("RESOURCE_METER_FINALIZED")

    def record_tool_call(self) -> None:
        self._require_active()
        self._tool_call_count += 1

    def record_retry(self) -> None:
        self._require_active()
        self._retry_count += 1

    def record_file_read(self, *, byte_count: int) -> None:
        self._require_active()
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise ValueError("byte_count must be a non-negative integer")
        self._files_read_count += 1
        self._bytes_read += byte_count

    def _elapsed_ms(self) -> int:
        if self._final_elapsed_ms is not None:
            return self._final_elapsed_ms
        elapsed_ns = time.monotonic_ns() - self._start_ns
        if elapsed_ns < 0:
            raise RuntimeError("MONOTONIC_CLOCK_REVERSED")
        return elapsed_ns // 1_000_000

    def snapshot(self) -> ResourceUsageObservation:
        binding = self._binding
        return ResourceUsageObservation(
            controller_task_id=binding.controller_task_id,
            operation_id=binding.operation_id,
            operation_version=binding.operation_version,
            provider=binding.provider,
            controller_run_id=binding.controller_run_id,
            source=ResourceUsageSource.CONTROLLER_MEASURED,
            tool_call_count=self._tool_call_count,
            retry_count=self._retry_count,
            files_read_count=self._files_read_count,
            bytes_read=self._bytes_read,
            elapsed_ms=self._elapsed_ms(),
        )

    def finalize(self) -> ResourceUsageObservation:
        if self._final_elapsed_ms is None:
            elapsed_ns = time.monotonic_ns() - self._start_ns
            if elapsed_ns < 0:
                raise RuntimeError("MONOTONIC_CLOCK_REVERSED")
            self._final_elapsed_ms = elapsed_ns // 1_000_000
        return self.snapshot()
