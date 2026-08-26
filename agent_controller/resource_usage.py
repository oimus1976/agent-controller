from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Optional


class ResourceUsageSource(str, Enum):
    ACCOUNT_TELEMETRY = "ACCOUNT_TELEMETRY"
    PROVIDER_TELEMETRY = "PROVIDER_TELEMETRY"
    CONTROLLER_MEASURED = "CONTROLLER_MEASURED"
    AGENT_REPORTED = "AGENT_REPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ResourceUsageObservation:
    controller_task_id: str
    operation_id: str
    operation_version: str
    provider: str
    controller_run_id: str
    source: ResourceUsageSource
    model: Optional[str] = None
    reasoning_setting: Optional[str] = None
    uncached_input_tokens: Optional[int] = None
    cached_input_tokens: Optional[int] = None
    cache_write_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    reasoning_tokens: Optional[int] = None
    allowance_units: Optional[float] = None
    tool_call_count: Optional[int] = None
    provider_turn_count: Optional[int] = None
    retry_count: Optional[int] = None
    files_read_count: Optional[int] = None
    bytes_read: Optional[int] = None
    elapsed_ms: Optional[int] = None

    def __post_init__(self) -> None:
        for field_name in (
            "controller_task_id",
            "operation_id",
            "operation_version",
            "provider",
            "controller_run_id",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be nonempty")
        if not isinstance(self.source, ResourceUsageSource):
            raise TypeError("source must be ResourceUsageSource")
        for field_name in ("model", "reasoning_setting"):
            value = getattr(self, field_name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{field_name} must be nonempty when present")
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
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError(f"{field_name} must be a non-negative integer when present")
        if self.allowance_units is not None:
            value = self.allowance_units
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise ValueError("allowance_units must be non-negative when present")
            object.__setattr__(self, "allowance_units", float(value))

    @property
    def measured_source(self) -> bool:
        return self.source in {
            ResourceUsageSource.ACCOUNT_TELEMETRY,
            ResourceUsageSource.PROVIDER_TELEMETRY,
            ResourceUsageSource.CONTROLLER_MEASURED,
        }

    def to_mapping(self) -> Mapping[str, object]:
        return MappingProxyType(asdict(self))


def same_usage_identity(
    left: ResourceUsageObservation, right: ResourceUsageObservation
) -> bool:
    return (
        left.controller_task_id,
        left.operation_id,
        left.operation_version,
        left.provider,
    ) == (
        right.controller_task_id,
        right.operation_id,
        right.operation_version,
        right.provider,
    )
