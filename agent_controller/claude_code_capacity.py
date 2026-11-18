from __future__ import annotations

from datetime import datetime, timezone
import json
import math
from typing import Mapping

from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
    ProviderCapacityObservation,
)
from agent_controller.provider_capacity_pool import ProviderCapacityPoolObservation


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _remaining_from_used_percentage(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError("used_percentage must be a finite number")
    used = float(value)
    if used < 0 or used > 100:
        raise ValueError("used_percentage must be within [0, 100]")
    return 1.0 - used / 100.0


def _epoch_seconds_to_iso8601(value: object) -> str:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError("resets_at must be a finite number")
    epoch = float(value)
    if epoch < 0 or epoch != int(epoch):
        raise ValueError("resets_at must be a non-negative whole number of seconds")
    parsed = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    return parsed.isoformat().replace("+00:00", "Z")


_WINDOW_POOLS = (
    ("five_hour", "five-hour"),
    ("seven_day", "weekly"),
)


def parse_claude_code_statusline_capacity(
    payload: str,
    *,
    controller_task_id: str,
    workstream_id: str,
    operation_id: str,
    operation_version: str,
    observed_at: str,
) -> tuple[ProviderCapacityPoolObservation, ...]:
    """Parse Claude Code status-line JSON rate-limit windows.

    The status-line payload is the documented machine-readable surface Claude
    Code passes to status-line commands on stdin. ``rate_limits`` is present
    only for claude.ai Pro/Max/Ultra subscribers and only after the first API
    response of a session; when it is absent the payload carries no capacity
    telemetry and this parser fails closed instead of inventing an UNKNOWN
    observation. Each window (``five_hour`` / ``seven_day``) may be
    independently absent, and an absent window yields no observation for that
    pool. The gateway-only ``spend_limit`` window is intentionally out of
    scope: it is an organization spend cap, not a plan quota window.

    This parser is pure and performs no CLI, provider, billing, routing, or
    GitHub effects.
    """

    if not isinstance(payload, str):
        raise TypeError("payload must be str")
    try:
        root = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("malformed Claude Code statusline JSON") from exc

    if not isinstance(root, Mapping):
        raise ValueError("Claude Code statusline root must be an object")

    rate_limits = root.get("rate_limits")
    if not isinstance(rate_limits, Mapping):
        raise ValueError("Claude Code statusline rate_limits object is required")

    version = root.get("version")
    if version is not None and not _nonempty_string(version):
        raise ValueError("Claude Code version must be a nonempty string when present")
    provenance = (
        f"claude-code-statusline/{version}" if version is not None else "claude-code-statusline"
    )

    observations: list[ProviderCapacityPoolObservation] = []
    for window_key, pool_id in _WINDOW_POOLS:
        window = rate_limits.get(window_key)
        if window is None:
            continue
        if not isinstance(window, Mapping):
            raise ValueError(f"rate_limits.{window_key} must be an object")

        if "used_percentage" not in window:
            raise ValueError(f"rate_limits.{window_key}.used_percentage is required")
        remaining = _remaining_from_used_percentage(window["used_percentage"])

        reset_at = window.get("resets_at")
        if reset_at is not None:
            reset_at = _epoch_seconds_to_iso8601(reset_at)

        availability = (
            ProviderAvailability.EXHAUSTED
            if remaining == 0
            else ProviderAvailability.AVAILABLE
        )
        neutral = ProviderCapacityObservation(
            controller_task_id=controller_task_id,
            workstream_id=workstream_id,
            operation_id=operation_id,
            operation_version=operation_version,
            provider="claude-code",
            observed_at=observed_at,
            availability=availability,
            source=CapacityObservationSource.PROVIDER_TELEMETRY,
            remaining_capacity=remaining,
            capacity_unit="fraction",
            reset_at=reset_at,
        )
        observations.append(
            ProviderCapacityPoolObservation(
                capacity_pool=pool_id,
                observation=neutral,
                provenance=provenance,
            )
        )

    return tuple(observations)
