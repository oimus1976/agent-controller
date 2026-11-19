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


def _remaining_from_used_percent(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError("usedPercent must be a finite number")
    used = float(value)
    if used < 0:
        raise ValueError("usedPercent must be non-negative")
    # The protocol type notes usedPercent may exceed 100. The remaining
    # fraction is clamped at 0 (which maps to EXHAUSTED) rather than letting
    # a negative remaining capacity escape into the neutral model.
    return max(0.0, 1.0 - used / 100.0)


def _epoch_seconds_to_iso8601(value: object) -> str:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError("resetsAt must be a finite number")
    epoch = float(value)
    if epoch < 0 or epoch != int(epoch):
        raise ValueError("resetsAt must be a non-negative whole number of seconds")
    parsed = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    return parsed.isoformat().replace("+00:00", "Z")


def _window_pool_suffix(window: Mapping, slot: str) -> str:
    minutes = window.get("windowDurationMins")
    if minutes is None:
        # Without a duration the window cannot be classified; keep it under
        # its neutral slot name instead of guessing five-hour or weekly.
        return slot
    if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes <= 0:
        raise ValueError("windowDurationMins must be a positive integer when present")
    if minutes == 300:
        return "five-hour"
    if minutes == 10080:
        return "weekly"
    return f"window-{minutes}m"


def parse_codex_rate_limits_capacity(
    payload: str,
    *,
    controller_task_id: str,
    workstream_id: str,
    operation_id: str,
    operation_version: str,
    observed_at: str,
) -> tuple[ProviderCapacityPoolObservation, ...]:
    """Parse a Codex app-server ``account/rateLimits/read`` result.

    The input is the result object of the documented app-server JSON-RPC
    method. ``rateLimitsByLimitId`` (the multi-bucket view keyed by metered
    limit id) is authoritative when present and nonempty; otherwise the
    backward-compatible single ``rateLimits`` bucket is used. Buckets are
    never merged, and the two views are never combined, so no window is
    double-counted.

    Windows are classified by ``windowDurationMins`` (300 = five-hour,
    10080 = weekly); the ``primary``/``secondary`` slot position alone never
    decides the classification, and any other duration keeps a neutral
    ``window-<mins>m`` pool name. A null window yields no observation.

    ``credits``, ``planType``, and ``rateLimitResetCredits`` are intentionally
    not modeled as capacity pools and are dropped by this parser: credits are
    a balance, not a quota window. Modeling them is a future extension point
    and must not be folded into window observations.

    This parser is pure and performs no CLI, provider, billing, routing, or
    GitHub effects.
    """

    if not isinstance(payload, str):
        raise TypeError("payload must be str")
    try:
        root = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("malformed Codex rate-limits JSON") from exc

    if not isinstance(root, Mapping):
        raise ValueError("Codex rate-limits root must be an object")

    error = root.get("error")
    if error not in (None, ""):
        raise ValueError("Codex error envelope is not capacity telemetry")

    buckets: dict[str, object] = {}
    by_limit_id = root.get("rateLimitsByLimitId")
    if by_limit_id is not None and not isinstance(by_limit_id, Mapping):
        raise ValueError("rateLimitsByLimitId must be an object when present")
    if isinstance(by_limit_id, Mapping) and by_limit_id:
        buckets = dict(by_limit_id)
    else:
        single = root.get("rateLimits")
        if single is not None:
            if not isinstance(single, Mapping):
                raise ValueError("rateLimits must be an object when present")
            limit_id = single.get("limitId")
            if not _nonempty_string(limit_id):
                raise ValueError("rateLimits.limitId is required")
            buckets = {limit_id: single}
    if not buckets:
        raise ValueError("Codex rate-limits result contains no buckets")

    observations: list[ProviderCapacityPoolObservation] = []
    for map_key in sorted(buckets):
        if not _nonempty_string(map_key):
            raise ValueError("rate limit bucket id must be nonempty")
        bucket = buckets[map_key]
        if not isinstance(bucket, Mapping):
            raise ValueError("rate limit bucket must be an object")
        limit_id = bucket.get("limitId")
        if limit_id is not None:
            if not _nonempty_string(limit_id):
                raise ValueError("rate limit bucket limitId must be a nonempty string")
            if limit_id != map_key:
                raise ValueError("rate limit bucket limitId does not match its key")
        else:
            limit_id = map_key

        for slot in ("primary", "secondary"):
            window = bucket.get(slot)
            if window is None:
                continue
            if not isinstance(window, Mapping):
                raise ValueError(f"rate limit window {slot} must be an object")

            if "usedPercent" not in window:
                raise ValueError("usedPercent is required")
            remaining = _remaining_from_used_percent(window["usedPercent"])

            reset_at = window.get("resetsAt")
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
                provider="codex",
                observed_at=observed_at,
                availability=availability,
                source=CapacityObservationSource.PROVIDER_TELEMETRY,
                remaining_capacity=remaining,
                capacity_unit="fraction",
                reset_at=reset_at,
            )
            observations.append(
                ProviderCapacityPoolObservation(
                    capacity_pool=f"{limit_id}-{_window_pool_suffix(window, slot)}",
                    observation=neutral,
                    provenance="codex-app-server/account/rateLimits/read",
                )
            )

    return tuple(observations)
