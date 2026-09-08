from __future__ import annotations

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


def _finite_fraction(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError("remaining_fraction must be a finite number")
    fraction = float(value)
    if fraction < 0 or fraction > 1:
        raise ValueError("remaining_fraction must be within [0, 1]")
    return fraction


def parse_antigravity_statusline_capacity(
    payload: str,
    *,
    controller_task_id: str,
    workstream_id: str,
    operation_id: str,
    operation_version: str,
    observed_at: str,
) -> tuple[ProviderCapacityPoolObservation, ...]:
    """Parse documented Antigravity CLI status-line quota JSON.

    The status-line payload is a supported machine-readable CLI surface. `/usage`
    remains an interactive TUI refresh/view command and is intentionally not scraped.
    This parser is pure and performs no CLI, provider, billing, routing, or GitHub
    effects.
    """

    if not isinstance(payload, str):
        raise TypeError("payload must be str")
    try:
        root = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed Antigravity statusline JSON") from exc

    if not isinstance(root, Mapping):
        raise ValueError("Antigravity statusline root must be an object")

    status = root.get("status")
    error = root.get("error")
    if error not in (None, "") or (
        isinstance(status, str) and status.strip().upper() in {"ERROR", "FAILED", "FAILURE"}
    ):
        raise ValueError("Antigravity error envelope is not capacity telemetry")

    if root.get("product") != "antigravity":
        raise ValueError("statusline product is not antigravity")

    version = root.get("version")
    if not _nonempty_string(version):
        raise ValueError("Antigravity CLI version is required")

    quota = root.get("quota")
    if not isinstance(quota, Mapping) or not quota:
        raise ValueError("Antigravity quota object is required and must be nonempty")

    observations: list[ProviderCapacityPoolObservation] = []
    for pool_id in sorted(quota):
        if not _nonempty_string(pool_id):
            raise ValueError("quota pool id must be nonempty")
        item = quota[pool_id]
        if not isinstance(item, Mapping):
            raise ValueError("quota pool status must be an object")

        if "remaining_fraction" not in item:
            raise ValueError("remaining_fraction is required")
        remaining = _finite_fraction(item["remaining_fraction"])

        reset_at = item.get("reset_time")
        if reset_at is not None and not _nonempty_string(reset_at):
            raise ValueError("reset_time must be a nonempty string when present")

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
            provider="antigravity",
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
                provenance=f"antigravity-cli-statusline/{version}",
            )
        )

    return tuple(observations)
