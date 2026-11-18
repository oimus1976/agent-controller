from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Iterable, Optional

from agent_controller.provider_capacity import ProviderAvailability
from agent_controller.provider_capacity_pool import ProviderCapacityPoolObservation


"""Convert neutral pool observations into life-dashboard ai-usage records.

The dashboard contract lives in life-dashboard
``client/src/lib/ai-usage-types.ts`` (``AiUsageObservation`` /
``AiUsageDocument``, guarded by ``validateAiUsageDocument``). This module is
the single place that knows both shapes:

- Input records are :class:`ProviderCapacityPoolObservation` values produced
  by the provider parsers (Claude Code status line, Codex app-server,
  Antigravity status line). The controller binding fields
  (``controller_task_id`` and friends) exist only to bind observations to a
  controller decision; the dashboard record has no such fields, so they are
  dropped here and never leak into the export.
- Pools are exported one record per pool, verbatim. Nothing is aggregated
  into a single invented remainder.
- Timestamps are normalized to the dashboard's exact format
  (``YYYY-MM-DDTHH:MM:SS.mmmZ``, UTC): the parsers emit second-precision
  ISO-8601, which the dashboard validator rejects.
- Records describe real observations taken on the owner's machine, so
  ``data_status`` is ``confirmed`` and ``privacy_class`` is ``private-low``
  (the owner's own usage figures; the dashboard refuses sensitive/restricted
  fixture records at its bundle boundary).
- Every parser in this repository models quota windows only, so
  ``capacity_kind`` is always ``window``. Codex credits are a balance, not a
  window; the Codex parser already drops them, and modeling them as a
  separate ``credits`` pool remains a future extension point that must not
  be folded into window records here.

Conversion fails closed: any observation that cannot be represented exactly
in the dashboard contract (unknown provider, malformed pool id, a measured
fraction on an UNKNOWN pool, a fraction/unit mismatch, an over-long
provenance, duplicate record ids) raises ``ValueError`` instead of emitting
a record the dashboard would reject or misread.
"""

DASHBOARD_DOCUMENT_VERSION = "1.0"
DASHBOARD_DOCUMENT_KIND = "ai-usage-observations"
DASHBOARD_SCHEMA_VERSION = "1.0"
DASHBOARD_SOURCE_KIND = "manual"
DASHBOARD_SOURCE_PROVENANCE = (
    "Collected locally by agent-controller capacity_collect from provider "
    "telemetry on the owner's machine; imported manually, never pushed by "
    "the collector"
)
DASHBOARD_MAX_OBSERVATIONS = 200

_PROVIDERS = frozenset({"claude-code", "codex", "antigravity"})
_POOL_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_RECORD_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_CONTROL_CHARS = re.compile(r"[\u0000-\u001f\u007f]")


def _require_dashboard_text(name: str, value: object, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or _CONTROL_CHARS.search(value)
    ):
        raise ValueError(f"{name} must be bounded dashboard text")
    return value


def _dashboard_timestamp(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone offset")
    utc = parsed.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _optional_dashboard_timestamp(name: str, value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return _dashboard_timestamp(name, value)


def pool_observation_to_dashboard_record(
    pool_observation: ProviderCapacityPoolObservation,
) -> dict:
    """Convert one pool observation into one dashboard observation record."""

    if not isinstance(pool_observation, ProviderCapacityPoolObservation):
        raise TypeError("pool_observation must be ProviderCapacityPoolObservation")
    observation = pool_observation.observation

    provider = observation.provider
    if provider not in _PROVIDERS:
        raise ValueError(f"provider is not a dashboard provider: {provider!r}")

    capacity_pool = pool_observation.capacity_pool
    if not _POOL_ID_PATTERN.match(capacity_pool):
        raise ValueError(f"capacity_pool is not a dashboard pool id: {capacity_pool!r}")

    record_id = f"ai-usage-{provider}-{capacity_pool}"
    if not _RECORD_ID_PATTERN.match(record_id):
        raise ValueError(f"record id is not a dashboard id: {record_id!r}")

    remaining = observation.remaining_capacity
    unit = observation.capacity_unit
    if (remaining is None) != (unit is None):
        raise ValueError("remaining_capacity and capacity_unit must be present together")
    if remaining is not None:
        if unit != "fraction":
            raise ValueError(f"capacity_unit is not representable on the dashboard: {unit!r}")
        if remaining < 0 or remaining > 1:
            raise ValueError("remaining_capacity must be within [0, 1] for the dashboard")
        if observation.availability is ProviderAvailability.UNKNOWN:
            raise ValueError("UNKNOWN availability cannot carry a measured fraction")
        if remaining == 0 and observation.availability is not ProviderAvailability.EXHAUSTED:
            raise ValueError("a measured 0 fraction requires EXHAUSTED availability")

    observed_at = _dashboard_timestamp("observed_at", observation.observed_at)
    provenance = _require_dashboard_text("provenance", pool_observation.provenance)

    return {
        "id": record_id,
        "provider": provider,
        "capacity_pool": capacity_pool,
        "capacity_kind": "window",
        "availability": observation.availability.value,
        "observation_source": observation.source.value,
        "remaining_fraction": remaining,
        "capacity_unit": unit,
        "reset_at": _optional_dashboard_timestamp("reset_at", observation.reset_at),
        "observed_at": observed_at,
        "provenance": provenance,
        "source": {
            "source_kind": DASHBOARD_SOURCE_KIND,
            "provenance": DASHBOARD_SOURCE_PROVENANCE,
            "schema_version": DASHBOARD_SCHEMA_VERSION,
            "data_status": "confirmed",
            "privacy_class": "private-low",
            "pushed_at": None,
            "last_verified_at": observed_at,
        },
    }


def pool_observations_to_dashboard_records(
    pool_observations: Iterable[ProviderCapacityPoolObservation],
) -> list[dict]:
    """Convert pool observations to dashboard records, rejecting duplicates."""

    records: list[dict] = []
    seen_ids: set[str] = set()
    for pool_observation in pool_observations:
        record = pool_observation_to_dashboard_record(pool_observation)
        if record["id"] in seen_ids:
            raise ValueError(f"duplicate dashboard record id: {record['id']}")
        seen_ids.add(record["id"])
        records.append(record)
    return records


def dashboard_document(records: Iterable[dict]) -> dict:
    """Wrap dashboard records in the ``AiUsageDocument`` envelope."""

    materialized = list(records)
    if len(materialized) > DASHBOARD_MAX_OBSERVATIONS:
        raise ValueError("dashboard document exceeds the observation limit")
    seen_ids: set[str] = set()
    for record in materialized:
        record_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(record_id, str) or not _RECORD_ID_PATTERN.match(record_id):
            raise ValueError("dashboard record id is invalid")
        if record_id in seen_ids:
            raise ValueError(f"duplicate dashboard record id: {record_id}")
        seen_ids.add(record_id)
    return {
        "version": DASHBOARD_DOCUMENT_VERSION,
        "document_kind": DASHBOARD_DOCUMENT_KIND,
        "observations": materialized,
    }
