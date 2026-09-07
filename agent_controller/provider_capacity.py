from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import math
from typing import Optional, Sequence


class ProviderAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    EXHAUSTED = "EXHAUSTED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class CapacityObservationSource(str, Enum):
    ACCOUNT_TELEMETRY = "ACCOUNT_TELEMETRY"
    PROVIDER_TELEMETRY = "PROVIDER_TELEMETRY"
    CONTROLLER_MEASURED = "CONTROLLER_MEASURED"
    OPERATOR_OBSERVED = "OPERATOR_OBSERVED"
    UNKNOWN = "UNKNOWN"


class ProviderDeferralReason(str, Enum):
    INSUFFICIENT_CAPABILITY = "INSUFFICIENT_CAPABILITY"
    PAID_USAGE_NOT_AUTHORIZED = "PAID_USAGE_NOT_AUTHORIZED"
    CAPACITY_EXHAUSTED = "CAPACITY_EXHAUSTED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    CAPACITY_REOBSERVATION_REQUIRED = "CAPACITY_REOBSERVATION_REQUIRED"
    PRESERVE_SCARCE_REVIEW_PROVIDER = "PRESERVE_SCARCE_REVIEW_PROVIDER"


def _require_nonempty_string(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be nonempty")
    return value


def _parse_aware_iso8601(name: str, value: str) -> datetime:
    _require_nonempty_string(name, value)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone offset")
    return parsed


def _require_aware_iso8601(name: str, value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    _parse_aware_iso8601(name, value)
    return value


@dataclass(frozen=True)
class ProviderCapacityObservation:
    controller_task_id: str
    workstream_id: str
    operation_id: str
    operation_version: str
    provider: str
    observed_at: str
    availability: ProviderAvailability
    source: CapacityObservationSource
    remaining_capacity: Optional[float] = None
    capacity_unit: Optional[str] = None
    reset_at: Optional[str] = None

    def __post_init__(self) -> None:
        for field_name in (
            "controller_task_id",
            "workstream_id",
            "operation_id",
            "operation_version",
            "provider",
        ):
            _require_nonempty_string(field_name, getattr(self, field_name))
        _require_aware_iso8601("observed_at", self.observed_at)
        _require_aware_iso8601("reset_at", self.reset_at)
        if not isinstance(self.availability, ProviderAvailability):
            raise TypeError("availability must be ProviderAvailability")
        if not isinstance(self.source, CapacityObservationSource):
            raise TypeError("source must be CapacityObservationSource")

        if self.remaining_capacity is not None:
            value = self.remaining_capacity
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or value < 0
            ):
                raise ValueError("remaining_capacity must be a finite non-negative number when present")
            object.__setattr__(self, "remaining_capacity", float(value))
        if self.capacity_unit is not None:
            _require_nonempty_string("capacity_unit", self.capacity_unit)
        if (self.remaining_capacity is None) != (self.capacity_unit is None):
            raise ValueError("remaining_capacity and capacity_unit must be present together")

    @property
    def provider_or_account_telemetry(self) -> bool:
        return self.source in {
            CapacityObservationSource.ACCOUNT_TELEMETRY,
            CapacityObservationSource.PROVIDER_TELEMETRY,
        }


@dataclass(frozen=True)
class ProviderCandidate:
    provider: str
    capability_eligible: bool
    additional_paid_usage_required: bool = False

    def __post_init__(self) -> None:
        _require_nonempty_string("provider", self.provider)
        if not isinstance(self.capability_eligible, bool):
            raise TypeError("capability_eligible must be bool")
        if not isinstance(self.additional_paid_usage_required, bool):
            raise TypeError("additional_paid_usage_required must be bool")


@dataclass(frozen=True)
class DeferredProvider:
    provider: str
    reason: ProviderDeferralReason

    def __post_init__(self) -> None:
        _require_nonempty_string("provider", self.provider)
        if not isinstance(self.reason, ProviderDeferralReason):
            raise TypeError("reason must be ProviderDeferralReason")


@dataclass(frozen=True)
class ProviderRecommendation:
    controller_task_id: str
    workstream_id: str
    operation_id: str
    operation_version: str
    decision_at: str
    recommendation: Optional[str]
    eligible: tuple[str, ...]
    deferred: tuple[DeferredProvider, ...]
    reason_codes: tuple[str, ...]


_AVAILABILITY_RANK = {
    ProviderAvailability.AVAILABLE: 0,
    ProviderAvailability.DEGRADED: 1,
    ProviderAvailability.UNKNOWN: 2,
}


def recommend_provider(
    *,
    controller_task_id: str,
    workstream_id: str,
    operation_id: str,
    operation_version: str,
    decision_at: str,
    candidates: Sequence[ProviderCandidate],
    capacity_observations: Sequence[ProviderCapacityObservation],
    max_observation_validity_seconds: float,
    reserved_independent_review_provider: Optional[str] = None,
    paid_usage_authorized: bool = False,
) -> ProviderRecommendation:
    """Return a pure advisory recommendation for any provider operation.

    ``decision_at`` makes the recommendation replayable and lets reset/replenishment
    boundaries invalidate old capacity evidence. Reaching ``reset_at`` never promotes
    a provider to AVAILABLE; that provider is deferred until a fresh observation is
    supplied. This function performs no provider or GitHub effects.
    """

    for name, value in (
        ("controller_task_id", controller_task_id),
        ("workstream_id", workstream_id),
        ("operation_id", operation_id),
        ("operation_version", operation_version),
    ):
        _require_nonempty_string(name, value)
    decision_time = _parse_aware_iso8601("decision_at", decision_at)
    if reserved_independent_review_provider is not None:
        _require_nonempty_string(
            "reserved_independent_review_provider", reserved_independent_review_provider
        )
    if not isinstance(paid_usage_authorized, bool):
        raise TypeError("paid_usage_authorized must be bool")
    if (
        isinstance(max_observation_validity_seconds, bool)
        or not isinstance(max_observation_validity_seconds, (int, float))
        or not math.isfinite(float(max_observation_validity_seconds))
        or max_observation_validity_seconds <= 0
    ):
        raise ValueError("max_observation_validity_seconds must be a finite positive number")
    max_observation_validity_seconds = float(max_observation_validity_seconds)

    candidate_by_provider: dict[str, ProviderCandidate] = {}
    for candidate in candidates:
        if not isinstance(candidate, ProviderCandidate):
            raise TypeError("candidates must contain ProviderCandidate")
        if candidate.provider in candidate_by_provider:
            raise ValueError("candidate providers must be unique")
        candidate_by_provider[candidate.provider] = candidate

    eligible = tuple(
        provider
        for provider in sorted(candidate_by_provider)
        if candidate_by_provider[provider].capability_eligible
    )

    observation_by_provider: dict[str, ProviderCapacityObservation] = {}
    expected_binding = (
        controller_task_id,
        workstream_id,
        operation_id,
        operation_version,
    )
    for observation in capacity_observations:
        if not isinstance(observation, ProviderCapacityObservation):
            raise TypeError("capacity_observations must contain ProviderCapacityObservation")
        observed_binding = (
            observation.controller_task_id,
            observation.workstream_id,
            observation.operation_id,
            observation.operation_version,
        )
        if observed_binding != expected_binding:
            raise ValueError("capacity observation binding mismatch")
        if observation.provider in observation_by_provider:
            raise ValueError("capacity observations must be unique per provider")
        if _parse_aware_iso8601("observed_at", observation.observed_at) > decision_time:
            raise ValueError("capacity observation cannot be newer than decision_at")
        observation_by_provider[observation.provider] = observation

    deferred: list[DeferredProvider] = []
    usable: list[tuple[int, str]] = []

    for provider in sorted(candidate_by_provider):
        candidate = candidate_by_provider[provider]
        if not candidate.capability_eligible:
            deferred.append(
                DeferredProvider(provider, ProviderDeferralReason.INSUFFICIENT_CAPABILITY)
            )
            continue
        if candidate.additional_paid_usage_required and not paid_usage_authorized:
            deferred.append(
                DeferredProvider(provider, ProviderDeferralReason.PAID_USAGE_NOT_AUTHORIZED)
            )
            continue

        observation = observation_by_provider.get(provider)
        if observation is not None:
            observed_at = _parse_aware_iso8601("observed_at", observation.observed_at)
            freshness_expired = (
                decision_time - observed_at
            ).total_seconds() >= max_observation_validity_seconds

            reset_expired = False
            if observation.reset_at is not None:
                reset_time = _parse_aware_iso8601("reset_at", observation.reset_at)
                reset_expired = decision_time >= reset_time

            if freshness_expired or reset_expired:
                deferred.append(
                    DeferredProvider(
                        provider, ProviderDeferralReason.CAPACITY_REOBSERVATION_REQUIRED
                    )
                )
                continue

        availability = (
            observation.availability if observation is not None else ProviderAvailability.UNKNOWN
        )
        if availability == ProviderAvailability.EXHAUSTED:
            deferred.append(
                DeferredProvider(provider, ProviderDeferralReason.CAPACITY_EXHAUSTED)
            )
            continue
        if availability == ProviderAvailability.UNAVAILABLE:
            deferred.append(
                DeferredProvider(provider, ProviderDeferralReason.PROVIDER_UNAVAILABLE)
            )
            continue

        usable.append((_AVAILABILITY_RANK[availability], provider))

    preserved_review_provider = False
    if reserved_independent_review_provider is not None and len(usable) > 1:
        retained: list[tuple[int, str]] = []
        for item in usable:
            if item[1] == reserved_independent_review_provider:
                deferred.append(
                    DeferredProvider(
                        item[1], ProviderDeferralReason.PRESERVE_SCARCE_REVIEW_PROVIDER
                    )
                )
                preserved_review_provider = True
            else:
                retained.append(item)
        if retained:
            usable = retained

    usable.sort()
    recommendation = usable[0][1] if usable else None

    reason_codes: list[str] = []
    if recommendation is not None:
        reason_codes.append("CAPABILITY_MATCH")
        observation = observation_by_provider.get(recommendation)
        availability = (
            observation.availability if observation is not None else ProviderAvailability.UNKNOWN
        )
        if availability == ProviderAvailability.AVAILABLE:
            reason_codes.append("AVAILABLE_CAPACITY")
        elif availability == ProviderAvailability.DEGRADED:
            reason_codes.append("DEGRADED_CAPACITY")
        else:
            reason_codes.append("CAPACITY_UNKNOWN")
        if preserved_review_provider:
            reason_codes.append("PRESERVE_SCARCE_REVIEW_PROVIDER")
        candidate = candidate_by_provider[recommendation]
        reason_codes.append(
            "PAID_USAGE_AUTHORIZED"
            if candidate.additional_paid_usage_required
            else "NO_ADDITIONAL_COST"
        )

    return ProviderRecommendation(
        controller_task_id=controller_task_id,
        workstream_id=workstream_id,
        operation_id=operation_id,
        operation_version=operation_version,
        decision_at=decision_at,
        recommendation=recommendation,
        eligible=eligible,
        deferred=tuple(deferred),
        reason_codes=tuple(reason_codes),
    )
