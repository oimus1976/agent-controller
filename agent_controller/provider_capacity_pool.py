from __future__ import annotations

from dataclasses import dataclass

from agent_controller.provider_capacity import ProviderCapacityObservation


def _require_nonempty_string(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be nonempty")
    return value


@dataclass(frozen=True)
class ProviderCapacityPoolObservation:
    """Bind one provider-neutral capacity observation to a distinct quota pool.

    This additive wrapper lets provider adapters preserve multiple independent
    quota/model buckets without forcing the existing provider-level recommendation
    function to invent an aggregation rule. Routing across pools remains a later
    concern once a task/model can be bound to the relevant pool.
    """

    capacity_pool: str
    observation: ProviderCapacityObservation
    provenance: str

    def __post_init__(self) -> None:
        _require_nonempty_string("capacity_pool", self.capacity_pool)
        _require_nonempty_string("provenance", self.provenance)
        if not isinstance(self.observation, ProviderCapacityObservation):
            raise TypeError("observation must be ProviderCapacityObservation")
