from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from agent_controller.provider_clients import ProviderReadClient
from agent_controller.provider_contract import AgentObservation, ProviderOperationRef
from agent_controller.provider_mappers import (
    map_codex_observation,
    map_jules_observation,
)


ObservedAtFactory = Callable[[], str]


@dataclass(frozen=True)
class JulesObservationAdapter:
    """Thin read-only Jules observation adapter.

    This is intentionally not a complete AgentAdapter yet. It exposes no
    dispatch or provider mutation capability. The injected client supplies a
    raw provider observation, and the pure Jules mapper performs all state
    interpretation.
    """

    client: ProviderReadClient
    observed_at: ObservedAtFactory

    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        if operation.provider != "jules":
            raise ValueError("JulesObservationAdapter requires provider='jules'")
        raw_state = self.client.get_operation_raw(operation)
        return map_jules_observation(
            provider_operation_id=operation.provider_operation_id,
            raw_state=raw_state,
            observed_at=self.observed_at(),
        )


@dataclass(frozen=True)
class CodexObservationAdapter:
    """Thin read-only Codex observation adapter.

    This is intentionally not a complete AgentAdapter yet. It exposes no
    dispatch or provider mutation capability. The injected client supplies a
    raw provider observation, and the pure Codex mapper performs all state
    interpretation.
    """

    client: ProviderReadClient
    observed_at: ObservedAtFactory

    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        if operation.provider != "codex":
            raise ValueError("CodexObservationAdapter requires provider='codex'")
        raw_state = self.client.get_operation_raw(operation)
        return map_codex_observation(
            provider_operation_id=operation.provider_operation_id,
            raw_state=raw_state,
            observed_at=self.observed_at(),
        )
