from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Protocol, runtime_checkable

from agent_controller.binding_validator import validate_operation_binding
from agent_controller.provider_adapters import (
    CodexObservationAdapter,
    JulesObservationAdapter,
)
from agent_controller.provider_artifacts import (
    CodexArtifactAdapter,
    JulesArtifactAdapter,
)
from agent_controller.provider_contract import (
    AgentObservation,
    ArtifactEvidence,
    ProviderOperationRef,
    TaskBinding,
)


@runtime_checkable
class ProviderDispatchClient(Protocol):
    """Injectable provider dispatch seam used by the PN1 contract proof.

    No concrete network implementation is included in PN1. A future provider
    integration may wrap an official SDK/CLI/Action behind this boundary.
    """

    def dispatch(self, task: TaskBinding) -> ProviderOperationRef:
        ...


@dataclass(frozen=True)
class AdapterCapabilities:
    """Optional provider capabilities, deliberately outside AgentAdapter."""

    values: FrozenSet[str] = frozenset()

    def supports(self, capability: str) -> bool:
        return capability in self.values


@dataclass(frozen=True)
class JulesAgentAdapter:
    dispatch_client: ProviderDispatchClient
    observation: JulesObservationAdapter
    artifacts: JulesArtifactAdapter
    capabilities: AdapterCapabilities = AdapterCapabilities()

    def dispatch(self, task: TaskBinding) -> ProviderOperationRef:
        if task.provider != "jules":
            raise ValueError("JulesAgentAdapter requires task.provider='jules'")
        operation = self.dispatch_client.dispatch(task)
        binding = validate_operation_binding(task=task, operation=operation)
        if not binding.valid:
            raise ValueError(f"invalid dispatched operation binding: {binding.reason}")
        return operation

    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        return self.observation.observe(operation)

    def collect_artifacts(self, operation: ProviderOperationRef) -> list[ArtifactEvidence]:
        return list(self.artifacts.collect_artifacts(operation))


@dataclass(frozen=True)
class CodexAgentAdapter:
    dispatch_client: ProviderDispatchClient
    observation: CodexObservationAdapter
    artifacts: CodexArtifactAdapter
    capabilities: AdapterCapabilities = AdapterCapabilities()

    def dispatch(self, task: TaskBinding) -> ProviderOperationRef:
        if task.provider != "codex":
            raise ValueError("CodexAgentAdapter requires task.provider='codex'")
        operation = self.dispatch_client.dispatch(task)
        binding = validate_operation_binding(task=task, operation=operation)
        if not binding.valid:
            raise ValueError(f"invalid dispatched operation binding: {binding.reason}")
        return operation

    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        return self.observation.observe(operation)

    def collect_artifacts(self, operation: ProviderOperationRef) -> list[ArtifactEvidence]:
        return list(self.artifacts.collect_artifacts(operation))
