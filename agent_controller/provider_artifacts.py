from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Protocol, runtime_checkable

from agent_controller.provider_contract import ArtifactEvidence, ProviderOperationRef


@runtime_checkable
class ProviderArtifactReadClient(Protocol):
    """Read-only boundary for provider-reported artifacts.

    This capability is deliberately separate from operation observation so a
    provider may support one without being forced to expose the other.
    """

    def list_artifacts_raw(self, operation: ProviderOperationRef) -> Iterable[Any]:
        ...


def _string(value: Any):
    return value if isinstance(value, str) and value else None


def _map_artifact(
    *,
    provider: str,
    provider_operation_id: str,
    raw_artifact: Any,
    observed_at: str,
) -> ArtifactEvidence:
    if not isinstance(raw_artifact, Mapping):
        return ArtifactEvidence(
            provider=provider,
            provider_operation_id=provider_operation_id,
            artifact_kind="unknown",
            provider_artifact_id=None,
            provider_reported_ref=None,
            provider_reported_sha=None,
            content_hash=None,
            observed_at=observed_at,
            freshness_basis="provider_report_unparseable",
        )

    return ArtifactEvidence(
        provider=provider,
        provider_operation_id=provider_operation_id,
        artifact_kind=_string(raw_artifact.get("kind")) or "unknown",
        provider_artifact_id=_string(raw_artifact.get("id")),
        provider_reported_ref=_string(raw_artifact.get("ref")),
        provider_reported_sha=_string(raw_artifact.get("sha")),
        content_hash=_string(raw_artifact.get("content_hash")),
        observed_at=observed_at,
        freshness_basis=_string(raw_artifact.get("freshness_basis")) or "provider_report",
    )


def map_jules_artifact(
    *,
    provider_operation_id: str,
    raw_artifact: Any,
    observed_at: str,
) -> ArtifactEvidence:
    """Normalize one Jules-reported artifact without verifying it."""
    return _map_artifact(
        provider="jules",
        provider_operation_id=provider_operation_id,
        raw_artifact=raw_artifact,
        observed_at=observed_at,
    )


def map_codex_artifact(
    *,
    provider_operation_id: str,
    raw_artifact: Any,
    observed_at: str,
) -> ArtifactEvidence:
    """Normalize one Codex-reported artifact without verifying it."""
    return _map_artifact(
        provider="codex",
        provider_operation_id=provider_operation_id,
        raw_artifact=raw_artifact,
        observed_at=observed_at,
    )


ObservedAtFactory = Callable[[], str]


@dataclass(frozen=True)
class JulesArtifactAdapter:
    client: ProviderArtifactReadClient
    observed_at: ObservedAtFactory

    def collect_artifacts(self, operation: ProviderOperationRef):
        if operation.provider != "jules":
            raise ValueError("JulesArtifactAdapter requires provider='jules'")
        observed_at = self.observed_at()
        return [
            map_jules_artifact(
                provider_operation_id=operation.provider_operation_id,
                raw_artifact=raw,
                observed_at=observed_at,
            )
            for raw in self.client.list_artifacts_raw(operation)
        ]


@dataclass(frozen=True)
class CodexArtifactAdapter:
    client: ProviderArtifactReadClient
    observed_at: ObservedAtFactory

    def collect_artifacts(self, operation: ProviderOperationRef):
        if operation.provider != "codex":
            raise ValueError("CodexArtifactAdapter requires provider='codex'")
        observed_at = self.observed_at()
        return [
            map_codex_artifact(
                provider_operation_id=operation.provider_operation_id,
                raw_artifact=raw,
                observed_at=observed_at,
            )
            for raw in self.client.list_artifacts_raw(operation)
        ]
