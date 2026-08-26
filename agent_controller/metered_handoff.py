from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from agent_controller.artifact_verifier import GitHubArtifactReadClient
from agent_controller.provider_contract import AgentObservation, ArtifactEvidence, ProviderOperationRef, TaskBinding
from agent_controller.provider_handoff import ArtifactCollector, ObservationReader, VerifiedHandoffResult, run_verified_handoff
from agent_controller.resource_meter import ControllerResourceMeter, ResourceMeterBinding
from agent_controller.resource_usage import ResourceUsageObservation


class MeteredObservationReader:
    def __init__(self, *, inner: ObservationReader, meter: ControllerResourceMeter) -> None:
        self._inner = inner
        self._meter = meter

    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        self._meter.record_tool_call()
        return self._inner.observe(operation)


class MeteredArtifactCollector:
    def __init__(self, *, inner: ArtifactCollector, meter: ControllerResourceMeter) -> None:
        self._inner = inner
        self._meter = meter

    def collect_artifacts(self, operation: ProviderOperationRef) -> Sequence[ArtifactEvidence]:
        self._meter.record_tool_call()
        return self._inner.collect_artifacts(operation)


class MeteredGitHubArtifactReadClient:
    def __init__(self, *, inner: GitHubArtifactReadClient, meter: ControllerResourceMeter) -> None:
        self._inner = inner
        self._meter = meter

    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        self._meter.record_tool_call()
        return self._inner.get_ref_sha(repo, ref)

    def compare_commits(self, repo: str, base_sha: str, head_sha: str) -> Mapping[str, Any]:
        self._meter.record_tool_call()
        return self._inner.compare_commits(repo, base_sha, head_sha)

    def get_pull_request(self, repo: str, pr_number: int) -> Mapping[str, Any]:
        method = getattr(self._inner, "get_pull_request", None)
        if method is None:
            raise AttributeError("wrapped GitHub client does not provide get_pull_request")
        self._meter.record_tool_call()
        return method(repo, pr_number)


@dataclass(frozen=True)
class MeteredVerifiedHandoffResult:
    handoff: VerifiedHandoffResult
    resource_usage: ResourceUsageObservation


def run_metered_verified_handoff(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    observer: ObservationReader,
    artifact_collector: ArtifactCollector,
    github: GitHubArtifactReadClient,
    controller_run_id: str,
) -> MeteredVerifiedHandoffResult:
    """Measure Controller-owned read/tool calls around the existing handoff path.

    This wrapper deliberately does not change handoff verification semantics and
    makes no token-savings claim. Because the current MVP operation contract has
    no operation-version field, this adapter binds the meter to the stable
    explicit compatibility version ``mvp-v1`` rather than widening core models.
    """

    meter = ControllerResourceMeter(
        binding=ResourceMeterBinding(
            controller_task_id=task.controller_task_id,
            operation_id=task.operation_id,
            operation_version="mvp-v1",
            provider=task.provider,
            controller_run_id=controller_run_id,
        )
    )
    handoff = run_verified_handoff(
        task=task,
        operation=operation,
        observer=MeteredObservationReader(inner=observer, meter=meter),
        artifact_collector=MeteredArtifactCollector(inner=artifact_collector, meter=meter),
        github=MeteredGitHubArtifactReadClient(inner=github, meter=meter),
    )
    return MeteredVerifiedHandoffResult(handoff=handoff, resource_usage=meter.finalize())
