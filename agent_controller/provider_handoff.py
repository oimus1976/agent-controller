from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from agent_controller.artifact_verifier import (
    GitHubArtifactReadClient,
    verify_github_artifact,
)
from agent_controller.binding_validator import (
    BindingValidation,
    validate_artifact_binding,
    validate_observation_binding,
    validate_operation_binding,
)
from agent_controller.provider_contract import (
    AgentObservation,
    ArtifactEvidence,
    ControllerState,
    ProviderOperationRef,
    TaskBinding,
    TerminalClaim,
    VerificationResult,
)


class ObservationReader(Protocol):
    def observe(self, operation: ProviderOperationRef) -> AgentObservation:
        ...


class ArtifactCollector(Protocol):
    def collect_artifacts(self, operation: ProviderOperationRef) -> Sequence[ArtifactEvidence]:
        ...


@dataclass(frozen=True)
class VerifiedHandoffResult:
    binding: BindingValidation
    observation: AgentObservation | None
    artifacts: Sequence[ArtifactEvidence]
    verification_result: VerificationResult


def _aggregate_artifact_results(artifacts: Sequence[ArtifactEvidence]) -> VerificationResult:
    if not artifacts:
        return VerificationResult.BLOCKED

    results = {artifact.verification_result for artifact in artifacts}
    if VerificationResult.FAIL in results:
        return VerificationResult.FAIL
    if VerificationResult.BLOCKED in results:
        return VerificationResult.BLOCKED
    if VerificationResult.UNCERTAIN in results:
        return VerificationResult.UNCERTAIN
    if results == {VerificationResult.PASS} and all(
        artifact.independently_verified for artifact in artifacts
    ):
        return VerificationResult.PASS
    return VerificationResult.UNCERTAIN


def run_verified_handoff(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    observer: ObservationReader,
    artifact_collector: ArtifactCollector,
    github: GitHubArtifactReadClient,
) -> VerifiedHandoffResult:
    """Run the provider-neutral read-only handoff path after dispatch.

    Identity binding is checked before provider reads. Artifact collection is
    attempted only when the normalized provider observation claims terminal
    success and is mapped to ARTIFACT_READY. Artifact identities are checked
    before any artifact can be promoted by GitHub verification. Overall
    verification success is explicit and separate from binding validity. The
    flow never branches on provider name.
    """

    operation_binding = validate_operation_binding(task=task, operation=operation)
    if not operation_binding.valid:
        return VerifiedHandoffResult(
            operation_binding,
            None,
            (),
            VerificationResult.BLOCKED,
        )

    observation = observer.observe(operation)
    observation_binding = validate_observation_binding(
        operation=operation,
        observation=observation,
    )
    if not observation_binding.valid:
        return VerifiedHandoffResult(
            observation_binding,
            observation,
            (),
            VerificationResult.BLOCKED,
        )

    if (
        observation.mapped_state is not ControllerState.ARTIFACT_READY
        or observation.terminal_claim is not TerminalClaim.SUCCESS
    ):
        return VerifiedHandoffResult(
            BindingValidation(False, "OBSERVATION_NOT_ARTIFACT_READY_SUCCESS"),
            observation,
            (),
            VerificationResult.BLOCKED,
        )

    raw_artifacts = artifact_collector.collect_artifacts(operation)
    verified_artifacts = []
    for artifact in raw_artifacts:
        artifact_binding = validate_artifact_binding(
            operation=operation,
            artifact=artifact,
        )
        if not artifact_binding.valid:
            # Never return partially verified evidence from an invalid chain.
            return VerifiedHandoffResult(
                artifact_binding,
                observation,
                (),
                VerificationResult.BLOCKED,
            )

        verified_artifacts.append(
            verify_github_artifact(
                task=task,
                operation=operation,
                evidence=artifact,
                github=github,
            )
        )

    verified_artifacts = tuple(verified_artifacts)
    return VerifiedHandoffResult(
        BindingValidation(True),
        observation,
        verified_artifacts,
        _aggregate_artifact_results(verified_artifacts),
    )
