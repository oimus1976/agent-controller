from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from agent_controller.provider_contract import (
    AgentObservation,
    ArtifactEvidence,
    ProviderOperationRef,
    TaskBinding,
)


@dataclass(frozen=True)
class BindingValidation:
    valid: bool
    reason: Optional[str] = None


def validate_operation_binding(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
) -> BindingValidation:
    """Validate task -> provider operation identity before provider I/O."""

    if operation.controller_task_id != task.controller_task_id:
        return BindingValidation(False, "CONTROLLER_TASK_ID_MISMATCH")
    if operation.operation_id != task.operation_id:
        return BindingValidation(False, "OPERATION_ID_MISMATCH")
    if operation.provider != task.provider:
        return BindingValidation(False, "PROVIDER_MISMATCH")
    if not operation.provider_operation_id:
        return BindingValidation(False, "PROVIDER_OPERATION_ID_MISSING")
    return BindingValidation(True)


def validate_observation_binding(
    *,
    operation: ProviderOperationRef,
    observation: AgentObservation,
) -> BindingValidation:
    """Validate provider observation identity against the bound operation."""

    if observation.provider != operation.provider:
        return BindingValidation(False, "OBSERVATION_PROVIDER_MISMATCH")
    if observation.provider_operation_id != operation.provider_operation_id:
        return BindingValidation(False, "OBSERVATION_OPERATION_ID_MISMATCH")
    return BindingValidation(True)


def validate_artifact_binding(
    *,
    operation: ProviderOperationRef,
    artifact: ArtifactEvidence,
) -> BindingValidation:
    """Validate provider artifact identity against the bound operation."""

    if artifact.provider != operation.provider:
        return BindingValidation(False, "ARTIFACT_PROVIDER_MISMATCH")
    if artifact.provider_operation_id != operation.provider_operation_id:
        return BindingValidation(False, "ARTIFACT_OPERATION_ID_MISMATCH")
    return BindingValidation(True)


def validate_evidence_chain(
    *,
    task: TaskBinding,
    operation: ProviderOperationRef,
    observation: AgentObservation | None = None,
    artifact: ArtifactEvidence | None = None,
) -> BindingValidation:
    """Validate the complete task -> operation -> evidence chain.

    The first mismatch wins so callers get a deterministic fail-closed reason.
    """

    result = validate_operation_binding(task=task, operation=operation)
    if not result.valid:
        return result

    if observation is not None:
        result = validate_observation_binding(operation=operation, observation=observation)
        if not result.valid:
            return result

    if artifact is not None:
        result = validate_artifact_binding(operation=operation, artifact=artifact)
        if not result.valid:
            return result

    return BindingValidation(True)
