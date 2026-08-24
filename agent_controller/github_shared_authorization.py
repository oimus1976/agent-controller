from __future__ import annotations

import json
from typing import Optional

from agent_controller.github_controller_state import GitHubControllerStateAdapter
from agent_controller.shared_authorization import (
    AuthorizationProvenance,
    AuthorizationState,
    BackendWriteResult,
    CONTROLLER_STATE_REF,
    OperationAuthorizationBinding,
    SCHEMA_VERSION,
    SharedAuthorizationBackend,
    SharedAuthorizationRecord,
    SharedRecordSnapshot,
)


_BINDING_KEYS = frozenset({
    "approval_id", "approval_policy_id", "controller_task_id", "operation_id",
    "operation_version", "provider", "requested_capability", "effect", "repo",
    "target_kind", "target_id", "expected_head_sha",
})
_PROVENANCE_KEYS = frozenset({
    "assurance", "provenance_kind", "signer_key_id", "challenge_nonce",
    "challenge_digest", "signature_digest",
})
_RECORD_KEYS = frozenset({
    "binding", "state", "provenance", "execution_claim_id", "controller_run_id",
    "schema_version",
})


def _encode_record(record: SharedAuthorizationRecord) -> str:
    if not isinstance(record, SharedAuthorizationRecord):
        raise TypeError("record must be SharedAuthorizationRecord")
    return json.dumps(
        record.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ) + "\n"


def _optional_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def _decode_record(content: str) -> SharedAuthorizationRecord:
    if not isinstance(content, str):
        raise ValueError("state content must be text")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("state JSON invalid") from exc
    if not isinstance(data, dict) or set(data) != _RECORD_KEYS:
        raise ValueError("state record keys invalid")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("state schema invalid")

    binding_data = data.get("binding")
    if not isinstance(binding_data, dict) or set(binding_data) != _BINDING_KEYS:
        raise ValueError("state binding keys invalid")
    required_binding = (
        "approval_id", "approval_policy_id", "controller_task_id", "operation_id",
        "operation_version", "requested_capability", "effect", "target_kind",
    )
    if any(not isinstance(binding_data.get(key), str) or not binding_data[key] for key in required_binding):
        raise ValueError("state binding field invalid")
    for key in ("provider", "repo", "target_id", "expected_head_sha"):
        if not _optional_string(binding_data.get(key)):
            raise ValueError("state optional binding field invalid")
    binding = OperationAuthorizationBinding(**binding_data)

    try:
        state = AuthorizationState(data.get("state"))
    except (TypeError, ValueError) as exc:
        raise ValueError("state value invalid") from exc

    provenance_data = data.get("provenance")
    provenance: Optional[AuthorizationProvenance]
    if provenance_data is None:
        provenance = None
    else:
        if not isinstance(provenance_data, dict) or set(provenance_data) != _PROVENANCE_KEYS:
            raise ValueError("state provenance keys invalid")
        if any(not isinstance(provenance_data.get(key), str) or not provenance_data[key] for key in _PROVENANCE_KEYS):
            raise ValueError("state provenance field invalid")
        provenance = AuthorizationProvenance(**provenance_data)

    execution_claim_id = data.get("execution_claim_id")
    controller_run_id = data.get("controller_run_id")
    if not _optional_string(execution_claim_id) or not _optional_string(controller_run_id):
        raise ValueError("state execution field invalid")

    return SharedAuthorizationRecord(
        binding=binding,
        state=state,
        provenance=provenance,
        execution_claim_id=execution_claim_id,
        controller_run_id=controller_run_id,
        schema_version=data["schema_version"],
    )


class GitHubSharedAuthorizationBackend(SharedAuthorizationBackend):
    """Typed shared-authorization backend over the fixed GitHub state adapter."""

    __slots__ = ("_state",)

    def __init__(self, *, state_adapter: GitHubControllerStateAdapter) -> None:
        if not isinstance(state_adapter, GitHubControllerStateAdapter):
            raise TypeError("state_adapter must be GitHubControllerStateAdapter")
        if state_adapter.state_ref != CONTROLLER_STATE_REF:
            raise ValueError("controller state ref mismatch")
        self._state = state_adapter

    @staticmethod
    def _require_ref(state_ref: str) -> None:
        if state_ref != CONTROLLER_STATE_REF:
            raise ValueError("shared state ref mismatch")

    def read(self, *, state_ref: str, path: str) -> Optional[SharedRecordSnapshot]:
        self._require_ref(state_ref)
        snapshot = self._state.read(path=path)
        if snapshot is None:
            return None
        record = _decode_record(snapshot.content)
        return SharedRecordSnapshot(record=record, revision=snapshot.revision)

    def create_if_absent(
        self, *, state_ref: str, path: str, record: SharedAuthorizationRecord
    ) -> BackendWriteResult:
        self._require_ref(state_ref)
        content = _encode_record(record)
        result = self._state.create_if_absent(
            path=path, content=content, message="Create shared authorization state"
        )
        return BackendWriteResult(
            written=result.written,
            conflict=result.conflict,
            uncertain=result.uncertain,
            revision=result.revision,
        )

    def compare_and_swap(
        self,
        *,
        state_ref: str,
        path: str,
        expected_revision: str,
        record: SharedAuthorizationRecord,
    ) -> BackendWriteResult:
        self._require_ref(state_ref)
        content = _encode_record(record)
        result = self._state.compare_and_swap(
            path=path,
            expected_revision=expected_revision,
            content=content,
            message="Advance shared authorization state",
        )
        return BackendWriteResult(
            written=result.written,
            conflict=result.conflict,
            uncertain=result.uncertain,
            revision=result.revision,
        )
