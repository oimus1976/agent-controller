import copy
import inspect
import unittest

from agent_controller.shared_authorization import (
    AuthorizationDecision,
    AuthorizationProvenance,
    AuthorizationState,
    BackendWriteResult,
    OperationAuthorizationBinding,
    SharedAuthorizationRecord,
    SharedAuthorizationStore,
    SharedRecordSnapshot,
    operation_state_path,
    propose_operation,
    read_operation,
)


class MemoryBackend:
    def __init__(self):
        self.records = {}
        self.rev = 0
        self.fail_read = False
        self.fail_create = False
        self.create_result_override = None

    def _next(self):
        self.rev += 1
        return f"r{self.rev}"

    def read(self, *, state_ref, path):
        if self.fail_read:
            raise RuntimeError("read failed")
        return copy.deepcopy(self.records.get((state_ref, path)))

    def create_if_absent(self, *, state_ref, path, record):
        if self.fail_create:
            raise RuntimeError("create failed")
        if self.create_result_override is not None:
            return self.create_result_override
        key = (state_ref, path)
        if key in self.records:
            return BackendWriteResult(False, conflict=True)
        rev = self._next()
        self.records[key] = SharedRecordSnapshot(copy.deepcopy(record), rev)
        return BackendWriteResult(True, revision=rev)

    def compare_and_swap(self, *, state_ref, path, expected_revision, record):
        key = (state_ref, path)
        current = self.records.get(key)
        if current is None or current.revision != expected_revision:
            return BackendWriteResult(False, conflict=True)
        rev = self._next()
        self.records[key] = SharedRecordSnapshot(copy.deepcopy(record), rev)
        return BackendWriteResult(True, revision=rev)


class InvalidBackend:
    pass


class SharedAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.backend = MemoryBackend()
        self.store = SharedAuthorizationStore(self.backend)
        self.binding = OperationAuthorizationBinding(
            approval_id="approval-1",
            approval_policy_id="policy-level3-v1",
            controller_task_id="task-1",
            operation_id="op-1",
            operation_version="v1",
            provider="codex",
            requested_capability="MERGE_PR",
            effect="MERGE",
            repo="oimus1976/agent-controller",
            target_kind="PULL_REQUEST",
            target_id="30",
            expected_head_sha="a" * 40,
        )

    def test_store_ref_is_fixed(self):
        with self.assertRaises(ValueError):
            SharedAuthorizationStore(self.backend, state_ref="main")

    def test_invalid_backend_rejected(self):
        with self.assertRaises(TypeError):
            SharedAuthorizationStore(InvalidBackend())

    def test_path_is_deterministic_and_operation_version_scoped(self):
        self.assertEqual(
            "controller-state/operations/task-1/op-1/v1.json",
            operation_state_path(self.binding),
        )

    def test_unsafe_path_component_rejected(self):
        bad = OperationAuthorizationBinding(**{**self.binding.__dict__, "operation_id": "../escape"})
        with self.assertRaises(ValueError):
            operation_state_path(bad)

    def test_propose_creates_once(self):
        first = propose_operation(store=self.store, binding=self.binding)
        second = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.PASS, first.decision)
        self.assertEqual(AuthorizationState.PROPOSED, first.snapshot.record.state)
        self.assertEqual(AuthorizationDecision.REPLAYED, second.decision)

    def test_propose_conflicting_binding_blocks(self):
        propose_operation(store=self.store, binding=self.binding)
        conflict = OperationAuthorizationBinding(**{**self.binding.__dict__, "effect": "DEPLOY"})
        self.assertEqual(operation_state_path(conflict), operation_state_path(self.binding))
        result = propose_operation(store=self.store, binding=conflict)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("OPERATION_BINDING_CONFLICT", result.reason)

    def test_create_uncertainty_fails_closed(self):
        self.backend.fail_create = True
        result = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)

    def test_contradictory_write_result_never_passes(self):
        self.backend.create_result_override = BackendWriteResult(
            True, conflict=True, uncertain=True, revision="r1"
        )
        result = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)
        self.assertEqual("STATE_WRITE_RESULT_INVALID", result.reason)

    def test_success_without_revision_never_passes(self):
        self.backend.create_result_override = BackendWriteResult(True)
        result = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)

    def test_empty_backend_outcome_never_passes(self):
        self.backend.create_result_override = BackendWriteResult(False)
        result = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)

    def test_conflict_with_malformed_snapshot_blocks(self):
        path = operation_state_path(self.binding)
        malformed = SharedAuthorizationRecord(
            binding=self.binding,
            state=AuthorizationState.PROPOSED,
            provenance=AuthorizationProvenance(
                assurance="VERIFIED_EVENT_PROVENANCE",
                provenance_kind="SIGNED_CHALLENGE",
                signer_key_id="fake",
                challenge_nonce="n",
                challenge_digest="d",
                signature_digest="s",
            ),
        )
        self.backend.records[("controller-state", path)] = SharedRecordSnapshot(malformed, "r1")
        result = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("STATE_RECORD_INVALID", result.reason)

    def test_unknown_schema_snapshot_blocks(self):
        path = operation_state_path(self.binding)
        malformed = SharedAuthorizationRecord(
            binding=self.binding,
            state=AuthorizationState.PROPOSED,
            schema_version="future-v2",
        )
        self.backend.records[("controller-state", path)] = SharedRecordSnapshot(malformed, "r1")
        result = read_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("STATE_RECORD_INVALID", result.reason)

    def test_missing_snapshot_revision_blocks(self):
        path = operation_state_path(self.binding)
        record = SharedAuthorizationRecord(binding=self.binding, state=AuthorizationState.PROPOSED)
        self.backend.records[("controller-state", path)] = SharedRecordSnapshot(record, "")
        result = read_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)

    def test_read_binding_conflict_blocks(self):
        propose_operation(store=self.store, binding=self.binding)
        conflict = OperationAuthorizationBinding(**{**self.binding.__dict__, "effect": "DEPLOY"})
        result = read_operation(store=self.store, binding=conflict)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("OPERATION_BINDING_CONFLICT", result.reason)

    def test_read_failure_is_uncertain(self):
        self.backend.fail_read = True
        result = read_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)

    def test_public_api_exposes_no_human_approved_transition(self):
        import agent_controller.shared_authorization as module

        self.assertFalse(hasattr(module, "approve_proposed_operation"))
        for name in ("operation_state_path", "propose_operation", "read_operation"):
            self.assertTrue(inspect.isfunction(getattr(module, name)))

    def test_plain_caller_provenance_cannot_advance_state(self):
        first = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationState.PROPOSED, first.snapshot.record.state)
        path = operation_state_path(self.binding)
        snapshot = self.backend.read(state_ref="controller-state", path=path)
        self.assertEqual(AuthorizationState.PROPOSED, snapshot.record.state)
        self.assertIsNone(snapshot.record.provenance)


if __name__ == "__main__":
    unittest.main()
