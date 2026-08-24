import copy
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
    approve_proposed_operation,
    operation_state_path,
    propose_operation,
)


class MemoryBackend:
    def __init__(self):
        self.records = {}
        self.rev = 0
        self.fail_read = False
        self.fail_create = False
        self.fail_cas = False
        self.uncertain_cas = False
        self.before_cas = None

    def _next(self):
        self.rev += 1
        return f"r{self.rev}"

    def read(self, *, state_ref, path):
        if self.fail_read:
            raise RuntimeError("read failed")
        item = self.records.get((state_ref, path))
        return copy.deepcopy(item)

    def create_if_absent(self, *, state_ref, path, record):
        if self.fail_create:
            raise RuntimeError("create failed")
        key = (state_ref, path)
        if key in self.records:
            return BackendWriteResult(False, conflict=True)
        rev = self._next()
        self.records[key] = SharedRecordSnapshot(copy.deepcopy(record), rev)
        return BackendWriteResult(True, revision=rev)

    def compare_and_swap(self, *, state_ref, path, expected_revision, record):
        if self.fail_cas:
            raise RuntimeError("cas failed")
        if self.before_cas:
            callback = self.before_cas
            self.before_cas = None
            callback()
        if self.uncertain_cas:
            return BackendWriteResult(False, uncertain=True)
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
        self.provenance = AuthorizationProvenance(
            assurance="VERIFIED_EVENT_PROVENANCE",
            provenance_kind="SIGNED_CHALLENGE",
            signer_key_id="human-key-1",
            challenge_nonce="nonce-1",
            challenge_digest="c" * 64,
            signature_digest="s" * 64,
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
        path = operation_state_path(conflict)
        original_path = operation_state_path(self.binding)
        self.assertEqual(path, original_path)
        result = propose_operation(store=self.store, binding=conflict)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("OPERATION_BINDING_CONFLICT", result.reason)

    def test_create_uncertainty_fails_closed(self):
        self.backend.fail_create = True
        result = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)

    def test_verified_signed_provenance_approves(self):
        propose_operation(store=self.store, binding=self.binding)
        result = approve_proposed_operation(
            store=self.store, binding=self.binding, provenance=self.provenance
        )
        self.assertEqual(AuthorizationDecision.PASS, result.decision)
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, result.snapshot.record.state)
        self.assertEqual(self.provenance, result.snapshot.record.provenance)

    def test_source_authenticated_only_cannot_approve(self):
        propose_operation(store=self.store, binding=self.binding)
        weaker = AuthorizationProvenance(**{**self.provenance.__dict__, "assurance": "SOURCE_AUTHENTICATED_ONLY"})
        result = approve_proposed_operation(store=self.store, binding=self.binding, provenance=weaker)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("ASSURANCE_NOT_VERIFIED", result.reason)

    def test_wrong_provenance_kind_cannot_approve(self):
        propose_operation(store=self.store, binding=self.binding)
        wrong = AuthorizationProvenance(**{**self.provenance.__dict__, "provenance_kind": "GITHUB_WORKFLOW"})
        result = approve_proposed_operation(store=self.store, binding=self.binding, provenance=wrong)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)

    def test_duplicate_same_approval_is_replay(self):
        propose_operation(store=self.store, binding=self.binding)
        first = approve_proposed_operation(store=self.store, binding=self.binding, provenance=self.provenance)
        second = approve_proposed_operation(store=self.store, binding=self.binding, provenance=self.provenance)
        self.assertEqual(AuthorizationDecision.PASS, first.decision)
        self.assertEqual(AuthorizationDecision.REPLAYED, second.decision)

    def test_duplicate_different_provenance_is_conflict(self):
        propose_operation(store=self.store, binding=self.binding)
        approve_proposed_operation(store=self.store, binding=self.binding, provenance=self.provenance)
        other = AuthorizationProvenance(**{**self.provenance.__dict__, "challenge_nonce": "nonce-2"})
        result = approve_proposed_operation(store=self.store, binding=self.binding, provenance=other)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("APPROVAL_PROVENANCE_CONFLICT", result.reason)

    def test_two_controllers_same_approval_have_one_logical_winner(self):
        propose_operation(store=self.store, binding=self.binding)

        raced_result = None
        def winner():
            nonlocal raced_result
            raced_result = approve_proposed_operation(
                store=self.store, binding=self.binding, provenance=self.provenance
            )

        self.backend.before_cas = winner
        loser = approve_proposed_operation(
            store=self.store, binding=self.binding, provenance=self.provenance
        )
        self.assertEqual(AuthorizationDecision.PASS, raced_result.decision)
        self.assertEqual(AuthorizationDecision.REPLAYED, loser.decision)
        snapshot = self.backend.read(
            state_ref="controller-state", path=operation_state_path(self.binding)
        )
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, snapshot.record.state)

    def test_two_controllers_different_approval_provenance_one_wins_other_blocks(self):
        propose_operation(store=self.store, binding=self.binding)
        other = AuthorizationProvenance(**{**self.provenance.__dict__, "challenge_nonce": "nonce-other"})

        def winner():
            approve_proposed_operation(store=self.store, binding=self.binding, provenance=other)

        self.backend.before_cas = winner
        loser = approve_proposed_operation(store=self.store, binding=self.binding, provenance=self.provenance)
        self.assertEqual(AuthorizationDecision.BLOCKED, loser.decision)
        self.assertEqual("APPROVAL_RACE_LOST_DIFFERENT_WINNER", loser.reason)

    def test_uncertain_cas_does_not_report_approval(self):
        propose_operation(store=self.store, binding=self.binding)
        self.backend.uncertain_cas = True
        result = approve_proposed_operation(store=self.store, binding=self.binding, provenance=self.provenance)
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)

    def test_missing_proposed_state_blocks(self):
        result = approve_proposed_operation(store=self.store, binding=self.binding, provenance=self.provenance)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("PROPOSED_STATE_MISSING", result.reason)

    def test_binding_conflict_blocks_before_transition(self):
        propose_operation(store=self.store, binding=self.binding)
        conflict = OperationAuthorizationBinding(**{**self.binding.__dict__, "expected_head_sha": "b" * 40})
        result = approve_proposed_operation(store=self.store, binding=conflict, provenance=self.provenance)
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)


if __name__ == "__main__":
    unittest.main()
