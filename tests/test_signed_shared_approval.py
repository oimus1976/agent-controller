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
    propose_operation,
)
from agent_controller.signed_approval import ApprovalChallenge
from agent_controller.signed_shared_approval import SignedSharedApprovalController


SIGNATURE_B64 = "ysPv815PSBz1qe6IEy/PaH2JuNx8KvqT7F8bRreNVsd4Nlu07qSSUzHiu8t77685fnmLFJAyANIsz6jOdP1UCA=="


class MemoryBackend:
    def __init__(self):
        self.snapshot = None
        self.rev = 0
        self.before_cas = None
        self.uncertain_apply = False
        self.uncertain_without_apply = False

    def _next(self):
        self.rev += 1
        return f"r{self.rev}"

    def read(self, *, state_ref, path):
        return self.snapshot

    def create_if_absent(self, *, state_ref, path, record):
        if self.snapshot is not None:
            return BackendWriteResult(False, conflict=True)
        revision = self._next()
        self.snapshot = SharedRecordSnapshot(record, revision)
        return BackendWriteResult(True, revision=revision)

    def compare_and_swap(self, *, state_ref, path, expected_revision, record):
        if self.before_cas is not None:
            callback = self.before_cas
            self.before_cas = None
            callback()
        if self.uncertain_without_apply:
            return BackendWriteResult(False, uncertain=True)
        if self.snapshot is None or self.snapshot.revision != expected_revision:
            return BackendWriteResult(False, conflict=True)
        revision = self._next()
        self.snapshot = SharedRecordSnapshot(record, revision)
        if self.uncertain_apply:
            return BackendWriteResult(False, uncertain=True)
        return BackendWriteResult(True, revision=revision)


class TargetReader:
    def __init__(self):
        self.facts = {
            "repo": "oimus1976/agent-controller",
            "target_kind": "PULL_REQUEST",
            "target_id": "999",
            "head_sha": "a" * 40,
        }
        self.calls = 0
        self.fail = False

    def get_target_facts(self, *, repo, target_kind, target_id):
        self.calls += 1
        if self.fail:
            raise RuntimeError("read failed")
        return dict(self.facts)


class SignedSharedApprovalTests(unittest.TestCase):
    def setUp(self):
        self.backend = MemoryBackend()
        self.store = SharedAuthorizationStore(self.backend)
        self.reader = TargetReader()
        self.controller = SignedSharedApprovalController(
            store=self.store, target_reader=self.reader
        )
        self.binding = OperationAuthorizationBinding(
            approval_id="approval-poc-1",
            approval_policy_id="policy-level3-v1",
            controller_task_id="task-poc-1",
            operation_id="op-poc-1",
            operation_version="v1",
            provider="codex",
            requested_capability="MERGE_PR",
            effect="MERGE",
            repo="oimus1976/agent-controller",
            target_kind="PULL_REQUEST",
            target_id="999",
            expected_head_sha="a" * 40,
        )
        self.challenge = ApprovalChallenge(
            approval_id="approval-poc-1",
            controller_task_id="task-poc-1",
            operation_id="op-poc-1",
            operation_version="v1",
            effect="MERGE",
            repo="oimus1976/agent-controller",
            target_kind="PULL_REQUEST",
            target_id="999",
            expected_head_sha="a" * 40,
            challenge_nonce="nonce-poc-001",
            signer_key_id="human-key-poc-1",
        )
        proposed = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.PASS, proposed.decision)

    def approve(self, signature=SIGNATURE_B64, challenge=None):
        return self.controller.approve(
            challenge=self.challenge if challenge is None else challenge,
            signature_b64=signature,
        )

    def test_valid_exact_signature_and_fresh_target_advances_once(self):
        result = self.approve()
        self.assertEqual(AuthorizationDecision.PASS, result.decision)
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, result.snapshot.record.state)
        provenance = result.snapshot.record.provenance
        self.assertEqual("VERIFIED_EVENT_PROVENANCE", provenance.assurance)
        self.assertEqual("SIGNED_CHALLENGE", provenance.provenance_kind)
        self.assertEqual("human-key-poc-1", provenance.signer_key_id)
        self.assertEqual("nonce-poc-001", provenance.challenge_nonce)
        self.assertEqual(64, len(provenance.challenge_digest))
        self.assertEqual(64, len(provenance.signature_digest))
        self.assertNotIn(SIGNATURE_B64, str(result.snapshot.record.to_dict()))

    def test_shared_record_is_authoritative_binding_not_per_call_input(self):
        params = set(inspect.signature(self.controller.approve).parameters)
        self.assertEqual({"challenge", "signature_b64"}, params)
        self.assertEqual("policy-level3-v1", self.backend.snapshot.record.binding.approval_policy_id)
        self.assertEqual("MERGE_PR", self.backend.snapshot.record.binding.requested_capability)

    def test_repeated_same_signature_is_replay_without_second_target_read(self):
        first = self.approve()
        calls_after_first = self.reader.calls
        second = self.approve()
        self.assertEqual(AuthorizationDecision.PASS, first.decision)
        self.assertEqual(AuthorizationDecision.REPLAYED, second.decision)
        self.assertEqual(calls_after_first, self.reader.calls)

    def test_invalid_signature_never_reads_target_or_advances(self):
        result = self.approve(signature="not-base64")
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual(0, self.reader.calls)
        self.assertEqual(AuthorizationState.PROPOSED, self.backend.snapshot.record.state)

    def test_valid_signature_cannot_approve_mismatched_shared_binding(self):
        changed_binding = OperationAuthorizationBinding(
            **{**self.binding.__dict__, "effect": "DEPLOY"}
        )
        self.backend.snapshot = SharedRecordSnapshot(
            SharedAuthorizationRecord(
                binding=changed_binding, state=AuthorizationState.PROPOSED
            ),
            self.backend.snapshot.revision,
        )
        result = self.approve()
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("CHALLENGE_BINDING_MISMATCH", result.reason)
        self.assertEqual(0, self.reader.calls)

    def test_stale_objective_head_does_not_advance(self):
        self.reader.facts["head_sha"] = "b" * 40
        result = self.approve()
        self.assertEqual(AuthorizationDecision.STALE, result.decision)
        self.assertEqual("TARGET_HEAD_SHA_STALE", result.reason)
        self.assertEqual(AuthorizationState.PROPOSED, self.backend.snapshot.record.state)

    def test_target_read_uncertainty_does_not_advance(self):
        self.reader.fail = True
        result = self.approve()
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)
        self.assertEqual(AuthorizationState.PROPOSED, self.backend.snapshot.record.state)

    def test_same_signature_race_has_one_logical_winner(self):
        raced = None

        def winner():
            nonlocal raced
            raced = self.approve()

        self.backend.before_cas = winner
        loser = self.approve()
        self.assertEqual(AuthorizationDecision.PASS, raced.decision)
        self.assertEqual(AuthorizationDecision.REPLAYED, loser.decision)
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, self.backend.snapshot.record.state)

    def test_conflicting_existing_human_approval_blocks(self):
        fake = AuthorizationProvenance(
            assurance="VERIFIED_EVENT_PROVENANCE",
            provenance_kind="SIGNED_CHALLENGE",
            signer_key_id="other-key",
            challenge_nonce="other",
            challenge_digest="d" * 64,
            signature_digest="s" * 64,
        )
        self.backend.snapshot = SharedRecordSnapshot(
            SharedAuthorizationRecord(
                binding=self.binding,
                state=AuthorizationState.HUMAN_APPROVED,
                provenance=fake,
            ),
            "r-conflict",
        )
        result = self.approve()
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertEqual("APPROVAL_PROVENANCE_CONFLICT", result.reason)

    def test_uncertain_write_with_durable_exact_winner_is_resolved_by_reread(self):
        self.backend.uncertain_apply = True
        result = self.approve()
        self.assertEqual(AuthorizationDecision.PASS, result.decision)
        self.assertEqual("APPROVAL_CONFIRMED_AFTER_UNCERTAIN_WRITE", result.reason)
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, self.backend.snapshot.record.state)

    def test_uncertain_write_without_state_change_remains_uncertain(self):
        self.backend.uncertain_without_apply = True
        result = self.approve()
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)
        self.assertEqual(AuthorizationState.PROPOSED, self.backend.snapshot.record.state)

    def test_no_execution_claim_is_created(self):
        result = self.approve()
        self.assertIsNone(result.snapshot.record.execution_claim_id)
        self.assertIsNone(result.snapshot.record.controller_run_id)


if __name__ == "__main__":
    unittest.main()
