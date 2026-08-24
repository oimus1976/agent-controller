import dataclasses
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
from agent_controller.shared_execution_claim import SharedExecutionClaimController
from agent_controller.signed_approval import ApprovalChallenge
from agent_controller.signed_shared_approval import SignedSharedApprovalController


SIGNATURE_B64 = "XRURwOosCkwgQxER/5Rf1vzxCCgDFjzGLJPZy4N3DHMXcaQ2uOpn8kOznq9G3+z+bp1AoQLh/UoDzckgHCoUBg=="


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
        self.fail = False
        self.calls = 0

    def get_target_facts(self, *, repo, target_kind, target_id):
        self.calls += 1
        if self.fail:
            raise RuntimeError("unavailable")
        return dict(self.facts)


class SharedExecutionClaimTests(unittest.TestCase):
    def setUp(self):
        self.backend = MemoryBackend()
        self.store = SharedAuthorizationStore(self.backend)
        self.reader = TargetReader()
        self.binding = OperationAuthorizationBinding(
            approval_id="approval-poc-2",
            approval_policy_id="policy-level3-v1",
            controller_task_id="task-poc-2",
            operation_id="op-poc-2",
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
            approval_id="approval-poc-2",
            approval_policy_id="policy-level3-v1",
            controller_task_id="task-poc-2",
            operation_id="op-poc-2",
            operation_version="v1",
            provider="codex",
            requested_capability="MERGE_PR",
            effect="MERGE",
            repo="oimus1976/agent-controller",
            target_kind="PULL_REQUEST",
            target_id="999",
            expected_head_sha="a" * 40,
            challenge_nonce="nonce-poc-002",
            signer_key_id="human-key-poc-2",
        )
        self._approve()
        self.claim = SharedExecutionClaimController(
            store=self.store,
            target_reader=self.reader,
            controller_run_id="controller-run-a",
        )

    def _approve(self):
        proposed = propose_operation(store=self.store, binding=self.binding)
        self.assertEqual(AuthorizationDecision.PASS, proposed.decision)
        approval = SignedSharedApprovalController(
            store=self.store, target_reader=self.reader
        ).approve(challenge=self.challenge, signature_b64=SIGNATURE_B64)
        self.assertEqual(AuthorizationDecision.PASS, approval.decision)
        self.reader.calls = 0
        return approval

    def do_claim(self, controller=None):
        controller = self.claim if controller is None else controller
        return controller.claim(
            controller_task_id="task-poc-2",
            operation_id="op-poc-2",
            operation_version="v1",
        )

    def test_valid_signed_human_approval_claims_once(self):
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.PASS, result.decision)
        self.assertEqual(AuthorizationState.EXECUTION_CLAIMED, result.snapshot.record.state)
        self.assertTrue(result.snapshot.record.execution_claim_id.startswith("claim_"))
        self.assertEqual("controller-run-a", result.snapshot.record.controller_run_id)
        self.assertEqual(1, self.reader.calls)

    def test_duplicate_claim_is_replayed_without_second_target_read(self):
        first = self.do_claim()
        calls = self.reader.calls
        second = self.do_claim()
        self.assertEqual(AuthorizationDecision.PASS, first.decision)
        self.assertEqual(AuthorizationDecision.REPLAYED, second.decision)
        self.assertEqual(first.snapshot.record.execution_claim_id, second.snapshot.record.execution_claim_id)
        self.assertEqual(calls, self.reader.calls)

    def test_two_controllers_race_one_logical_winner(self):
        other = SharedExecutionClaimController(
            store=self.store,
            target_reader=self.reader,
            controller_run_id="controller-run-b",
        )
        raced = None

        def winner():
            nonlocal raced
            raced = self.do_claim(other)

        self.backend.before_cas = winner
        loser = self.do_claim()
        self.assertEqual(AuthorizationDecision.PASS, raced.decision)
        self.assertEqual(AuthorizationDecision.REPLAYED, loser.decision)
        self.assertEqual("controller-run-b", self.backend.snapshot.record.controller_run_id)
        self.assertEqual(
            raced.snapshot.record.execution_claim_id,
            loser.snapshot.record.execution_claim_id,
        )

    def test_forged_human_approved_strings_without_signature_cannot_claim(self):
        fake = AuthorizationProvenance(
            assurance="VERIFIED_EVENT_PROVENANCE",
            provenance_kind="SIGNED_CHALLENGE",
            signer_key_id="human-key-poc-2",
            challenge_nonce="nonce-poc-002",
            challenge_schema_version="agent-controller-approval-challenge-v2",
            challenge_digest="d" * 64,
            signature_digest="e" * 64,
            signature_b64="A" * 88,
        )
        self.backend.snapshot = SharedRecordSnapshot(
            SharedAuthorizationRecord(
                binding=self.binding,
                state=AuthorizationState.HUMAN_APPROVED,
                provenance=fake,
            ),
            "forged-r1",
        )
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)
        self.assertIsNone(self.backend.snapshot.record.execution_claim_id)

    def test_tampered_signed_binding_cannot_claim(self):
        current = self.backend.snapshot
        tampered_binding = dataclasses.replace(
            current.record.binding, requested_capability="DEPLOY"
        )
        self.backend.snapshot = SharedRecordSnapshot(
            dataclasses.replace(current.record, binding=tampered_binding), current.revision
        )
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)

    def test_stale_target_never_claims(self):
        self.reader.facts["head_sha"] = "b" * 40
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.STALE, result.decision)
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, self.backend.snapshot.record.state)
        self.assertIsNone(self.backend.snapshot.record.execution_claim_id)

    def test_target_read_uncertainty_never_claims(self):
        self.reader.fail = True
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, self.backend.snapshot.record.state)

    def test_uncertain_cas_with_durable_exact_winner_resolves_by_reread(self):
        self.backend.uncertain_apply = True
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.PASS, result.decision)
        self.assertEqual(AuthorizationState.EXECUTION_CLAIMED, result.snapshot.record.state)

    def test_uncertain_cas_without_durable_winner_remains_uncertain(self):
        self.backend.uncertain_without_apply = True
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.UNCERTAIN, result.decision)
        self.assertEqual(AuthorizationState.HUMAN_APPROVED, self.backend.snapshot.record.state)

    def test_existing_forged_claim_is_not_accepted_as_valid_replay(self):
        approved = self.backend.snapshot.record
        forged = dataclasses.replace(
            approved,
            state=AuthorizationState.EXECUTION_CLAIMED,
            execution_claim_id="claim_forged",
            controller_run_id="attacker-run",
            provenance=dataclasses.replace(approved.provenance, signature_b64="A" * 88),
        )
        self.backend.snapshot = SharedRecordSnapshot(forged, "forged-r2")
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.BLOCKED, result.decision)

    def test_valid_signature_copied_into_forged_claim_is_coordination_replay_only(self):
        approved = self.backend.snapshot.record
        forged = dataclasses.replace(
            approved,
            state=AuthorizationState.EXECUTION_CLAIMED,
            execution_claim_id="claim_attacker_selected",
            controller_run_id="attacker-run",
        )
        self.backend.snapshot = SharedRecordSnapshot(forged, "forged-r3")
        result = self.do_claim()
        self.assertEqual(AuthorizationDecision.REPLAYED, result.decision)
        self.assertEqual("EXECUTION_ALREADY_CLAIMED", result.reason)
        self.assertEqual("claim_attacker_selected", result.snapshot.record.execution_claim_id)
        self.assertEqual(0, self.reader.calls)
        # This explicitly documents the boundary: claim origin is not authenticated
        # by the human signature and this result must never authorize an effect.

    def test_public_claim_api_has_no_claim_id_or_authority_override(self):
        params = set(inspect.signature(self.claim.claim).parameters)
        self.assertEqual(
            {"controller_task_id", "operation_id", "operation_version"}, params
        )

    def test_module_exposes_no_effect_start_executor(self):
        import agent_controller.shared_execution_claim as module

        names = set(dir(module))
        self.assertNotIn("start_effect", names)
        self.assertNotIn("execute_effect", names)
        self.assertNotIn("merge_pull_request", names)


if __name__ == "__main__":
    unittest.main()
