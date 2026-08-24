import hashlib
import inspect
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from agent_controller.signed_approval import ApprovalChallenge, canonicalize_approval_challenge
from agent_controller.trusted_broker_ledger import (
    BrokerAttemptState,
    BrokerLedgerDecision,
    TrustedBrokerAttemptLedger,
)


SIGNATURE_B64 = "XRURwOosCkwgQxER/5Rf1vzxCCgDFjzGLJPZy4N3DHMXcaQ2uOpn8kOznq9G3+z+bp1AoQLh/UoDzckgHCoUBg=="
SIGNATURE_B64_3 = "uxUi39FFJ8lrblIrwR7sEo8V0kNLxDNZoxydyOoSidqPZDj5tLeSg7HwYFALDKofrrJMBGx6MUQGjrVJHuMxAg=="


def challenge(**changes):
    values = dict(
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
    values.update(changes)
    return ApprovalChallenge(**values)


def challenge3():
    return ApprovalChallenge(
        approval_id="approval-poc-3",
        approval_policy_id="policy-level3-v1",
        controller_task_id="task-poc-3",
        operation_id="op-poc-3",
        operation_version="v1",
        provider="codex",
        requested_capability="MERGE_PR",
        effect="MERGE",
        repo="oimus1976/agent-controller",
        target_kind="PULL_REQUEST",
        target_id="1000",
        expected_head_sha="b" * 40,
        challenge_nonce="nonce-poc-003",
        signer_key_id="human-key-poc-3",
    )


class TrustedBrokerLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "broker.sqlite3"
        self.ledger = TrustedBrokerAttemptLedger(db_path=self.db, timeout_seconds=1.0)
        self.challenge = challenge()

    def tearDown(self):
        self.temp.cleanup()

    def digest(self, item=None):
        item = self.challenge if item is None else item
        return hashlib.sha256(canonicalize_approval_challenge(item)).hexdigest()

    def claim(self, ledger=None):
        ledger = self.ledger if ledger is None else ledger
        return ledger.claim_effect_attempt(
            challenge=self.challenge, signature_b64=SIGNATURE_B64
        )

    def test_first_claim_is_durable_pass(self):
        result = self.claim()
        self.assertEqual(BrokerLedgerDecision.PASS, result.decision)
        self.assertEqual(BrokerAttemptState.CLAIMED, result.record.state)
        self.assertEqual(self.digest(), result.record.authorization_digest)
        self.assertTrue(result.record.attempt_id.startswith("attempt_"))
        reread = self.ledger.read_attempt(authorization_digest=self.digest())
        self.assertEqual(result.record, reread.record)

    def test_same_authorization_replays_original_attempt(self):
        first = self.claim()
        second = self.claim()
        self.assertEqual(BrokerLedgerDecision.PASS, first.decision)
        self.assertEqual(BrokerLedgerDecision.REPLAYED, second.decision)
        self.assertEqual(first.record.attempt_id, second.record.attempt_id)
        self.assertEqual(BrokerAttemptState.CLAIMED, second.record.state)

    def test_invalid_signature_never_creates_attempt(self):
        result = self.ledger.claim_effect_attempt(
            challenge=self.challenge, signature_b64="not-base64"
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        missing = self.ledger.read_attempt(authorization_digest=self.digest())
        self.assertEqual(BrokerLedgerDecision.BLOCKED, missing.decision)

    def test_two_connections_race_exactly_one_first_claim(self):
        ledger_a = TrustedBrokerAttemptLedger(db_path=self.db, timeout_seconds=2.0)
        ledger_b = TrustedBrokerAttemptLedger(db_path=self.db, timeout_seconds=2.0)
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def worker(ledger):
            barrier.wait()
            result = ledger.claim_effect_attempt(
                challenge=self.challenge, signature_b64=SIGNATURE_B64
            )
            with lock:
                results.append(result)

        threads = [
            threading.Thread(target=worker, args=(ledger_a,)),
            threading.Thread(target=worker, args=(ledger_b,)),
        ]
        for item in threads:
            item.start()
        for item in threads:
            item.join()
        self.assertEqual(2, len(results))
        self.assertEqual(
            {BrokerLedgerDecision.PASS, BrokerLedgerDecision.REPLAYED},
            {r.decision for r in results},
        )
        self.assertEqual(1, len({r.record.attempt_id for r in results}))

    def test_different_valid_authorizations_are_independent(self):
        first = self.claim()
        second = self.ledger.claim_effect_attempt(
            challenge=challenge3(), signature_b64=SIGNATURE_B64_3
        )
        self.assertEqual(BrokerLedgerDecision.PASS, first.decision)
        self.assertEqual(BrokerLedgerDecision.PASS, second.decision)
        self.assertNotEqual(first.record.authorization_digest, second.record.authorization_digest)
        self.assertNotEqual(first.record.attempt_id, second.record.attempt_id)

    def test_duplicate_generated_attempt_id_fails_closed(self):
        first = self.claim()
        with mock.patch(
            "agent_controller.trusted_broker_ledger.secrets.token_urlsafe",
            return_value=first.record.attempt_id.removeprefix("attempt_"),
        ):
            result = self.ledger.claim_effect_attempt(
                challenge=challenge3(), signature_b64=SIGNATURE_B64_3
            )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        self.assertEqual("BROKER_LEDGER_UNIQUENESS_CONFLICT", result.reason)
        self.assertEqual(
            BrokerLedgerDecision.BLOCKED,
            self.ledger.read_attempt(authorization_digest=self.digest(challenge3())).decision,
        )

    def test_existing_digest_with_tampered_audit_binding_blocks(self):
        first = self.claim()
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE effect_attempts SET requested_capability='DEPLOY' "
                "WHERE authorization_digest=?",
                (first.record.authorization_digest,),
            )
            connection.commit()
        finally:
            connection.close()
        replay = self.claim()
        self.assertEqual(BrokerLedgerDecision.BLOCKED, replay.decision)
        self.assertEqual("BROKER_LEDGER_AUTHORIZATION_BINDING_INVALID", replay.reason)

    def test_claim_to_effect_verified_is_one_way(self):
        first = self.claim()
        done = self.ledger.mark_effect_verified(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
        )
        self.assertEqual(BrokerLedgerDecision.PASS, done.decision)
        self.assertEqual(BrokerAttemptState.EFFECT_VERIFIED, done.record.state)
        replay = self.ledger.mark_effect_verified(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
        )
        self.assertEqual(BrokerLedgerDecision.REPLAYED, replay.decision)
        conflict = self.ledger.mark_failed_after_claim(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
            failure_code="SHOULD_NOT_RETRY",
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, conflict.decision)
        self.assertEqual(BrokerAttemptState.EFFECT_VERIFIED, conflict.record.state)

    def test_claim_to_failed_after_claim_is_terminal(self):
        first = self.claim()
        failed = self.ledger.mark_failed_after_claim(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
            failure_code="NETWORK_UNCERTAIN",
        )
        self.assertEqual(BrokerLedgerDecision.PASS, failed.decision)
        self.assertEqual(BrokerAttemptState.FAILED_AFTER_CLAIM, failed.record.state)
        self.assertEqual("NETWORK_UNCERTAIN", failed.record.failure_code)
        replay_claim = self.claim()
        self.assertEqual(BrokerLedgerDecision.REPLAYED, replay_claim.decision)
        self.assertEqual(BrokerAttemptState.FAILED_AFTER_CLAIM, replay_claim.record.state)
        verified = self.ledger.mark_effect_verified(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, verified.decision)

    def test_wrong_attempt_id_cannot_change_terminal_state(self):
        first = self.claim()
        result = self.ledger.mark_effect_verified(
            authorization_digest=first.record.authorization_digest,
            attempt_id="attempt_attacker",
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        self.assertEqual(BrokerAttemptState.CLAIMED, result.record.state)

    def test_locked_database_claim_is_uncertain_not_pass(self):
        impatient = TrustedBrokerAttemptLedger(db_path=self.db, timeout_seconds=0.01)
        blocker = sqlite3.connect(self.db, isolation_level=None)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            result = impatient.claim_effect_attempt(
                challenge=self.challenge, signature_b64=SIGNATURE_B64
            )
            self.assertEqual(BrokerLedgerDecision.UNCERTAIN, result.decision)
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()
        self.assertEqual(
            BrokerLedgerDecision.BLOCKED,
            self.ledger.read_attempt(authorization_digest=self.digest()).decision,
        )

    def test_integrity_check_passes_and_schema_tamper_fails_closed(self):
        self.assertEqual(BrokerLedgerDecision.PASS, self.ledger.integrity_check().decision)
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE broker_meta SET value='attacker-v2' WHERE key='schema_version'"
            )
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(
            BrokerLedgerDecision.BLOCKED, self.ledger.integrity_check().decision
        )

    def test_public_api_has_no_delete_reset_or_force_reclaim(self):
        names = set(dir(TrustedBrokerAttemptLedger))
        forbidden = {
            "delete_attempt",
            "reset_attempt",
            "force_reclaim",
            "unclaim",
            "retry_effect",
            "execute_effect",
        }
        self.assertTrue(forbidden.isdisjoint(names))
        params = set(inspect.signature(self.ledger.claim_effect_attempt).parameters)
        self.assertEqual({"challenge", "signature_b64"}, params)


if __name__ == "__main__":
    unittest.main()
