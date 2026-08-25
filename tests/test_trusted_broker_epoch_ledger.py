import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest

from agent_controller.broker_epoch import (
    BrokerContinuityState,
    EpochBoundApprovalGate,
    TrustedBrokerAuthorityConfig,
)
from agent_controller.signed_approval import ApprovalChallengeV3, canonicalize_approval_challenge
from agent_controller.trusted_broker_epoch_ledger import EpochBoundTrustedBrokerLedger
from agent_controller.trusted_broker_ledger import (
    BrokerLedgerDecision,
    TrustedBrokerAttemptLedger,
)


SIGNATURE_V3 = "p4DTQlILZY1hMYKGa2j37eEEBmZXldUd8uN4Z3mApg2BFy2+jmM3azUtyFndFHADJTdZZb7mSUzFrU54sD0iCQ=="


def challenge_v3(**changes):
    values = dict(
        approval_id="approval-poc-v3",
        approval_policy_id="policy-level3-v1",
        controller_task_id="task-poc-v3",
        operation_id="op-poc-v3",
        operation_version="v1",
        provider="codex",
        requested_capability="MERGE_PR",
        effect="MERGE",
        repo="oimus1976/agent-controller",
        target_kind="PULL_REQUEST",
        target_id="999",
        expected_head_sha="b" * 40,
        challenge_nonce="nonce-poc-v3-001",
        signer_key_id="human-key-poc-v3",
        broker_authority_id="broker-prod-primary",
        broker_epoch="epoch-2026-08-25-a",
    )
    values.update(changes)
    return ApprovalChallengeV3(**values)


def gate(epoch="epoch-2026-08-25-a", *, authority="broker-prod-primary", state=BrokerContinuityState.ACTIVE):
    return EpochBoundApprovalGate(
        config=TrustedBrokerAuthorityConfig(
            broker_authority_id=authority,
            broker_epoch=epoch,
            continuity_state=state,
        )
    )


class EpochBoundTrustedBrokerLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.temp.name, "broker-v2.sqlite")

    def tearDown(self):
        self.temp.cleanup()

    def ledger(self, active_gate=None):
        return EpochBoundTrustedBrokerLedger(
            db_path=self.db,
            gate=active_gate or gate(),
        )

    def row_count(self):
        connection = sqlite3.connect(self.db)
        try:
            return connection.execute("SELECT COUNT(*) FROM effect_attempts").fetchone()[0]
        finally:
            connection.close()

    def test_current_exact_v3_claims_once_and_replays(self):
        ledger = self.ledger()
        first = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        second = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        self.assertEqual(BrokerLedgerDecision.PASS, first.decision)
        self.assertEqual(BrokerLedgerDecision.REPLAYED, second.decision)
        self.assertEqual(first.record.attempt_id, second.record.attempt_id)
        self.assertEqual("broker-prod-primary", first.record.broker_authority_id)
        self.assertEqual("epoch-2026-08-25-a", first.record.broker_epoch)
        expected = hashlib.sha256(canonicalize_approval_challenge(challenge_v3())).hexdigest()
        self.assertEqual(expected, first.record.authorization_digest)

    def test_old_epoch_blocks_before_database_mutation(self):
        ledger = self.ledger(gate("epoch-2026-08-25-b"))
        result = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        self.assertEqual("BROKER_EPOCH_MISMATCH", result.reason)
        self.assertEqual(0, self.row_count())

    def test_wrong_authority_blocks_before_database_mutation(self):
        ledger = self.ledger(gate(authority="broker-secondary"))
        result = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        self.assertEqual("BROKER_AUTHORITY_MISMATCH", result.reason)
        self.assertEqual(0, self.row_count())

    def test_recovery_suspended_blocks_before_database_mutation(self):
        ledger = self.ledger(gate(state=BrokerContinuityState.RECOVERY_SUSPENDED))
        result = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        self.assertEqual("BROKER_RECOVERY_SUSPENDED", result.reason)
        self.assertEqual(0, self.row_count())

    def test_stored_epoch_tamper_blocks_read_and_replay(self):
        ledger = self.ledger()
        first = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        digest = first.record.authorization_digest
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE effect_attempts SET broker_epoch='epoch-attacker' WHERE authorization_digest=?",
                (digest,),
            )
            connection.commit()
        finally:
            connection.close()
        read = ledger.read_attempt(authorization_digest=digest)
        replay = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_AUTHORIZATION_BINDING_INVALID", read.reason)
        self.assertEqual(BrokerLedgerDecision.BLOCKED, replay.decision)
        self.assertEqual("BROKER_LEDGER_AUTHORIZATION_BINDING_INVALID", replay.reason)

    def test_stored_authority_tamper_blocks_read(self):
        ledger = self.ledger()
        first = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        digest = first.record.authorization_digest
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE effect_attempts SET broker_authority_id='broker-attacker' WHERE authorization_digest=?",
                (digest,),
            )
            connection.commit()
        finally:
            connection.close()
        result = ledger.read_attempt(authorization_digest=digest)
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        self.assertEqual("BROKER_LEDGER_AUTHORIZATION_BINDING_INVALID", result.reason)

    def test_old_v1_ledger_is_not_auto_migrated(self):
        old_db = os.path.join(self.temp.name, "old.sqlite")
        TrustedBrokerAttemptLedger(db_path=old_db)
        with self.assertRaises(Exception) as caught:
            EpochBoundTrustedBrokerLedger(db_path=old_db, gate=gate())
        self.assertIn("BROKER_LEDGER", str(caught.exception))
        connection = sqlite3.connect(old_db)
        try:
            version = connection.execute(
                "SELECT value FROM broker_meta WHERE key='schema_version'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual("agent-controller-trusted-broker-ledger-v1", version)

    def test_two_connections_race_exactly_one_first_claim(self):
        self.ledger().claim_effect_attempt  # initialize DB
        ledger_a = EpochBoundTrustedBrokerLedger(db_path=self.db, gate=gate())
        ledger_b = EpochBoundTrustedBrokerLedger(db_path=self.db, gate=gate())
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def run(ledger):
            barrier.wait()
            result = ledger.claim_effect_attempt(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=run, args=(ledger_a,)), threading.Thread(target=run, args=(ledger_b,))]
        for item in threads:
            item.start()
        for item in threads:
            item.join()
        self.assertEqual(1, sum(r.decision is BrokerLedgerDecision.PASS for r in results))
        self.assertEqual(1, sum(r.decision is BrokerLedgerDecision.REPLAYED for r in results))
        self.assertEqual(1, self.row_count())

    def test_public_surface_has_no_delete_reset_reclaim_or_effect_executor(self):
        names = set(dir(EpochBoundTrustedBrokerLedger))
        for forbidden in ("delete", "reset", "reclaim", "execute_effect", "start_effect", "merge", "deploy"):
            self.assertNotIn(forbidden, names)


if __name__ == "__main__":
    unittest.main()
