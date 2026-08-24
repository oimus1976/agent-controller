import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_controller.signed_approval import ApprovalChallenge
from agent_controller.trusted_broker_ledger import (
    BrokerLedgerCorruptError,
    BrokerLedgerDecision,
    TrustedBrokerAttemptLedger,
)


SIGNATURE_B64 = "XRURwOosCkwgQxER/5Rf1vzxCCgDFjzGLJPZy4N3DHMXcaQ2uOpn8kOznq9G3+z+bp1AoQLh/UoDzckgHCoUBg=="


def fixture_challenge():
    return ApprovalChallenge(
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


class TrustedBrokerLedgerHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "broker.sqlite3"
        self.ledger = TrustedBrokerAttemptLedger(db_path=self.db)
        self.challenge = fixture_challenge()

    def tearDown(self):
        self.temp.cleanup()

    def claim(self):
        return self.ledger.claim_effect_attempt(
            challenge=self.challenge, signature_b64=SIGNATURE_B64
        )

    def mutate(self, sql, params=()):
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(sql, params)
            connection.commit()
        finally:
            connection.close()

    def test_existing_empty_database_is_not_auto_repaired(self):
        other = Path(self.temp.name) / "existing-empty.sqlite3"
        other.touch()
        with self.assertRaises(BrokerLedgerCorruptError):
            TrustedBrokerAttemptLedger(db_path=other)
        connection = sqlite3.connect(other)
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual([], tables)

    def test_schema_version_tamper_blocks_read_and_new_claim(self):
        first = self.claim()
        self.mutate(
            "UPDATE broker_meta SET value='attacker-version' WHERE key='schema_version'"
        )
        read = self.ledger.read_attempt(
            authorization_digest=first.record.authorization_digest
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_SCHEMA_VERSION_MISMATCH", read.reason)
        replay = self.claim()
        self.assertEqual(BrokerLedgerDecision.BLOCKED, replay.decision)
        self.assertEqual("BROKER_LEDGER_SCHEMA_VERSION_MISMATCH", replay.reason)

    def test_schema_version_tamper_blocks_terminal_mutation(self):
        first = self.claim()
        self.mutate(
            "UPDATE broker_meta SET value='attacker-version' WHERE key='schema_version'"
        )
        result = self.ledger.mark_effect_verified(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, result.decision)
        self.assertEqual("BROKER_LEDGER_SCHEMA_VERSION_MISMATCH", result.reason)

    def test_claimed_row_with_failure_code_is_corrupt_not_replayed(self):
        first = self.claim()
        self.mutate(
            "UPDATE effect_attempts SET failure_code='impossible' WHERE authorization_digest=?",
            (first.record.authorization_digest,),
        )
        read = self.ledger.read_attempt(
            authorization_digest=first.record.authorization_digest
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_FAILURE_STATE_INVALID", read.reason)
        replay = self.claim()
        self.assertEqual(BrokerLedgerDecision.BLOCKED, replay.decision)

    def test_effect_verified_row_with_failure_code_is_corrupt(self):
        first = self.claim()
        done = self.ledger.mark_effect_verified(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
        )
        self.assertEqual(BrokerLedgerDecision.PASS, done.decision)
        self.mutate(
            "UPDATE effect_attempts SET failure_code='impossible' WHERE authorization_digest=?",
            (first.record.authorization_digest,),
        )
        read = self.ledger.read_attempt(
            authorization_digest=first.record.authorization_digest
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_FAILURE_STATE_INVALID", read.reason)

    def test_failed_after_claim_without_failure_code_is_corrupt(self):
        first = self.claim()
        failed = self.ledger.mark_failed_after_claim(
            authorization_digest=first.record.authorization_digest,
            attempt_id=first.record.attempt_id,
            failure_code="NETWORK_UNCERTAIN",
        )
        self.assertEqual(BrokerLedgerDecision.PASS, failed.decision)
        self.mutate(
            "UPDATE effect_attempts SET failure_code=NULL WHERE authorization_digest=?",
            (first.record.authorization_digest,),
        )
        read = self.ledger.read_attempt(
            authorization_digest=first.record.authorization_digest
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_FAILURE_STATE_INVALID", read.reason)

    def test_non_hex_signature_digest_is_corrupt(self):
        first = self.claim()
        self.mutate(
            "UPDATE effect_attempts SET signature_digest=? WHERE authorization_digest=?",
            ("G" * 64, first.record.authorization_digest),
        )
        read = self.ledger.read_attempt(
            authorization_digest=first.record.authorization_digest
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_DIGEST_INVALID", read.reason)

    def test_noncanonical_attempt_id_is_corrupt(self):
        first = self.claim()
        self.mutate(
            "UPDATE effect_attempts SET attempt_id='evil' WHERE authorization_digest=?",
            (first.record.authorization_digest,),
        )
        read = self.ledger.read_attempt(
            authorization_digest=first.record.authorization_digest
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_ATTEMPT_ID_INVALID", read.reason)

    def test_signed_binding_field_tamper_is_detected_from_canonical_digest(self):
        first = self.claim()
        self.mutate(
            "UPDATE effect_attempts SET requested_capability='DEPLOY' WHERE authorization_digest=?",
            (first.record.authorization_digest,),
        )
        read = self.ledger.read_attempt(
            authorization_digest=first.record.authorization_digest
        )
        self.assertEqual(BrokerLedgerDecision.BLOCKED, read.decision)
        self.assertEqual("BROKER_LEDGER_AUTHORIZATION_BINDING_INVALID", read.reason)


if __name__ == "__main__":
    unittest.main()
