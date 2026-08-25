import hashlib
import inspect
import unittest

from agent_controller.broker_epoch import (
    BrokerContinuityState,
    EpochBoundApprovalGate,
    TrustedBrokerAuthorityConfig,
)
from agent_controller.signed_approval import (
    ApprovalChallenge,
    ApprovalChallengeV3,
    canonicalize_approval_challenge,
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


def legacy_v2():
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


class BrokerEpochTests(unittest.TestCase):
    def setUp(self):
        self.config = TrustedBrokerAuthorityConfig(
            broker_authority_id="broker-prod-primary",
            broker_epoch="epoch-2026-08-25-a",
        )
        self.gate = EpochBoundApprovalGate(config=self.config)

    def test_exact_v3_signature_current_epoch_passes(self):
        item = challenge_v3()
        result = self.gate.validate_for_claim(
            challenge=item, signature_b64=SIGNATURE_V3
        )
        self.assertTrue(result.valid)
        self.assertEqual(
            hashlib.sha256(canonicalize_approval_challenge(item)).hexdigest(),
            result.authorization_digest,
        )

    def test_old_epoch_is_blocked_before_claim(self):
        result = EpochBoundApprovalGate(
            config=TrustedBrokerAuthorityConfig(
                broker_authority_id="broker-prod-primary",
                broker_epoch="epoch-2026-08-25-b",
            )
        ).validate_for_claim(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        self.assertFalse(result.valid)
        self.assertEqual("BROKER_EPOCH_MISMATCH", result.reason)

    def test_wrong_authority_is_blocked(self):
        result = EpochBoundApprovalGate(
            config=TrustedBrokerAuthorityConfig(
                broker_authority_id="broker-prod-secondary",
                broker_epoch="epoch-2026-08-25-a",
            )
        ).validate_for_claim(challenge=challenge_v3(), signature_b64=SIGNATURE_V3)
        self.assertFalse(result.valid)
        self.assertEqual("BROKER_AUTHORITY_MISMATCH", result.reason)

    def test_recovery_suspended_blocks_even_valid_signature(self):
        gate = EpochBoundApprovalGate(
            config=TrustedBrokerAuthorityConfig(
                broker_authority_id="broker-prod-primary",
                broker_epoch="epoch-2026-08-25-a",
                continuity_state=BrokerContinuityState.RECOVERY_SUSPENDED,
            )
        )
        result = gate.validate_for_claim(
            challenge=challenge_v3(), signature_b64=SIGNATURE_V3
        )
        self.assertFalse(result.valid)
        self.assertEqual("BROKER_RECOVERY_SUSPENDED", result.reason)

    def test_v2_cannot_enter_production_epoch_gate(self):
        result = self.gate.validate_for_claim(
            challenge=legacy_v2(), signature_b64="irrelevant"
        )
        self.assertFalse(result.valid)
        self.assertEqual("V3_CHALLENGE_REQUIRED", result.reason)

    def test_tampered_epoch_breaks_signature_even_if_gate_config_matches_tamper(self):
        item = challenge_v3(broker_epoch="epoch-attacker")
        gate = EpochBoundApprovalGate(
            config=TrustedBrokerAuthorityConfig(
                broker_authority_id=item.broker_authority_id,
                broker_epoch=item.broker_epoch,
            )
        )
        result = gate.validate_for_claim(challenge=item, signature_b64=SIGNATURE_V3)
        self.assertFalse(result.valid)
        self.assertEqual("SIGNATURE_INVALID", result.reason)

    def test_tampered_authority_breaks_signature_even_if_gate_config_matches_tamper(self):
        item = challenge_v3(broker_authority_id="broker-attacker")
        gate = EpochBoundApprovalGate(
            config=TrustedBrokerAuthorityConfig(
                broker_authority_id=item.broker_authority_id,
                broker_epoch=item.broker_epoch,
            )
        )
        result = gate.validate_for_claim(challenge=item, signature_b64=SIGNATURE_V3)
        self.assertFalse(result.valid)
        self.assertEqual("SIGNATURE_INVALID", result.reason)

    def test_epoch_changes_canonical_replay_identity(self):
        a = challenge_v3()
        b = challenge_v3(broker_epoch="epoch-2026-08-25-b")
        self.assertNotEqual(
            hashlib.sha256(canonicalize_approval_challenge(a)).hexdigest(),
            hashlib.sha256(canonicalize_approval_challenge(b)).hexdigest(),
        )

    def test_public_api_has_no_per_call_authority_or_epoch_override(self):
        params = set(inspect.signature(self.gate.validate_for_claim).parameters)
        self.assertEqual({"challenge", "signature_b64"}, params)


if __name__ == "__main__":
    unittest.main()
