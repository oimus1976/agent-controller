import dataclasses
import unittest

from agent_controller.signed_approval import (
    ApprovalChallenge,
    canonicalize_approval_challenge,
    verify_signed_approval,
)


PUBLIC_KEY_B64 = "7Q0UMfe+yvtb1GiAnwKMKLgdKEzBX7IvGIRXuOkoxxM="
SIGNATURE_B64 = "QtGev92Rm5/ffPol+8S7KS3uWWPS8lmUpJ+J9bXEQyiLWr08C3Nr24Qo9tysdsdG6hOY+IfKTU2bLB5RHRgbBA=="


class SignedApprovalTests(unittest.TestCase):
    def setUp(self):
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
        )

    def verify(self, challenge=None, signature=SIGNATURE_B64, public_key=PUBLIC_KEY_B64, key_id="human-key-poc-1"):
        return verify_signed_approval(
            challenge=self.challenge if challenge is None else challenge,
            signature_b64=signature,
            pinned_public_key_b64=public_key,
            signer_key_id=key_id,
        )

    def test_known_valid_signature_verifies(self):
        result = self.verify()
        self.assertTrue(result.valid)
        self.assertEqual("VERIFIED_EVENT_PROVENANCE", result.assurance)
        self.assertEqual("human-key-poc-1", result.signer_key_id)

    def test_canonical_representation_is_exact_and_newline_terminated(self):
        payload = canonicalize_approval_challenge(self.challenge)
        self.assertTrue(payload.endswith(b"\n"))
        self.assertIn(b'"schema_version":"agent-controller-approval-challenge-v1"', payload)

    def test_changed_head_invalidates_signature(self):
        changed = dataclasses.replace(self.challenge, expected_head_sha="b" * 40)
        result = self.verify(challenge=changed)
        self.assertFalse(result.valid)
        self.assertEqual("SIGNATURE_INVALID", result.reason)

    def test_changed_effect_invalidates_signature(self):
        changed = dataclasses.replace(self.challenge, effect="DEPLOY")
        self.assertFalse(self.verify(challenge=changed).valid)

    def test_changed_operation_version_invalidates_signature(self):
        changed = dataclasses.replace(self.challenge, operation_version="v2")
        self.assertFalse(self.verify(challenge=changed).valid)

    def test_changed_nonce_invalidates_signature(self):
        changed = dataclasses.replace(self.challenge, challenge_nonce="nonce-poc-002")
        self.assertFalse(self.verify(challenge=changed).valid)

    def test_changed_target_invalidates_signature(self):
        changed = dataclasses.replace(self.challenge, target_id="1000")
        self.assertFalse(self.verify(challenge=changed).valid)

    def test_wrong_public_key_fails_closed(self):
        wrong_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        result = self.verify(public_key=wrong_key)
        self.assertFalse(result.valid)
        self.assertEqual("SIGNATURE_INVALID", result.reason)

    def test_malformed_signature_fails_closed(self):
        result = self.verify(signature="not-base64")
        self.assertFalse(result.valid)
        self.assertEqual("SIGNATURE_ENCODING_INVALID", result.reason)

    def test_empty_signer_key_id_fails_closed(self):
        result = self.verify(key_id="")
        self.assertFalse(result.valid)
        self.assertEqual("SIGNER_KEY_ID_MISSING", result.reason)

    def test_empty_challenge_field_fails_closed(self):
        changed = dataclasses.replace(self.challenge, approval_id="")
        result = self.verify(challenge=changed)
        self.assertFalse(result.valid)
        self.assertIn("approval_id", result.reason)

    def test_unknown_schema_fails_closed(self):
        changed = dataclasses.replace(self.challenge, schema_version="future-v2")
        result = self.verify(challenge=changed)
        self.assertFalse(result.valid)
        self.assertEqual("unsupported challenge schema", result.reason)

    def test_model_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.challenge.operation_id = "other"

    def test_public_module_exposes_no_private_key_or_sign_function(self):
        import agent_controller.signed_approval as module

        names = set(dir(module))
        self.assertNotIn("Ed25519PrivateKey", names)
        self.assertNotIn("sign_approval", names)
        self.assertNotIn("generate_key", names)


if __name__ == "__main__":
    unittest.main()
