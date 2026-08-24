import dataclasses
import unittest

from agent_controller.signed_approval import (
    ApprovalChallenge,
    ProvenanceAssurance,
    canonicalize_approval_challenge,
    verify_signed_approval,
)


SIGNATURE_B64 = "ysPv815PSBz1qe6IEy/PaH2JuNx8KvqT7F8bRreNVsd4Nlu07qSSUzHiu8t77685fnmLFJAyANIsz6jOdP1UCA=="


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
            signer_key_id="human-key-poc-1",
        )

    def verify(self, challenge=None, signature=SIGNATURE_B64):
        return verify_signed_approval(
            challenge=self.challenge if challenge is None else challenge,
            signature_b64=signature,
        )

    def test_known_valid_signature_verifies(self):
        result = self.verify()
        self.assertTrue(result.valid)
        self.assertEqual(ProvenanceAssurance.VERIFIED_EVENT_PROVENANCE, result.assurance)
        self.assertEqual("human-key-poc-1", result.signer_key_id)

    def test_canonical_representation_is_exact_and_newline_terminated(self):
        payload = canonicalize_approval_challenge(self.challenge)
        self.assertTrue(payload.endswith(b"\n"))
        self.assertIn(b'"schema_version":"agent-controller-approval-challenge-v1"', payload)
        self.assertIn(b'"signer_key_id":"human-key-poc-1"', payload)

    def test_signed_field_mutations_invalidate_signature(self):
        changes = {
            "expected_head_sha": "b" * 40,
            "effect": "DEPLOY",
            "operation_version": "v2",
            "challenge_nonce": "nonce-poc-002",
            "target_id": "1000",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = dataclasses.replace(self.challenge, **{field: value})
                self.assertFalse(self.verify(challenge=changed).valid)

    def test_changed_signer_key_id_fails_closed(self):
        changed = dataclasses.replace(self.challenge, signer_key_id="attacker-key")
        result = self.verify(challenge=changed)
        self.assertFalse(result.valid)
        self.assertEqual("SIGNER_KEY_NOT_CONFIGURED", result.reason)

    def test_malformed_signature_fails_closed(self):
        result = self.verify(signature="not-base64")
        self.assertFalse(result.valid)
        self.assertEqual("SIGNATURE_ENCODING_INVALID", result.reason)

    def test_unknown_schema_fails_closed(self):
        changed = dataclasses.replace(self.challenge, schema_version="future-v2")
        result = self.verify(challenge=changed)
        self.assertFalse(result.valid)
        self.assertEqual("unsupported challenge schema", result.reason)

    def test_supported_api_has_no_public_key_or_store_override(self):
        import inspect
        self.assertEqual(
            {"challenge", "signature_b64"},
            set(inspect.signature(verify_signed_approval).parameters),
        )

    def test_public_module_exposes_no_private_key_or_sign_function(self):
        import agent_controller.signed_approval as module
        names = set(dir(module))
        self.assertNotIn("Ed25519PrivateKey", names)
        self.assertNotIn("sign_approval", names)
        self.assertNotIn("generate_key", names)


if __name__ == "__main__":
    unittest.main()
