import json
import unittest

from agent_controller.private_ci_consumption_marker import (
    CONSUMPTION_SCHEMA,
    canonical_consumption_bytes,
    parse_consumption_marker_bytes,
    validate_consumption_acl_state,
    validate_consumption_container_acl_state,
)


PLAN_SHA = "a" * 64
PHASE0_SHA = "b" * 64
APPROVAL_SHA = "c" * 64


def marker_bytes(**overrides):
    payload = {
        "schema": CONSUMPTION_SCHEMA,
        "plan_sha256": PLAN_SHA,
        "phase0_evidence_sha256": PHASE0_SHA,
        "human_approval_sha256": APPROVAL_SHA,
        "consumed_at": "2026-09-17T14:00:00+00:00",
    }
    payload.update(overrides)
    return canonical_consumption_bytes(payload)


def protected_acl(*, untrusted_mutator=False):
    rules = [
        {
            "sid": "S-1-5-18",
            "access_type": "Allow",
            "inherited": False,
            "can_mutate": True,
        },
        {
            "sid": "S-1-5-32-544",
            "access_type": "Allow",
            "inherited": False,
            "can_mutate": True,
        },
        {
            "sid": "S-1-5-32-545",
            "access_type": "Allow",
            "inherited": False,
            "can_mutate": untrusted_mutator,
        },
    ]
    return {
        "protected": True,
        "owner_sid": "S-1-5-32-544",
        "rules": rules,
    }


class ProtectedConsumptionMarkerTests(unittest.TestCase):
    def test_exact_marker_is_accepted(self):
        marker = parse_consumption_marker_bytes(
            marker_bytes(),
            expected_plan_sha256=PLAN_SHA,
            expected_phase0_evidence_sha256=PHASE0_SHA,
            expected_human_approval_sha256=APPROVAL_SHA,
        )
        self.assertEqual(marker.plan_sha256, PLAN_SHA)
        self.assertEqual(marker.phase0_evidence_sha256, PHASE0_SHA)
        self.assertEqual(marker.human_approval_sha256, APPROVAL_SHA)

    def test_wrong_hash_bindings_are_rejected(self):
        cases = (
            ("plan SHA-256 mismatch", {"expected_plan_sha256": "d" * 64}),
            ("Phase 0 SHA-256 mismatch", {"expected_phase0_evidence_sha256": "d" * 64}),
            ("human approval SHA-256 mismatch", {"expected_human_approval_sha256": "d" * 64}),
        )
        for message, changed in cases:
            kwargs = {
                "expected_plan_sha256": PLAN_SHA,
                "expected_phase0_evidence_sha256": PHASE0_SHA,
                "expected_human_approval_sha256": APPROVAL_SHA,
            }
            kwargs.update(changed)
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    parse_consumption_marker_bytes(marker_bytes(), **kwargs)

    def test_noncanonical_marker_is_rejected(self):
        payload = json.loads(marker_bytes().decode("utf-8"))
        raw = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "not canonical"):
            parse_consumption_marker_bytes(
                raw,
                expected_plan_sha256=PLAN_SHA,
                expected_phase0_evidence_sha256=PHASE0_SHA,
                expected_human_approval_sha256=APPROVAL_SHA,
            )

    def test_marker_and_container_acl_require_admin_only_mutation(self):
        validate_consumption_acl_state(protected_acl())
        validate_consumption_container_acl_state(protected_acl())
        with self.assertRaisesRegex(ValueError, "untrusted principal"):
            validate_consumption_acl_state(protected_acl(untrusted_mutator=True))
        with self.assertRaisesRegex(ValueError, "untrusted principal"):
            validate_consumption_container_acl_state(protected_acl(untrusted_mutator=True))

    def test_inherited_acl_is_rejected(self):
        acl = protected_acl()
        acl["protected"] = False
        with self.assertRaisesRegex(ValueError, "inheritance"):
            validate_consumption_acl_state(acl)

    def test_read_consumption_acl_state_atomic_rights(self):
        from agent_controller.private_ci_consumption_marker import (
            _ATOMIC_MUTATING_FILE_SYSTEM_RIGHTS,
        )
        expected_rights = {
            "WriteData",
            "AppendData",
            "WriteAttributes",
            "WriteExtendedAttributes",
            "Delete",
            "DeleteSubdirectoriesAndFiles",
            "ChangePermissions",
            "TakeOwnership",
        }
        self.assertEqual(set(_ATOMIC_MUTATING_FILE_SYSTEM_RIGHTS), expected_rights)

    def test_read_consumption_acl_state_powershell_failure_raises_value_error(self):
        from unittest.mock import patch
        from pathlib import Path
        import subprocess
        from agent_controller.private_ci_consumption_marker import read_consumption_acl_state

        with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Error")):
            with self.assertRaisesRegex(ValueError, "ACL readback failed"):
                read_consumption_acl_state(Path("some/path"))

    def test_read_consumption_acl_state_json_decode_error_raises_value_error(self):
        from unittest.mock import patch
        from pathlib import Path
        import subprocess
        from agent_controller.private_ci_consumption_marker import read_consumption_acl_state

        with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="not valid json", stderr="")):
            with self.assertRaisesRegex(ValueError, "ACL readback invalid"):
                read_consumption_acl_state(Path("some/path"))


if __name__ == "__main__":
    unittest.main()
