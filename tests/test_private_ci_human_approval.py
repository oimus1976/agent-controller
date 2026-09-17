import json
import unittest
from datetime import datetime, timedelta, timezone

from agent_controller.private_ci_human_approval import (
    ADMINISTRATORS_SID,
    APPROVAL_SCHEMA,
    SYSTEM_SID,
    approval_filename,
    parse_approval_bytes,
    validate_approval_acl_state,
)
from agent_controller.private_ci_phase0_evidence import (
    EXPECTED_BROKER_IDENTITY,
    EXPECTED_HOST,
)


PLAN_SHA = "a" * 64
NOW = datetime(2026, 9, 17, 13, 0, tzinfo=timezone.utc)


def approval_bytes(*, plan_sha=PLAN_SHA, approved_at=None, **overrides):
    payload = {
        "schema": APPROVAL_SCHEMA,
        "plan_sha256": plan_sha,
        "host": EXPECTED_HOST,
        "approver_identity": EXPECTED_BROKER_IDENTITY,
        "approved_at": (approved_at or NOW).isoformat(),
    }
    payload.update(overrides)
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def strong_acl():
    return {
        "protected": True,
        "owner_sid": ADMINISTRATORS_SID,
        "rules": [
            {
                "sid": SYSTEM_SID,
                "access_type": "Allow",
                "inherited": False,
                "can_mutate": True,
            },
            {
                "sid": ADMINISTRATORS_SID,
                "access_type": "Allow",
                "inherited": False,
                "can_mutate": True,
            },
            {
                "sid": "S-1-5-32-545",
                "access_type": "Allow",
                "inherited": False,
                "can_mutate": False,
            },
        ],
    }


class HumanApprovalContractTests(unittest.TestCase):
    def test_valid_exact_plan_approval_is_accepted(self):
        approval = parse_approval_bytes(
            approval_bytes(),
            expected_plan_sha256=PLAN_SHA,
            now=lambda: NOW + timedelta(minutes=1),
        )
        self.assertEqual(approval.plan_sha256, PLAN_SHA)
        self.assertEqual(
            approval_filename(PLAN_SHA),
            f"issue216-live-registration-approval-{PLAN_SHA}.json",
        )

    def test_wrong_plan_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "plan SHA-256 mismatch"):
            parse_approval_bytes(
                approval_bytes(plan_sha="b" * 64),
                expected_plan_sha256=PLAN_SHA,
                now=lambda: NOW,
            )

    def test_stale_approval_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "stale"):
            parse_approval_bytes(
                approval_bytes(approved_at=NOW - timedelta(minutes=16)),
                expected_plan_sha256=PLAN_SHA,
                now=lambda: NOW,
            )

    def test_unprotected_acl_is_rejected(self):
        acl = strong_acl()
        acl["protected"] = False
        with self.assertRaisesRegex(ValueError, "inheritance"):
            validate_approval_acl_state(acl)

    def test_untrusted_mutating_principal_is_rejected(self):
        acl = strong_acl()
        acl["rules"].append(
            {
                "sid": "S-1-5-32-545",
                "access_type": "Allow",
                "inherited": False,
                "can_mutate": True,
            }
        )
        with self.assertRaisesRegex(ValueError, "untrusted principal"):
            validate_approval_acl_state(acl)

    def test_missing_system_writer_is_rejected(self):
        acl = strong_acl()
        acl["rules"] = [rule for rule in acl["rules"] if rule["sid"] != SYSTEM_SID]
        with self.assertRaisesRegex(ValueError, "missing trusted"):
            validate_approval_acl_state(acl)

    def test_bool_or_non_hex_plan_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "plan SHA-256"):
            approval_filename("z" * 64)


if __name__ == "__main__":
    unittest.main()
