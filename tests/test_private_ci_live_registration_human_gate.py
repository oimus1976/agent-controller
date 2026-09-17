import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from agent_controller.private_ci_human_approval import (
    ADMINISTRATORS_SID,
    APPROVAL_SCHEMA,
    SYSTEM_SID,
    approval_sha256,
)
from agent_controller.private_ci_phase0_evidence import (
    EXPECTED_BROKER_IDENTITY,
    EXPECTED_HOST,
)


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_private_ci_live_registration.py"
SPEC = importlib.util.spec_from_file_location("run_private_ci_live_registration", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


PLAN_SHA = "a" * 64


def approval_bytes():
    payload = {
        "schema": APPROVAL_SCHEMA,
        "plan_sha256": PLAN_SHA,
        "host": EXPECTED_HOST,
        "approver_identity": EXPECTED_BROKER_IDENTITY,
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }
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


class HumanAuthorizationGateTests(unittest.TestCase):
    def test_live_gate_no_longer_uses_tty_as_authority(self):
        source = Path(SCRIPT_PATH).read_text(encoding="utf-8")
        self.assertNotIn("isatty", source)
        self.assertNotIn("readline", source)
        self.assertNotIn("_require_interactive_human_authorization", source)
        self.assertIn("_require_human_approval", source)

    def test_elevated_apply_is_blocked(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": '{"elevated":true}', "stderr": ""})()
        with mock.patch.object(MODULE, "_completed", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "must run non-elevated"):
                MODULE._require_non_elevated_broker()

    def test_non_elevated_apply_can_validate_separately_issued_approval(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "approval.json"
            raw = approval_bytes()
            path.write_bytes(raw)
            with (
                mock.patch.object(MODULE, "_approval_path", return_value=path),
                mock.patch.object(MODULE, "_require_non_elevated_broker"),
                mock.patch.object(MODULE, "_approval_acl_state", return_value=strong_acl()),
            ):
                observed = MODULE._require_human_approval(PLAN_SHA)
            self.assertEqual(observed, approval_sha256(raw))

    def test_missing_approval_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "missing.json"
            with (
                mock.patch.object(MODULE, "_approval_path", return_value=path),
                mock.patch.object(MODULE, "_require_non_elevated_broker"),
            ):
                with self.assertRaisesRegex(RuntimeError, "approval artifact missing"):
                    MODULE._require_human_approval(PLAN_SHA)

    def test_weak_acl_blocks_approval(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "approval.json"
            path.write_bytes(approval_bytes())
            weak_acl = strong_acl()
            weak_acl["protected"] = False
            with (
                mock.patch.object(MODULE, "_approval_path", return_value=path),
                mock.patch.object(MODULE, "_require_non_elevated_broker"),
                mock.patch.object(MODULE, "_approval_acl_state", return_value=weak_acl),
            ):
                with self.assertRaisesRegex(ValueError, "inheritance"):
                    MODULE._require_human_approval(PLAN_SHA)


if __name__ == "__main__":
    unittest.main()
