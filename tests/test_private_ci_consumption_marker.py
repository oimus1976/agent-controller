import json
import os
from pathlib import Path
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

    def test_install_protected_marker_acl_missing_file_raises_value_error(self):
        from agent_controller.private_ci_consumption_marker import install_protected_marker_acl

        with self.assertRaisesRegex(ValueError, "marker missing or not a regular file"):
            install_protected_marker_acl(Path("nonexistent/marker.json"))

    def test_install_protected_marker_acl_reparse_point_raises_value_error(self):
        import tempfile
        from unittest.mock import MagicMock, patch
        from agent_controller.private_ci_consumption_marker import install_protected_marker_acl

        mock_reparse_stat = MagicMock()
        mock_reparse_stat.st_mode = 0o100644
        mock_reparse_stat.st_file_attributes = 0x400

        with tempfile.NamedTemporaryFile() as temp_file:
            path = Path(temp_file.name)
            with patch.object(Path, "lstat", return_value=mock_reparse_stat):
                with self.assertRaisesRegex(ValueError, "marker ReparsePoint blocked"):
                    install_protected_marker_acl(path)

    def test_install_protected_marker_acl_powershell_failure_raises_value_error(self):
        import tempfile
        import subprocess
        from unittest.mock import patch
        from agent_controller.private_ci_consumption_marker import install_protected_marker_acl

        with tempfile.NamedTemporaryFile() as temp_file:
            path = Path(temp_file.name)
            with patch(
                "subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr="Access denied"
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError, "protected marker ACL installation failed"
                ):
                    install_protected_marker_acl(path)

    def test_install_protected_marker_acl_oserror_raises_value_error(self):
        import tempfile
        from unittest.mock import patch
        from agent_controller.private_ci_consumption_marker import install_protected_marker_acl

        with tempfile.NamedTemporaryFile() as temp_file:
            path = Path(temp_file.name)
            with patch("subprocess.run", side_effect=OSError("powershell not found")):
                with self.assertRaisesRegex(
                    ValueError, "protected marker ACL installation unavailable"
                ):
                    install_protected_marker_acl(path)

    def test_install_protected_marker_acl_uses_safe_path_transport(self):
        import tempfile
        import subprocess
        from unittest.mock import patch
        from agent_controller.private_ci_consumption_marker import (
            install_protected_marker_acl,
            _INSTALL_PROTECTED_MARKER_ACL_SCRIPT,
        )

        with tempfile.NamedTemporaryFile() as temp_file:
            path = Path(temp_file.name)
            captured_call = {}

            def fake_run(cmd, env=None, **kwargs):
                captured_call["cmd"] = cmd
                captured_call["env"] = env
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

            with patch.dict(os.environ, {"PSModulePath": r"C:\Program Files\PowerShell\7\Modules"}, clear=False):
                with patch("subprocess.run", side_effect=fake_run):
                    install_protected_marker_acl(path)

            self.assertFalse(
                any(key.upper() == "PSMODULEPATH" for key in captured_call["env"])
            )
            self.assertIn("TARGET_MARKER_PATH", captured_call["env"])
            self.assertEqual(captured_call["env"]["TARGET_MARKER_PATH"], str(path))
            # Verify script references env variable rather than interpolating literal path
            self.assertIn("$LiteralPath = $env:TARGET_MARKER_PATH", _INSTALL_PROTECTED_MARKER_ACL_SCRIPT)
            self.assertNotIn(str(path), _INSTALL_PROTECTED_MARKER_ACL_SCRIPT)

    def test_real_windows_install_protected_marker_acl_roundtrip(self):
        if os.name != "nt":
            self.skipTest("real Windows marker ACL roundtrip test")
        import tempfile
        from agent_controller.private_ci_consumption_marker import (
            install_protected_marker_acl,
            read_consumption_acl_state,
        )

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"marker payload")
            temp_file.flush()
        marker_path = Path(temp_file.name)
        try:
            install_protected_marker_acl(marker_path)
            acl = read_consumption_acl_state(marker_path)
            self.assertTrue(acl.get("protected"))
            rules = acl.get("rules", [])
            for r in rules:
                self.assertFalse(r.get("inherited"))
            mutating_sids = {r.get("sid") for r in rules if r.get("can_mutate")}
            self.assertEqual(mutating_sids, {"S-1-5-18", "S-1-5-32-544"})
            users_rules = [r for r in rules if r.get("sid") == "S-1-5-32-545"]
            self.assertTrue(users_rules)
            for ur in users_rules:
                self.assertFalse(ur.get("can_mutate"))
        finally:
            marker_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

