import re
import unittest
from pathlib import Path

from agent_controller.private_ci_human_approval import validate_approval_acl_state
from scripts import run_private_ci_live_registration as live_script


ATOMIC_MUTATION_RIGHTS = {
    "WriteData",
    "AppendData",
    "WriteAttributes",
    "WriteExtendedAttributes",
    "Delete",
    "DeleteSubdirectoriesAndFiles",
    "ChangePermissions",
    "TakeOwnership",
}

# FileSystemRights values are stable .NET/Win32 access-mask bits. WriteData and
# AppendData also represent directory CreateFiles and CreateDirectories.
RIGHT_VALUES = {
    "ReadAndExecute": 0x000200A9,
    "WriteData": 0x00000002,
    "AppendData": 0x00000004,
    "WriteAttributes": 0x00000100,
    "WriteExtendedAttributes": 0x00000010,
    "Delete": 0x00010000,
    "DeleteSubdirectoriesAndFiles": 0x00000040,
    "ChangePermissions": 0x00040000,
    "TakeOwnership": 0x00080000,
}


class AclMutationRightsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.helper_source = (
            root / "scripts" / "Consume-PrivateCiLiveRegistrationApproval.ps1"
        ).read_text(encoding="utf-8")

    def test_python_and_helper_use_the_same_atomic_mutation_rights(self):
        self.assertEqual(
            set(live_script._ATOMIC_MUTATING_FILE_SYSTEM_RIGHTS),
            ATOMIC_MUTATION_RIGHTS,
        )
        helper_mask = self.helper_source.split("$MutationMask = (", 1)[1].split(")", 1)[0]
        helper_rights = set(re.findall(r"FileSystemRights\]::([A-Za-z]+)", helper_mask))
        self.assertEqual(helper_rights, ATOMIC_MUTATION_RIGHTS)
        self.assertNotRegex(helper_mask, r"FileSystemRights\]::(?:Write|Modify|FullControl)\b")

    def test_read_and_execute_is_not_mutating_but_every_atomic_right_is(self):
        mutation_mask = 0
        for right in live_script._ATOMIC_MUTATING_FILE_SYSTEM_RIGHTS:
            mutation_mask |= RIGHT_VALUES[right]

        self.assertEqual(RIGHT_VALUES["ReadAndExecute"] & mutation_mask, 0)
        trusted_rules = [
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
                "can_mutate": bool(RIGHT_VALUES["ReadAndExecute"] & mutation_mask),
            },
        ]
        validate_approval_acl_state(
            {
                "protected": True,
                "owner_sid": "S-1-5-32-544",
                "rules": trusted_rules,
            }
        )

        for right in ATOMIC_MUTATION_RIGHTS:
            with self.subTest(right=right):
                self.assertNotEqual(RIGHT_VALUES[right] & mutation_mask, 0)
                untrusted_rules = trusted_rules + [
                    {
                        "sid": "S-1-5-21-1-2-3-1001",
                        "access_type": "Allow",
                        "inherited": False,
                        "can_mutate": bool(RIGHT_VALUES[right] & mutation_mask),
                    }
                ]
                with self.assertRaisesRegex(ValueError, "untrusted principal"):
                    validate_approval_acl_state(
                        {
                            "protected": True,
                            "owner_sid": "S-1-5-32-544",
                            "rules": untrusted_rules,
                        }
                    )

    def test_helper_applies_self_validated_read_only_users_acls(self):
        self.assertGreaterEqual(
            self.helper_source.count(
                "[Security.AccessControl.FileSystemRights]::ReadAndExecute"
            ),
            2,
        )
        self.assertIn("Test-ProtectedAcl -LiteralPath $ApprovalPath", self.helper_source)
        self.assertIn("Test-ProtectedAcl -LiteralPath $AuthorityRoot", self.helper_source)
        self.assertIn("Test-ProtectedAcl -LiteralPath $MarkerPath", self.helper_source)


if __name__ == "__main__":
    unittest.main()
