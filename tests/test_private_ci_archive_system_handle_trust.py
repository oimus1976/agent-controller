"""Issue #263: SMB exposure helpers that gate trust of System (PID 4) handles.

Pure helpers run on every platform. Real Windows handle-table and share
enumeration regressions live in
``test_private_ci_burned_evidence_archive_windows.py``.
"""

import unittest

from agent_controller import private_ci_windows_atomic_archive as m

B = "\\"
ROOT = "C:" + B + "Users" + B + "Public" + B + "Documents" + B + "agent-controller-handoff"


class WindowsPathContainmentTests(unittest.TestCase):
    def test_same_or_under(self):
        cases = (
            (ROOT, "C:" + B + "Users", True),
            (ROOT, "C:" + B, True),
            (ROOT, ROOT, True),
            (ROOT, ROOT + B, True),
            (ROOT.lower(), "C:" + B + "USERS", True),
            (ROOT.replace(B, "/"), "C:" + B + "Users", True),
        )
        for child, parent, expected in cases:
            with self.subTest(child=child, parent=parent):
                self.assertIs(m._windows_path_is_same_or_under(child, parent), expected)

    def test_siblings_prefixes_and_descendants_are_not_containers(self):
        cases = (
            (ROOT, "C:" + B + "Users" + B + "Pub"),
            (ROOT, "C:" + B + "Users" + B + "Public" + B + "Documents" + B + "agent-controller-handoff-old"),
            (ROOT, ROOT + B + "archive"),
            (ROOT, "D:" + B),
            (ROOT, ""),
            ("", "C:" + B),
        )
        for child, parent in cases:
            with self.subTest(child=child, parent=parent):
                self.assertIs(m._windows_path_is_same_or_under(child, parent), False)


class SharesExposePathTests(unittest.TestCase):
    def test_administrative_and_non_disk_shares_are_ignored(self):
        shares = (
            ("C$", "C:" + B, m.STYPE_SPECIAL | m.STYPE_DISKTREE),
            ("ADMIN$", "C:" + B + "Windows", m.STYPE_SPECIAL | m.STYPE_DISKTREE),
            ("IPC$", "", m.STYPE_SPECIAL | 3),
            ("printer", "", 1),
        )
        self.assertIs(m._shares_expose_path(shares, [ROOT]), False)

    def test_non_special_disk_share_on_an_ancestor_exposes_the_root(self):
        for path in ("C:" + B, "C:" + B + "Users", "C:" + B + "Users" + B + "Public", ROOT):
            with self.subTest(path=path):
                shares = (("share", path, m.STYPE_DISKTREE),)
                self.assertIs(m._shares_expose_path(shares, [ROOT]), True)

    def test_temporary_disk_share_still_counts(self):
        shares = (("tmp", "C:" + B + "Users", 0x40000000 | m.STYPE_DISKTREE),)
        self.assertIs(m._shares_expose_path(shares, [ROOT]), True)

    def test_unrelated_or_descendant_share_does_not_expose_the_root(self):
        shares = (
            ("data", "D:" + B + "data", m.STYPE_DISKTREE),
            ("archive", ROOT + B + "archive", m.STYPE_DISKTREE),
        )
        self.assertIs(m._shares_expose_path(shares, [ROOT]), False)

    def test_any_root_form_match_exposes(self):
        resolved = "E:" + B + "evidence"
        shares = (("e", "E:" + B, m.STYPE_DISKTREE),)
        self.assertIs(m._shares_expose_path(shares, [ROOT, resolved]), True)

    def test_disk_share_without_path_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "no path"):
            m._shares_expose_path((("odd", "", m.STYPE_DISKTREE),), [ROOT])

    def test_missing_root_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "needs a root path"):
            m._shares_expose_path((), ["", ""])


class ShareEnumerationPlatformTests(unittest.TestCase):
    @unittest.skipIf(m.os.name == "nt", "non-Windows guard")
    def test_enumeration_outside_windows_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "requires Windows"):
            m._smb_disk_shares()


if __name__ == "__main__":
    unittest.main()
