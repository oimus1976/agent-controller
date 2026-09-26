"""Issue #263: SMB exposure helpers that gate trust of System (PID 4) handles.

Pure helpers run on every platform. Real Windows handle-table and share
enumeration regressions live in
``test_private_ci_burned_evidence_archive_windows.py``.
"""

import unittest
from pathlib import Path
from unittest import mock

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


class EvidenceRootExposureTests(unittest.TestCase):
    """_evidence_root_exposed_by_smb with enumeration and resolution patched."""

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "evidence"
        self.root.mkdir()
        self.real_resolve = Path.resolve

    def tearDown(self):
        self._tmp.cleanup()

    def _resolve_with(self, overrides):
        real_resolve = self.real_resolve

        def fake_resolve(path_self, strict=False):
            key = str(path_self)
            if key in overrides:
                value = overrides[key]
                if isinstance(value, Exception):
                    raise value
                return Path(value)
            return real_resolve(path_self, strict=strict)

        return fake_resolve

    def test_unresolvable_relevant_share_fails_closed(self):
        shares = (("alias", "ALIAS-SHARE-PATH", m.STYPE_DISKTREE),)
        with mock.patch.object(m, "_smb_disk_shares", return_value=shares), \
                mock.patch.object(
                    Path,
                    "resolve",
                    self._resolve_with({"ALIAS-SHARE-PATH": OSError("target offline")}),
                ):
            with self.assertRaisesRegex(RuntimeError, "cannot be resolved: alias"):
                m._evidence_root_exposed_by_smb(self.root)

    def test_unresolvable_special_or_non_disk_share_is_ignored(self):
        shares = (
            ("C$", "SPECIAL-PATH", m.STYPE_SPECIAL | m.STYPE_DISKTREE),
            ("printer", "PRINTER-PATH", 1),
        )
        overrides = {
            "SPECIAL-PATH": OSError("unused"),
            "PRINTER-PATH": OSError("unused"),
        }
        with mock.patch.object(m, "_smb_disk_shares", return_value=shares), \
                mock.patch.object(Path, "resolve", self._resolve_with(overrides)):
            self.assertIs(m._evidence_root_exposed_by_smb(self.root), False)

    def test_resolved_share_target_above_root_exposes(self):
        parent = str(self.real_resolve(self.root.parent, strict=True))
        shares = (("alias", "ALIAS-SHARE-PATH", m.STYPE_DISKTREE),)
        with mock.patch.object(m, "_smb_disk_shares", return_value=shares), \
                mock.patch.object(
                    Path,
                    "resolve",
                    self._resolve_with({"ALIAS-SHARE-PATH": parent}),
                ):
            self.assertIs(m._evidence_root_exposed_by_smb(self.root), True)

    def test_unrelated_resolved_share_does_not_expose(self):
        shares = (("data", "DATA-SHARE-PATH", m.STYPE_DISKTREE),)
        with mock.patch.object(m, "_smb_disk_shares", return_value=shares), \
                mock.patch.object(
                    Path,
                    "resolve",
                    self._resolve_with({"DATA-SHARE-PATH": "/unrelated/data"}),
                ):
            self.assertIs(m._evidence_root_exposed_by_smb(self.root), False)


class ShareEnumerationPlatformTests(unittest.TestCase):
    @unittest.skipIf(m.os.name == "nt", "non-Windows guard")
    def test_enumeration_outside_windows_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "requires Windows"):
            m._smb_disk_shares()


if __name__ == "__main__":
    unittest.main()
