import os
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows-only PowerShell 5.1 regression")
class PrivateCiBurnedEvidenceArchiveWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.script = (
            cls.repo_root / "scripts" / "Archive-PrivateCiBurnedEvidence.ps1"
        )
        cls.powershell = shutil.which("powershell.exe")
        if cls.powershell is None:
            raise unittest.SkipTest("Windows PowerShell 5.1 unavailable")

    def test_apply_bridge_parses_under_windows_powershell_51(self):
        quoted = str(self.script).replace("'", "''")
        command = (
            "$ErrorActionPreference='Stop';"
            "$Errors=$null;"
            "$Tokens=$null;"
            "[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{quoted}',[ref]$Tokens,[ref]$Errors) | Out-Null;"
            "if (@($Errors).Count -ne 0) {"
            "  @($Errors) | ForEach-Object { Write-Error $_.Message };"
            "  exit 2"
            "}"
        )
        completed = subprocess.run(
            [
                self.powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            cwd=self.repo_root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + "\n" + completed.stderr,
        )


    def test_locked_source_blocks_write_replace_and_retires_same_handle(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            replacement = root / "replacement.bin"
            raw = b"frozen-source"
            source.write_bytes(raw)
            replacement.write_bytes(b"replacement")

            handle = m._open_locked_source(
                source,
                expected_sha256=hashlib.sha256(raw).hexdigest(),
                expected_size=len(raw),
            )
            try:
                with self.assertRaises(OSError):
                    source.write_bytes(b"drift")
                with self.assertRaises(OSError):
                    os.replace(replacement, source)
                m._mark_delete_on_close(handle)
            finally:
                handle.close()

            self.assertFalse(source.exists())

    def test_hardlinked_source_is_rejected(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            sibling = root / "sibling.bin"
            raw = b"hard-link-source"
            source.write_bytes(raw)
            os.link(source, sibling)
            with self.assertRaisesRegex(RuntimeError, "hard-linked"):
                m._open_locked_source(
                    source,
                    expected_sha256=hashlib.sha256(raw).hexdigest(),
                    expected_size=len(raw),
                )

    def test_destination_creation_is_exclusive(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "archive.bin"
            first = m._create_locked_destination(destination)
            try:
                with self.assertRaises(OSError):
                    m._create_locked_destination(destination)
            finally:
                first.close()

    def test_relative_destination_stays_under_locked_directory_after_rename(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root_handle = m._open_locked_directory(parent)
            try:
                archive_handle = m._create_relative_directory(
                    root_handle, "archive"
                )
                try:
                    renamed = parent / "archive-renamed"
                    os.replace(parent / "archive", renamed)
                    (parent / "archive").mkdir()

                    destination = m._create_locked_destination_relative(
                        archive_handle,
                        "evidence.bin",
                    )
                    try:
                        m._write_all(destination, b"locked-destination")
                    finally:
                        destination.close()

                    self.assertEqual(
                        (renamed / "evidence.bin").read_bytes(),
                        b"locked-destination",
                    )
                    self.assertFalse(
                        (parent / "archive" / "evidence.bin").exists()
                    )
                finally:
                    archive_handle.close()
            finally:
                root_handle.close()

    def test_canonical_root_identity_rejects_path_replacement(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp)
            evidence = outer / "evidence"
            renamed = outer / "evidence-renamed"
            evidence.mkdir()

            root_handle = m._open_locked_directory(evidence)
            try:
                os.replace(evidence, renamed)
                evidence.mkdir()
                with self.assertRaisesRegex(RuntimeError, "identity drift"):
                    m._require_path_directory_identity(
                        evidence,
                        root_handle,
                        "authoritative evidence root",
                    )
            finally:
                root_handle.close()

    def test_relative_source_open_stays_bound_to_evidence_root_handle(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp)
            evidence = outer / "evidence"
            evidence.mkdir()
            source = evidence / "source.bin"
            raw = b"relative-source"
            source.write_bytes(raw)

            root_handle = m._open_locked_directory(evidence)
            try:
                renamed = outer / "evidence-renamed"
                os.replace(evidence, renamed)
                evidence.mkdir()
                (evidence / "source.bin").write_bytes(b"replacement")

                handle = m._open_locked_source_relative(
                    root_handle,
                    "source.bin",
                    expected_sha256=hashlib.sha256(raw).hexdigest(),
                    expected_size=len(raw),
                )
                try:
                    self.assertEqual(m._hash_handle(handle), hashlib.sha256(raw).hexdigest())
                finally:
                    handle.close()
            finally:
                root_handle.close()


if __name__ == "__main__":
    unittest.main()
