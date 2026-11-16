import ctypes
import importlib.util
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(
    os.name == "nt",
    "Windows generation retirement regression",
)
class PrivateCiGenerationRetirementWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo_root = Path(__file__).resolve().parents[1]
        helper_path = repo_root / "scripts" / "retire_private_ci_generation.py"
        spec = importlib.util.spec_from_file_location(
            "retire_private_ci_generation",
            helper_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("failed to load generation retirement helper")
        cls.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.helper)

    def test_identity_bound_generation_retirement_removes_only_generation(self):
        generation = "ac-pilot-0123456789abcdef"
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory) / "private-ci"
            generation_root = parent / generation
            nested = generation_root / "runner" / "_work" / "job"
            nested.mkdir(parents=True)
            (nested / "evidence.txt").write_text("ok", encoding="utf-8")
            sibling = parent / "preserve-me"
            sibling.mkdir()
            (sibling / "sentinel.txt").write_text("keep", encoding="utf-8")

            with patch.object(self.helper, "PRIVATE_CI_ROOT", parent):
                self.helper.retire_generation(generation_root, generation)

            self.assertFalse(generation_root.exists())
            self.assertTrue((sibling / "sentinel.txt").is_file())
            self.assertEqual(
                list(parent.glob(f".retiring-{generation}-*")),
                [],
            )

    def test_handle_rename_produces_exactly_the_intended_name(self):
        # #325: KernelBase reads FileRenameInfo.FileName as a NUL-terminated
        # path. Poison the bytes just past the size the helper requests so a
        # missing terminator deterministically shows up as a corrupted name.
        real_create_string_buffer = ctypes.create_string_buffer

        def poisoned_create_string_buffer(init, size=None):
            if not isinstance(init, int) or size is not None:
                return real_create_string_buffer(init, size)
            buffer = real_create_string_buffer(init + 16)
            ctypes.memset(ctypes.addressof(buffer) + init, 0x41, 8)
            return buffer

        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            source = parent / "ac-pilot-0011223344556677"
            source.mkdir()
            intended = parent / ".retiring-ac-pilot-0011223344556677-0123abcd"

            kernel32, handle = self.helper._open_directory_handle(source)
            try:
                with patch.object(
                    self.helper.ctypes,
                    "create_string_buffer",
                    poisoned_create_string_buffer,
                ):
                    self.helper._rename_by_handle(kernel32, handle, intended)
            finally:
                kernel32.CloseHandle(handle)

            self.assertEqual(os.listdir(parent), [intended.name])
            self.assertTrue(intended.is_dir())

    def test_generation_retirement_deletes_read_only_descendants(self):
        # #325: runner _work checkouts contain read-only git objects.
        generation = "ac-pilot-00aa11bb22cc33dd"
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory) / "private-ci"
            generation_root = parent / generation
            objects = generation_root / "runner" / "_work" / "repo" / ".git" / "objects" / "ab"
            objects.mkdir(parents=True)
            read_only_file = objects / "cdef0123456789"
            read_only_file.write_bytes(b"blob")
            os.chmod(read_only_file, stat.S_IREAD)
            read_only_dir = generation_root / "runner" / "_work" / "read-only-dir"
            read_only_dir.mkdir()
            (read_only_dir / "inner.txt").write_text("x", encoding="utf-8")
            os.chmod(read_only_dir / "inner.txt", stat.S_IREAD)
            os.chmod(read_only_dir, stat.S_IREAD)

            try:
                with patch.object(self.helper, "PRIVATE_CI_ROOT", parent):
                    self.helper.retire_generation(generation_root, generation)
            finally:
                for path in parent.rglob("*"):
                    os.chmod(path, stat.S_IWRITE)

            self.assertFalse(generation_root.exists())
            self.assertEqual(list(parent.iterdir()), [])

    def test_generation_retirement_blocks_junction_without_touching_target(self):
        generation = "ac-pilot-fedcba9876543210"
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory) / "private-ci"
            generation_root = parent / generation
            generation_root.mkdir(parents=True)
            outside = Path(temporary_directory) / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel.txt"
            sentinel.write_text("keep", encoding="utf-8")
            junction = generation_root / "junction"

            completed = subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(junction),
                    str(outside),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            with patch.object(self.helper, "PRIVATE_CI_ROOT", parent):
                with self.assertRaisesRegex(RuntimeError, "reparse point"):
                    self.helper.retire_generation(generation_root, generation)

            self.assertTrue(sentinel.is_file())
            self.assertTrue(generation_root.is_dir())


if __name__ == "__main__":
    unittest.main()
