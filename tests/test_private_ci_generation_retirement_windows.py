import importlib.util
import os
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
