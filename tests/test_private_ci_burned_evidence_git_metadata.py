"""Real Git fixtures exercise archive source verification without live effects."""

import contextlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


CLI_PATH = Path(__file__).resolve().parents[1] / "scripts/archive_private_ci_burned_evidence.py"
SPEC = importlib.util.spec_from_file_location("archive_git_metadata_under_test", CLI_PATH)
CLI = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CLI
SPEC.loader.exec_module(CLI)


class GitMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.profile = Path(temporary.name).resolve()
        self.root = self.profile / "checkout"
        self.root.mkdir()
        self.common = self.profile / "primary" / ".git"
        self.admin = self.common / "worktrees" / "checkout"

    def linked(self):
        self.admin.mkdir(parents=True)
        (self.root / ".git").write_text(f"gitdir: {self.admin}\n", encoding="utf-8")
        (self.admin / "commondir").write_bytes(b"../..\n")
        (self.admin / "gitdir").write_text(str(self.root / ".git") + "\n", encoding="utf-8")

    def resolve(self):
        return CLI._controller_git_metadata(self.root, self.profile)

    def test_ordinary_directory(self):
        (self.root / ".git").mkdir()
        self.assertEqual(self.resolve()[0], self.root / ".git")

    def test_linked_gitfile_absolute_and_relative(self):
        self.linked()
        self.assertEqual(self.resolve()[0], self.admin)
        (self.root / ".git").write_text(
            "gitdir: " + os.path.relpath(self.admin, self.root) + "\n", encoding="utf-8"
        )
        self.assertEqual(self.resolve()[0], self.admin)

    def test_missing_git_metadata_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            self.resolve()

    def test_malformed_gitfile_is_rejected(self):
        self.linked()
        for raw in (
            b"", b"gitdir:\n", b"gitdir: \n", b"gitdir: ../primary/.git\nsecond\n",
            b"gitdir: ../primary/.git\x00\n", b"gitdir: \xff\n",
            b"gitdir:  ../primary/.git\n", b"gitdir: ../primary/.git \n",
            b"gitdir: ../primary/.git\r", b"gitdir: C:relative\n",
            b"gitdir: ../primary/.git:stream\n",
        ):
            with self.subTest(raw=raw):
                (self.root / ".git").write_bytes(raw)
                with self.assertRaises(RuntimeError):
                    self.resolve()

    def test_gitfile_cannot_point_to_another_ordinary_checkout(self):
        self.common.mkdir(parents=True)
        (self.root / ".git").write_text(f"gitdir: {self.common}\n", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            self.resolve()

    def test_backlink_to_another_checkout_is_rejected(self):
        self.linked()
        other = self.profile / "other"
        other.mkdir()
        (other / ".git").write_text(f"gitdir: {self.admin}\n", encoding="utf-8")
        (self.admin / "gitdir").write_text(str(other / ".git") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "backlink mismatch"):
            self.resolve()

    def test_commondir_outside_profile_is_rejected(self):
        self.linked()
        (self.admin / "commondir").write_text(str(self.profile.parent) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "outside trusted profile"):
            self.resolve()

    def test_commondir_with_wrong_topology_is_rejected(self):
        self.linked()
        (self.admin / "commondir").write_bytes(b"..\n")
        with self.assertRaisesRegex(RuntimeError, "topology invalid"):
            self.resolve()

    def test_ordinary_directory_cannot_redirect_commondir(self):
        git_dir = self.root / ".git"
        git_dir.mkdir()
        (git_dir / "commondir").write_bytes(b"../other\n")
        with self.assertRaisesRegex(RuntimeError, "indirect commondir"):
            self.resolve()

    def test_symlink_in_gitdir_path_is_rejected_before_resolve(self):
        self.linked()
        alias = self.profile / "alias"
        try:
            alias.symlink_to(self.common.parent, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        (self.root / ".git").write_text(
            f"gitdir: {alias / '.git' / 'worktrees' / 'checkout'}\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "symlink/reparse"):
            self.resolve()

    def test_reparse_gitfile_admin_ancestor_and_backlink_are_rejected(self):
        self.linked()
        real_lstat = Path.lstat
        for unsafe in (self.root / ".git", self.common, self.admin / "gitdir"):
            with self.subTest(path=unsafe):
                def reparse(path, *args, **kwargs):
                    value = real_lstat(path, *args, **kwargs)
                    if path != unsafe:
                        return value
                    return SimpleNamespace(
                        st_file_attributes=0x400, st_mode=value.st_mode,
                        st_dev=value.st_dev, st_ino=value.st_ino, st_size=value.st_size,
                    )
                with mock.patch.object(Path, "lstat", reparse):
                    with self.assertRaisesRegex(RuntimeError, "symlink/reparse"):
                        self.resolve()


@unittest.skipUnless(shutil.which("git"), "Git executable required")
class SourceVerificationGitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.profile = Path(temporary.name).resolve()
        self.root = self.profile / "ordinary"
        self.root.mkdir()
        self.git = Path(shutil.which("git")).resolve()
        # Keep tests independent of owner/global/system Git configuration.
        self.env = {
            k: v for k, v in os.environ.items()
            if not k.upper().startswith("GIT_")
        }
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1")
        self.run_git("init")
        self.run_git("config", "core.autocrlf", "false")
        self.blobs = {}
        for relative in CLI.REVIEWED_CONTROLLER_SOURCE_PATHS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = f"# canonical fixture {relative}\n".encode()
            path.write_bytes(raw)
            self.blobs[relative] = CLI._git_blob_sha1(raw)
        self.run_git("add", ".")
        self.run_git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                     "commit", "-m", "canonical fixture")
        self.head = self.run_git("rev-parse", "HEAD").stdout.strip()
        self.commands = []

    def run_git(self, *args, cwd=None):
        return subprocess.run([str(self.git), *args], cwd=cwd or self.root,
                              env=self.env, text=True, capture_output=True, check=True)

    def linked(self):
        target = self.profile / "linked"
        self.run_git("worktree", "add", "--detach", str(target), self.head)
        self.root = target

    def verify(self, remote_sha=None, mutate=None):
        completed = CLI._completed

        def observe(*args, **kwargs):
            self.commands.append((args, kwargs))
            if "ls-remote" in args:
                return subprocess.CompletedProcess(args, 0,
                    (remote_sha or self.head) + "\trefs/heads/main\n", "")
            result = completed(*args, **kwargs)
            if mutate is not None and "ls-tree" in args:
                mutate()
            return result

        with contextlib.ExitStack() as stack:
            for name, value in (
                ("_controller_repo_root", self.root),
                ("_trusted_user_profile_directory", self.profile),
                ("_trusted_git_path", self.git),
                ("_trusted_git_environment", self.env),
                ("_trusted_system_directory", self.profile),
            ):
                stack.enter_context(mock.patch.object(CLI, name, return_value=value))
            stack.enter_context(mock.patch.object(CLI, "_completed", side_effect=observe))
            return CLI._require_controller_source_exact()

    def test_real_ordinary_and_linked_source_verification(self):
        for linked in (False, True):
            with self.subTest(linked=linked):
                if linked:
                    self.linked()
                self.commands = []
                self.assertEqual(self.verify(), (self.head, self.root, self.blobs))
                for args, kwargs in self.commands:
                    self.assertEqual(args[0], str(self.git))
                    self.assertEqual(kwargs["env"], self.env)
                    self.assertIn("--no-replace-objects", args)
                    if "hash-object" in args:
                        self.assertIn("--no-filters", args)
                    if "status" in args:
                        self.assertIn("core.fsmonitor=false", args)
                        self.assertIn(f"--work-tree={self.root}", args)

    def test_linked_dirty_tree_and_remote_head_drift_still_block(self):
        self.linked()
        with self.assertRaisesRegex(RuntimeError, "not current canonical main"):
            self.verify(remote_sha="0" * 40)
        (self.root / "untracked").write_bytes(b"dirty")
        with self.assertRaisesRegex(RuntimeError, "not clean"):
            self.verify()

    def test_config_cannot_redirect_worktree_or_hide_changed_source(self):
        self.linked()
        other = self.profile / "ordinary"
        self.run_git("config", "core.worktree", str(other))
        # Even a clean-looking index (assume-unchanged) cannot confer source
        # authority; exact remote-main tree blobs still own that authority.
        relative = CLI.REVIEWED_CONTROLLER_SOURCE_PATHS[0]
        self.run_git("update-index", "--assume-unchanged", relative)
        (self.root / relative).write_bytes(b"# changed source\n")
        with self.assertRaisesRegex(RuntimeError, "differs from canonical main"):
            self.verify()

    def test_linked_crlf_materialization_still_requires_canonical_blob(self):
        self.linked()
        for relative in CLI.REVIEWED_CONTROLLER_SOURCE_PATHS:
            path = self.root / relative
            self.run_git("update-index", "--assume-unchanged", relative)
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        self.assertEqual(self.verify(), (self.head, self.root, self.blobs))
        (self.root / CLI.REVIEWED_CONTROLLER_SOURCE_PATHS[0]).write_bytes(b"# changed\r\n")
        with self.assertRaisesRegex(RuntimeError, "differs from canonical main"):
            self.verify()

    def test_gitfile_substitution_during_source_reads_is_rejected(self):
        self.linked()
        path = self.root / ".git"
        raw = path.read_bytes()
        # Same target, different pointer bytes: even benign drift invalidates
        # the metadata snapshot used for the verification.
        def mutate():
            # Git for Windows hides gitfiles. Open the existing file rather
            # than using CREATE_ALWAYS, which rejects hidden files there.
            with path.open("r+b") as handle:
                handle.write(raw.rstrip(b"\r\n") + b"\r\n")
                handle.truncate()
        with self.assertRaisesRegex(RuntimeError, "metadata drift"):
            self.verify(mutate=mutate)


if __name__ == "__main__":
    unittest.main()
