import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


class PrivateCiBurnedEvidenceArchiveTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_burned_evidence_archive
        return private_ci_burned_evidence_archive

    def make_root(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name) / "agent-controller-handoff"
        root.mkdir()
        return tmp, root

    def write(self, root: Path, name: str, data: bytes) -> Path:
        path = root / name
        path.write_bytes(data)
        return path

    def test_allowlist_is_exact_and_excludes_authority_files(self):
        m = self.module()
        expected = (
            "issue216-pilot-identity-freeze.json",
            "issue216-phase0-canonical.json",
            "issue217-live-registration-candidate.ps1",
            "issue217-live-registration-plan.json",
            "issue217-live-registration-result.json",
            "issue217-live-registration.log",
            "issue225-registration-handoff.pending.json",
            "issue225-registration-handoff.json",
            "issue225-phase4-target-environment-candidate.ps1",
            "issue225-phase4-plan.json",
            "issue225-phase4-result.json",
            "issue225-phase4-target-environment.log",
            "issue225-phase5-candidate.ps1",
            "issue225-phase5-plan.json",
            "issue225-phase5-result.json",
            "issue225-phase5-exactly-one-job.log",
        )
        self.assertEqual(m.CANONICAL_RESTART_BLOCKING_FILENAMES, expected)
        joined = "\n".join(expected)
        self.assertNotIn("approval", joined)
        self.assertNotIn("consumed", joined)

    def test_empty_inventory_returns_no_plan(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        self.assertIsNone(plan)

    def test_plan_ignores_approval_and_unknown_files(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        self.write(root, "issue216-phase0-canonical.json", b"phase0\n")
        self.write(
            root,
            "issue216-live-registration-approval-" + "1" * 64 + ".json",
            b"approval\n",
        )
        self.write(root, "unrelated.txt", b"keep\n")

        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        self.assertIsNotNone(plan)
        self.assertEqual(
            tuple(item.filename for item in plan.items),
            ("issue216-phase0-canonical.json",),
        )

    def test_plan_is_canonical_and_archive_directory_is_inventory_bound(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        self.write(root, "issue216-phase0-canonical.json", b"phase0\n")
        self.write(root, "issue217-live-registration-plan.json", b"plan\n")

        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        raw = m.archive_plan_bytes(plan)
        parsed = m.parse_archive_plan_bytes(raw)
        self.assertEqual(parsed, plan)
        self.assertTrue(
            plan.archive_directory.startswith("archive/issue216-burned-")
        )
        self.assertEqual(
            plan.archive_directory,
            "archive/issue216-burned-" + plan.inventory_sha256[:16],
        )
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            m.archive_plan_sha256(plan),
        )

    def test_plan_rejects_symlink_or_reparse_source(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        target = self.write(root, "real.json", b"x")
        link = root / "issue216-phase0-canonical.json"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(ValueError, "reparse|symlink"):
            m.build_archive_plan(
                evidence_root=root,
                controller_main_sha="a" * 40,
                controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
                python_executable=r"C:\Python312\python.exe",
                python_sha256="b" * 64,
            )


    def test_existing_archive_directory_blocks_replanning(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        self.write(root, "issue216-phase0-canonical.json", b"phase0\n")
        first = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        archive_path = root.joinpath(
            *Path(first.archive_directory).parts
        )
        archive_path.mkdir(parents=True)

        with self.assertRaisesRegex(RuntimeError, "manual recovery"):
            m.build_archive_plan(
                evidence_root=root,
                controller_main_sha="a" * 40,
                controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
                python_executable=r"C:\Python312\python.exe",
                python_sha256="b" * 64,
            )


    def test_incomplete_prior_helper_archive_blocks_even_when_sources_are_empty(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        residue = root / "archive" / "issue216-burned-" + "1" * 16
        residue.mkdir(parents=True)
        (residue / "manifest.json").write_bytes(b"{}\n")

        with self.assertRaisesRegex(RuntimeError, "manual recovery"):
            m.build_archive_plan(
                evidence_root=root,
                controller_main_sha="a" * 40,
                controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
                python_executable=r"C:\Python312\python.exe",
                python_sha256="b" * 64,
            )

    def test_partial_prior_retirement_residue_blocks_new_inventory_plan(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        first = self.write(
            root, "issue216-phase0-canonical.json", b"phase0\n"
        )
        self.write(
            root, "issue217-live-registration-plan.json", b"plan\n"
        )
        original = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        residue = root.joinpath(*Path(original.archive_directory).parts)
        residue.mkdir(parents=True)
        (residue / "manifest.json").write_bytes(b"{}\n")
        first.unlink()

        with self.assertRaisesRegex(RuntimeError, "manual recovery"):
            m.build_archive_plan(
                evidence_root=root,
                controller_main_sha="a" * 40,
                controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
                python_executable=r"C:\Python312\python.exe",
                python_sha256="b" * 64,
            )

    def test_python_interpreter_binding_is_canonical_plan_authority(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        self.write(root, "issue216-phase0-canonical.json", b"phase0\n")
        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        raw = m.archive_plan_bytes(plan)
        self.assertIn(b'"python_executable":"C:\\\\Python312\\\\python.exe"', raw)
        self.assertIn(b'"python_sha256":"' + b"b" * 64 + b'"', raw)

        with self.assertRaisesRegex(ValueError, "absolute exe"):
            m.build_archive_plan(
                evidence_root=root,
                controller_main_sha="a" * 40,
                controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
                python_executable="python.exe",
                python_sha256="b" * 64,
            )

    def test_hash_drift_blocks_before_archive_creation(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        source = self.write(
            root, "issue216-phase0-canonical.json", b"phase0-v1\n"
        )
        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        digest = m.archive_plan_sha256(plan)
        source.write_bytes(b"phase0-drift\n")

        with self.assertRaisesRegex(RuntimeError, "drift"):
            m.apply_archive_plan(
                evidence_root=root,
                plan=plan,
                expected_plan_sha256=digest,
                completed_at=datetime(2026, 9, 20, 23, 0, tzinfo=timezone.utc),
            )
        self.assertFalse((root / plan.archive_directory).exists())
        self.assertTrue(source.exists())

    def test_copy_failure_never_deletes_sources(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        first = self.write(
            root, "issue216-phase0-canonical.json", b"phase0\n"
        )
        second = self.write(
            root, "issue217-live-registration-plan.json", b"plan\n"
        )
        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        digest = m.archive_plan_sha256(plan)

        calls = 0
        real_copy = m._copy_source_file

        def fail_second(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic copy failure")
            return real_copy(source, destination)

        with mock.patch.object(m, "_copy_source_file", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "synthetic copy failure"):
                m.apply_archive_plan(
                    evidence_root=root,
                    plan=plan,
                    expected_plan_sha256=digest,
                    completed_at=datetime(
                        2026, 9, 20, 23, 1, tzinfo=timezone.utc
                    ),
                )
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_manifest_is_verified_before_any_source_delete(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        self.write(root, "issue216-phase0-canonical.json", b"phase0\n")
        self.write(root, "issue217-live-registration-plan.json", b"plan\n")
        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        digest = m.archive_plan_sha256(plan)

        events = []
        real_verify = m._verify_archive_manifest
        real_remove = m._remove_source_file

        def verify(*args, **kwargs):
            events.append("manifest_verified")
            return real_verify(*args, **kwargs)

        def remove(path):
            events.append("remove:" + path.name)
            return real_remove(path)

        with mock.patch.object(
            m, "_verify_archive_manifest", side_effect=verify
        ), mock.patch.object(m, "_remove_source_file", side_effect=remove):
            result = m.apply_archive_plan(
                evidence_root=root,
                plan=plan,
                expected_plan_sha256=digest,
                completed_at=datetime(
                    2026, 9, 20, 23, 2, tzinfo=timezone.utc
                ),
            )

        first_remove = next(
            index
            for index, event in enumerate(events)
            if event.startswith("remove:")
        )
        self.assertLess(events.index("manifest_verified"), first_remove)
        self.assertEqual(result.status, m.ARCHIVE_RETIREMENT_PASS)

    def test_success_preserves_exact_archive_and_clears_only_planned_sources(self):
        m = self.module()
        tmp, root = self.make_root()
        self.addCleanup(tmp.cleanup)
        source_data = {
            "issue216-phase0-canonical.json": b"phase0\n",
            "issue217-live-registration-plan.json": b"plan\n",
        }
        for name, data in source_data.items():
            self.write(root, name, data)
        approval = self.write(
            root,
            "issue216-live-registration-approval-" + "2" * 64 + ".json",
            b"approval\n",
        )
        unrelated = self.write(root, "unrelated.txt", b"keep\n")

        plan = m.build_archive_plan(
            evidence_root=root,
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-216",
            python_executable=r"C:\Python312\python.exe",
            python_sha256="b" * 64,
        )
        result = m.apply_archive_plan(
            evidence_root=root,
            plan=plan,
            expected_plan_sha256=m.archive_plan_sha256(plan),
            completed_at=datetime(2026, 9, 20, 23, 3, tzinfo=timezone.utc),
        )
        archive = root / plan.archive_directory
        for name, data in source_data.items():
            self.assertFalse((root / name).exists())
            self.assertEqual((archive / name).read_bytes(), data)
        self.assertTrue(approval.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue((archive / "manifest.json").is_file())
        self.assertTrue((archive / "retirement-complete.json").is_file())
        self.assertEqual(result.status, m.ARCHIVE_RETIREMENT_PASS)


if __name__ == "__main__":
    unittest.main()
