import hashlib
import json
import tempfile
import unittest
from pathlib import Path


class PrivateCiRunnerTreeSnapshotRedTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_runner_tree_snapshot
        return private_ci_runner_tree_snapshot

    def make_generation(self, root: Path):
        generation = root / "ac-pilot-0123456789abcdef"
        runner = generation / "runner"
        (runner / "bin").mkdir(parents=True)
        (runner / "externals").mkdir()
        (runner / "config.cmd").write_bytes(b"config\r\n")
        (runner / "run.cmd").write_bytes(b"run\r\n")
        (runner / "bin" / "Runner.Listener.exe").write_bytes(b"listener")
        (runner / ".runner").write_text(
            '{"agentId":23,"agentName":"ac-ci-0123456789abcdef"}',
            encoding="utf-8",
        )
        (runner / ".credentials").write_bytes(b"runner-runtime-state")
        return generation, runner

    def test_snapshot_is_canonical_and_stable(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            generation, runner = self.make_generation(Path(tmp))
            raw = m.runner_generation_snapshot_bytes(
                generation_root=generation,
                runner_root=runner,
                work_folder="_work",
            )
            self.assertEqual(
                m.runner_generation_snapshot_sha256(
                    generation_root=generation,
                    runner_root=runner,
                    work_folder="_work",
                ),
                hashlib.sha256(raw).hexdigest(),
            )
            parsed = m.parse_runner_generation_snapshot_bytes(raw)
            self.assertEqual(
                parsed["schema"],
                m.RUNNER_GENERATION_SNAPSHOT_SCHEMA,
            )
            self.assertEqual(parsed["work_folder"], "_work")
            self.assertTrue(
                any(
                    entry["path"] == "runner/config.cmd"
                    and entry["kind"] == "file"
                    for entry in parsed["entries"]
                )
            )



    def test_parser_rejects_traversal_case_collision_and_work_folder(self):
        m = self.module()

        def raw(entries, work_folder="_work"):
            payload = {
                "schema": m.RUNNER_GENERATION_SNAPSHOT_SCHEMA,
                "runner_directory": "runner",
                "work_folder": work_folder,
                "entries": entries,
            }
            return (
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("utf-8")

        base_root = {"kind": "directory", "path": "runner"}
        bad_cases = (
            [
                base_root,
                {
                    "kind": "file",
                    "path": "runner/../escape",
                    "sha256": "1" * 64,
                    "size": 1,
                },
            ],
            [
                base_root,
                {"kind": "directory", "path": "runner/Bin"},
                {"kind": "directory", "path": "runner/bin"},
            ],
            [
                base_root,
                {"kind": "directory", "path": "runner/_work"},
            ],
        )
        for entries in bad_cases:
            with self.subTest(entries=entries):
                with self.assertRaises(ValueError):
                    m.parse_runner_generation_snapshot_bytes(raw(entries))

    def test_parser_rejects_unsorted_entries(self):
        m = self.module()
        payload = {
            "schema": m.RUNNER_GENERATION_SNAPSHOT_SCHEMA,
            "runner_directory": "runner",
            "work_folder": "_work",
            "entries": [
                {"kind": "directory", "path": "runner/z"},
                {"kind": "directory", "path": "runner"},
            ],
        }
        raw = (
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "sorted"):
            m.parse_runner_generation_snapshot_bytes(raw)

    def test_file_content_or_added_sibling_changes_digest(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            generation, runner = self.make_generation(Path(tmp))
            original = m.runner_generation_snapshot_sha256(
                generation_root=generation,
                runner_root=runner,
                work_folder="_work",
            )
            (runner / "run.cmd").write_bytes(b"changed")
            changed = m.runner_generation_snapshot_sha256(
                generation_root=generation,
                runner_root=runner,
                work_folder="_work",
            )
            self.assertNotEqual(original, changed)

            (generation / "cache").mkdir()
            with self.assertRaisesRegex(ValueError, "generation root"):
                m.runner_generation_snapshot_bytes(
                    generation_root=generation,
                    runner_root=runner,
                    work_folder="_work",
                )

    def test_prior_workspace_is_rejected(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            generation, runner = self.make_generation(Path(tmp))
            (runner / "_work").mkdir()
            with self.assertRaisesRegex(ValueError, "work folder"):
                m.runner_generation_snapshot_bytes(
                    generation_root=generation,
                    runner_root=runner,
                    work_folder="_work",
                )

    def test_symlink_or_reparse_shape_is_rejected(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            generation, runner = self.make_generation(Path(tmp))
            link = runner / "escape"
            try:
                link.symlink_to(Path(tmp))
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "reparse|symlink"):
                m.runner_generation_snapshot_bytes(
                    generation_root=generation,
                    runner_root=runner,
                    work_folder="_work",
                )


if __name__ == "__main__":
    unittest.main()
