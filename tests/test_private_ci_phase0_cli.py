"""Phase 0 CLI behavior with fixture-only observations and temporary outputs."""
import contextlib
import hashlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_controller.private_ci_phase0_collector import collect_validated_phase0_evidence
from agent_controller.private_ci_phase0_evidence import validate_phase0_evidence_bytes
from agent_controller.private_ci_pilot_identity import pilot_identity_freeze_bytes
from tests.test_private_ci_phase0_collector import FakeRunner, valid_freeze


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_private_ci_phase0.py"
SPEC = importlib.util.spec_from_file_location("phase0_cli_under_test", SCRIPT)
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


class Phase0CliTests(unittest.TestCase):
    def run_cli(self, directory, *, changes=None, expected_digest=None, runner=None):
        root = Path(directory)
        freeze = valid_freeze()
        raw = pilot_identity_freeze_bytes(freeze)
        (root / CLI.PILOT_FREEZE_FILENAME).write_bytes(raw)
        digest = expected_digest or hashlib.sha256(raw).hexdigest()

        def collect(tree, *, pilot_freeze):
            return collect_validated_phase0_evidence(
                tree, pilot_freeze=pilot_freeze,
                command_runner=runner or FakeRunner(policy_changes=changes),
                path_exists=lambda path: False,
            )

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(CLI, "authoritative_path", side_effect=lambda filename: root / filename),
            mock.patch.object(CLI, "_controller_repo_root", return_value=Path(freeze.controller_tree)),
            mock.patch.object(CLI, "collect_validated_phase0_evidence", side_effect=collect) as collector,
            mock.patch.object(sys, "argv", [str(SCRIPT), "--expected-freeze-sha256", digest]),
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr),
        ):
            result = CLI.main()
        return result, stdout.getvalue(), stderr.getvalue(), collector

    def test_only_policy_bound_v3_pass_is_written_exclusively(self):
        with tempfile.TemporaryDirectory() as directory:
            result, stdout, stderr, _ = self.run_cli(directory)
            self.assertEqual(result, 0, stderr)
            output = Path(directory) / CLI.PHASE0_FILENAME
            raw = output.read_bytes()
            evidence = validate_phase0_evidence_bytes(raw)
            self.assertTrue(evidence.schema.endswith(".v3"))
            self.assertEqual(evidence.target_user_policy, "Undefined")
            self.assertIn("PHASE0_PASS", stdout)
            result, stdout, stderr, collector = self.run_cli(directory)
            self.assertEqual(result, 2)
            self.assertIn("do not overwrite", stderr)
            self.assertEqual(stdout, "")
            collector.assert_not_called()
            self.assertEqual(output.read_bytes(), raw)
            with self.assertRaises(FileExistsError):
                CLI._write_exclusive(output, b"replacement")
            self.assertEqual(output.read_bytes(), raw)

    def test_unknown_or_incompatible_policy_never_writes_canonical_pass(self):
        for changes in (
            {"machine_policy": "Restricted"}, {"target_user_policy": "AllSigned"},
            {"target_user_policy": None}, {"machine_policy": None},
            {"execution_policy_target_identity": "c-admin"},
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                result, stdout, stderr, _ = self.run_cli(directory, changes=changes)
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertIn("BLOCKED", stderr)
                self.assertFalse((Path(directory) / CLI.PHASE0_FILENAME).exists())

    def test_freeze_digest_mismatch_blocks_before_probe_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            result, stdout, stderr, collector = self.run_cli(directory, expected_digest="f" * 64)
            self.assertEqual(result, 2)
            self.assertEqual(stdout, "")
            self.assertIn("freeze SHA-256 mismatch", stderr)
            collector.assert_not_called()
            self.assertFalse((Path(directory) / CLI.PHASE0_FILENAME).exists())


if __name__ == "__main__":
    unittest.main()
