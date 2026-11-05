"""Fixture-only tests for #316 deferred Phase0 commit; no target logon."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from agent_controller.private_ci_phase0_deferred import deferred_phase0_commit
from agent_controller.private_ci_phase0_collector import collect_validated_phase0_evidence
from agent_controller.private_ci_pilot_identity import pilot_identity_freeze_bytes
from scripts.collect_private_ci_phase0 import _write_exclusive
from tests.test_private_ci_phase0_collector import FakeRunner, valid_freeze


class DeferredPhase0Tests(unittest.TestCase):
    def test_commit_only_after_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            freeze = valid_freeze()
            raw = pilot_identity_freeze_bytes(freeze)
            path = root / "freeze.json"
            path.write_bytes(raw)
            output = root / "canonical.json"
            events = []
            def collect(value):
                events.append("collect")
                self.assertFalse(output.exists())
                return collect_validated_phase0_evidence(
                    Path(value.controller_tree), pilot_freeze=value,
                    command_runner=FakeRunner(), path_exists=lambda _: False,
                )
            def release():
                events.append("release")
                self.assertFalse(output.exists())
                return True
            def write(p, b):
                events.append("commit")
                _write_exclusive(p, b)
            result = deferred_phase0_commit(
                freeze_path=path, expected_freeze_sha256=hashlib.sha256(raw).hexdigest(),
                output=output, collect=collect, release_and_verify=release,
                exclusive_write=write,
            )
            self.assertEqual(events, ["collect", "release", "commit"])
            self.assertEqual(result.sha256, hashlib.sha256(output.read_bytes()).hexdigest())
            with self.assertRaisesRegex(RuntimeError, "occupied"):
                deferred_phase0_commit(
                    freeze_path=path, expected_freeze_sha256=hashlib.sha256(raw).hexdigest(),
                    output=output, collect=collect, release_and_verify=release,
                    exclusive_write=write,
                )

    def test_failure_never_commits(self):
        for mode in ("collect", "restore", "freeze", "drift"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                freeze = valid_freeze()
                raw = pilot_identity_freeze_bytes(freeze)
                path = root / "freeze.json"
                path.write_bytes(raw)
                output = root / "canonical.json"
                events = []
                def collect(value):
                    events.append("collect")
                    if mode == "collect":
                        raise RuntimeError("policy unreadable")
                    if mode == "drift":
                        path.write_bytes(b"changed")
                    return collect_validated_phase0_evidence(
                        Path(value.controller_tree), pilot_freeze=value,
                        command_runner=FakeRunner(), path_exists=lambda _: False,
                    )
                def release():
                    events.append("release")
                    return mode != "restore"
                with self.assertRaises(Exception):
                    deferred_phase0_commit(
                        freeze_path=path,
                        expected_freeze_sha256=("0" * 64 if mode == "freeze" else hashlib.sha256(raw).hexdigest()),
                        output=output, collect=collect, release_and_verify=release,
                        exclusive_write=_write_exclusive,
                    )
                self.assertFalse(output.exists())
                self.assertEqual(events, [] if mode == "freeze" else ["collect", "release"])


if __name__ == "__main__":
    unittest.main()
