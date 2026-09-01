from __future__ import annotations

import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_jules_e2e_smoke_retry_145 as retry


class JulesE2ESmokeRetry145Tests(unittest.TestCase):
    def _first_state(self) -> dict[str, object]:
        return {
            "expected_start_sha": retry.EXPECTED_FIRST_START_SHA,
            "result": {
                "status": "BLOCKED",
                "reason": retry.EXPECTED_FIRST_REASON,
                "provider_operation_id": retry.EXPECTED_FIRST_SESSION_ID,
                "publication": {
                    "status": "BLOCKED",
                    "reason": retry.EXPECTED_FIRST_REASON,
                    "branch": None,
                    "commit_sha": None,
                    "pr_number": None,
                },
            },
        }

    def _write(self, root: Path, payload: dict[str, object]) -> Path:
        path = root / ".jules_e2e_smoke_state.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_retry_is_bound_to_exact_first_failed_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self._write(root, self._first_state())
            loaded = retry._validate_first_run_state(path)
            self.assertEqual(retry.EXPECTED_FIRST_START_SHA, loaded["expected_start_sha"])

            for field, bad_value, reason in (
                ("expected_start_sha", "0" * 40, "FIRST_RUN_START_SHA_MISMATCH"),
            ):
                bad = self._first_state()
                bad[field] = bad_value
                bad_path = self._write(root, bad)
                with self.assertRaisesRegex(RuntimeError, reason):
                    retry._validate_first_run_state(bad_path)

            bad = self._first_state()
            bad["result"]["provider_operation_id"] = "replacement-session"  # type: ignore[index]
            with self.assertRaisesRegex(RuntimeError, "FIRST_RUN_SESSION_MISMATCH"):
                retry._validate_first_run_state(self._write(root, bad))

            bad = self._first_state()
            bad["result"]["publication"]["pr_number"] = 999  # type: ignore[index]
            with self.assertRaisesRegex(RuntimeError, "FIRST_RUN_UNEXPECTED_GITHUB_MUTATION"):
                retry._validate_first_run_state(self._write(root, bad))

    def test_retry_requires_durable_first_run_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.json"
            with self.assertRaisesRegex(RuntimeError, "AUTHORIZED_RETRY_REQUIRES_FIRST_RUN_STATE"):
                retry._validate_first_run_state(missing)

    def test_retry_surface_has_no_generic_retry_or_state_path_parameter(self) -> None:
        self.assertEqual({}, dict(inspect.signature(retry.main).parameters))
        self.assertEqual(Path(".jules_e2e_smoke_state.json"), retry.FIRST_STATE_FILE)
        self.assertEqual(Path(".jules_e2e_smoke_retry_145_state.json"), retry.RETRY_STATE_FILE)
        source = inspect.getsource(retry)
        self.assertNotIn("argparse", source)
        self.assertNotIn("--retry", source)
        self.assertNotIn("--state", source)

    def test_both_state_files_are_ignored(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".jules_e2e_smoke_state.json", ignore)
        self.assertIn(".jules_e2e_smoke_retry_145_state.json", ignore)


if __name__ == "__main__":
    unittest.main()
