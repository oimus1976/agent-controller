import importlib.util
import inspect
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_private_ci_live_registration.py"
SPEC = importlib.util.spec_from_file_location("run_private_ci_live_registration_apply_lock", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ApplyOwnershipTests(unittest.TestCase):
    def test_only_first_process_can_claim_apply_ownership(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            marker = Path(temporary_directory) / "apply.consumed.json"
            with mock.patch.object(MODULE, "_consumed_marker_path", return_value=marker):
                MODULE._acquire_apply_ownership("a" * 64, "b" * 64)
                original = marker.read_bytes()
                with self.assertRaisesRegex(RuntimeError, "apply ownership already claimed"):
                    MODULE._acquire_apply_ownership("a" * 64, "b" * 64)
                self.assertEqual(marker.read_bytes(), original)

    def test_host_revalidation_precedes_apply_ownership_and_live_execution(self):
        source = inspect.getsource(MODULE.command_apply)
        host_index = source.index("_require_exact_phase0_host(")
        claim_index = source.index("_acquire_apply_ownership(")
        execute_index = source.index("execute_live_registration(")
        self.assertLess(host_index, claim_index)
        self.assertLess(claim_index, execute_index)
        self.assertNotIn("prepare_with_durable_consumption", source)


if __name__ == "__main__":
    unittest.main()
