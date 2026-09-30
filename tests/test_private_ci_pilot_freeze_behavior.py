import contextlib
import io
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPO_ROOT / "scripts" / "create_private_ci_pilot_freeze.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "create_private_ci_pilot_freeze_behavior_under_test",
        CLI_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CLI = _load_cli()


class LateCompetingPilotFreezeWriteTests(unittest.TestCase):
    def test_late_competing_freeze_write_blocks_and_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            freeze_path = Path(tmpdir) / CLI.PILOT_FREEZE_FILENAME
            competing_bytes = b'{"competing": "late_write_freeze_payload_bytes"}\n'

            # 1. Start with no output freeze present, so initial output.exists() guard passes.
            self.assertFalse(freeze_path.exists())

            controller_tree = r"C:\agent-controller"

            fake_freeze = CLI.build_fresh_pilot_identity_freeze(
                repository="test-owner/test-repo",
                pull_request_number=255,
                target_sha="a" * 40,
                workflow_sha="b" * 40,
                workflow_path=".github/workflows/ci.yml",
                nonce="1234567890abcdef",
                controller_main_sha="c" * 40,
                controller_tree=controller_tree,
            )

            # On non-Windows OS, Path(r"C:\...") treats backslash strings as relative paths
            # in the working directory because backslashes are not path separators on Unix.
            # Thus Path(fake_freeze.runner_root).parent resolves to Path(".") which exists.
            # We filter out checks for the runner directory so the test runs cross-platform.
            orig_exists = Path.exists

            def cross_platform_exists(path_obj):
                if path_obj == freeze_path:
                    return orig_exists(path_obj)
                if (
                    "ac-pilot-" in str(path_obj)
                    or "ProgramData" in str(path_obj)
                    or str(path_obj) == "."
                ):
                    return False
                return orig_exists(path_obj)

            def late_competing_write_hook(*args, **kwargs):
                # 2. Create a competing freeze file during a late readback / final serialization-write boundary
                freeze_path.write_bytes(competing_bytes)

            patches = {
                "authoritative_path": mock.Mock(return_value=freeze_path),
                "_require_controller_main_exact": mock.Mock(
                    return_value=("c" * 40, controller_tree)
                ),
                "_local_zero_residual": mock.Mock(return_value=None),
                "_require_target_exact": mock.Mock(
                    return_value=("a" * 40, "b" * 40)
                ),
                "_require_workflow_runner_exclusivity": mock.Mock(return_value=None),
                "build_fresh_pilot_identity_freeze": mock.Mock(
                    return_value=fake_freeze
                ),
                "_require_no_pilot_runner": mock.Mock(
                    side_effect=late_competing_write_hook
                ),
            }

            cli_args = [
                str(CLI_PATH),
                "--repository",
                "test-owner/test-repo",
                "--pull-request-number",
                "255",
                "--workflow-path",
                ".github/workflows/ci.yml",
            ]

            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.ExitStack() as stack:
                for name, value in patches.items():
                    stack.enter_context(mock.patch.object(CLI, name, value))
                stack.enter_context(
                    mock.patch.object(Path, "exists", cross_platform_exists)
                )
                stack.enter_context(mock.patch.object(sys, "argv", cli_args))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))

                # 3. Continue through real production _write_exclusive() implementation
                returncode = CLI.main()

            out = stdout.getvalue()
            err = stderr.getvalue()

            # 4. Assert main() returns blocked/nonzero (expected 2)
            self.assertEqual(returncode, 2)
            self.assertIn("BLOCKED:", err)

            # 5. Assert that competing file's original bytes are preserved exactly
            self.assertTrue(freeze_path.exists())
            self.assertEqual(freeze_path.read_bytes(), competing_bytes)

            # 6. Assert that PILOT_IDENTITY_FREEZE_CREATED is not emitted
            self.assertNotIn("PILOT_IDENTITY_FREEZE_CREATED", out)


if __name__ == "__main__":
    unittest.main()
