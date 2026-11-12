import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from agent_controller.private_ci_live_registration import frozen_live_registration_binding
from agent_controller.private_ci_live_registration_runtime import (
    WindowsEphemeralRegistrationRuntime,
)


DUMMY_TOKEN = "dummy-registration-token-not-a-secret"


@unittest.skipUnless(os.name == "nt", "Windows cmd.exe launch regression")
class WindowsRegistrationCmdLaunchRegressionTests(unittest.TestCase):
    def test_config_cmd_resolves_with_no_default_current_directory_in_exe_path(self):
        # Issue #320: with NoDefaultCurrentDirectoryInExePath set, cmd.exe does
        # not search the current directory for a bare "config.cmd".
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = replace(
                frozen_live_registration_binding(),
                runner_root=str(Path(temporary_directory) / "generation" / "runner"),
            )
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / "config.cmd").write_bytes(
                b"@echo off\r\necho ISSUE320_CONFIG_CMD_REACHED %1\r\nexit /b 0\r\n"
            )
            runtime = WindowsEphemeralRegistrationRuntime(binding)

            with mock.patch.dict(
                os.environ,
                {"NoDefaultCurrentDirectoryInExePath": "1"},
            ):
                execution = runtime.run_registration(binding, DUMMY_TOKEN)

        self.assertEqual(execution.exit_code, 0, execution.stderr)
        self.assertNotIn("is not recognized", execution.stderr)
        self.assertIn("ISSUE320_CONFIG_CMD_REACHED --unattended", execution.stdout)


if __name__ == "__main__":
    unittest.main()
