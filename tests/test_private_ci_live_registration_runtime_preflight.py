import json
import tempfile
import unittest
from pathlib import Path

from agent_controller.private_ci_live_registration import frozen_live_registration_binding
from agent_controller.private_ci_live_registration_runtime import (
    WindowsEphemeralRegistrationRuntime,
)


class Completed:
    def __init__(self, *, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def binding_for(root):
    binding = frozen_live_registration_binding()
    return type(binding)(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        workflow_sha=binding.workflow_sha,
        runner_name=binding.runner_name,
        runner_label=binding.runner_label,
        environment_generation=binding.environment_generation,
        runner_root=str(Path(root) / "generation" / "runner"),
        work_folder=binding.work_folder,
    )


class MutationTimeLocalPreflightTests(unittest.TestCase):
    def _runtime(
        self,
        temporary_directory,
        *,
        host="WOBBUFFET",
        broker_identity="WOBBUFFET\\c-admin",
        target_admin=False,
        runner_process_count=0,
    ):
        binding = binding_for(temporary_directory)
        downloaded = []

        def command_runner(*command, **kwargs):
            if command == ("hostname.exe",):
                return Completed(stdout=host + "\n")
            if command == ("whoami.exe",):
                return Completed(stdout=broker_identity + "\n")
            if command[0] == "powershell.exe":
                payload = {
                    "target_identity_enabled": True,
                    "target_identity_admin": target_admin,
                    "runner_process_count": runner_process_count,
                    "runner_service_count": 0,
                    "runner_task_count": 0,
                }
                return Completed(stdout=json.dumps(payload))
            if command[0:2] == ("gh.exe", "api"):
                return Completed(stdout=json.dumps({"runners": []}))
            raise AssertionError(command)

        runtime = WindowsEphemeralRegistrationRuntime(
            binding,
            command_runner=command_runner,
            downloader=lambda url, path: downloaded.append((url, path)),
        )
        return binding, runtime, downloaded

    def test_wrong_host_with_same_broker_name_blocks_before_filesystem_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding, runtime, downloaded = self._runtime(
                temporary_directory,
                host="OTHERHOST",
                broker_identity="OTHERHOST\\c-admin",
            )
            with self.assertRaisesRegex(RuntimeError, "host mismatch"):
                runtime.prepare_runner(binding)
            self.assertEqual(downloaded, [])
            self.assertFalse(Path(binding.runner_root).parent.exists())

    def test_target_admin_drift_blocks_before_filesystem_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding, runtime, downloaded = self._runtime(
                temporary_directory,
                target_admin=True,
            )
            with self.assertRaisesRegex(RuntimeError, "target identity.*admin"):
                runtime.prepare_runner(binding)
            self.assertEqual(downloaded, [])
            self.assertFalse(Path(binding.runner_root).parent.exists())

    def test_runner_process_drift_blocks_before_filesystem_mutation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding, runtime, downloaded = self._runtime(
                temporary_directory,
                runner_process_count=1,
            )
            with self.assertRaisesRegex(RuntimeError, "runner process"):
                runtime.prepare_runner(binding)
            self.assertEqual(downloaded, [])
            self.assertFalse(Path(binding.runner_root).parent.exists())


if __name__ == "__main__":
    unittest.main()
