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


def runner(runner_id, *, name=None, labels=()):
    return {
        "id": runner_id,
        "name": name or f"runner-{runner_id}",
        "status": "offline",
        "busy": False,
        "labels": [{"name": label} for label in labels],
    }


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
                return Completed(
                    stdout=json.dumps({"total_count": 0, "runners": []})
                )
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

    def test_later_page_pilot_runner_blocks_before_filesystem_or_download(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = binding_for(temporary_directory)
            downloaded = []
            endpoints = []

            def command_runner(*command, **kwargs):
                if command == ("hostname.exe",):
                    return Completed(stdout="WOBBUFFET\n")
                if command == ("whoami.exe",):
                    return Completed(stdout="WOBBUFFET\\c-admin\n")
                if command[0] == "powershell.exe":
                    return Completed(
                        stdout=json.dumps(
                            {
                                "target_identity_enabled": True,
                                "target_identity_admin": False,
                                "runner_process_count": 0,
                                "runner_service_count": 0,
                                "runner_task_count": 0,
                            }
                        )
                    )
                if command[0:2] == ("gh.exe", "api"):
                    endpoint = command[2]
                    endpoints.append(endpoint)
                    if "page=2" in endpoint:
                        payload = {
                            "total_count": 101,
                            "runners": [
                                runner(
                                    101,
                                    name=binding.runner_name,
                                    labels=(binding.runner_label,),
                                )
                            ],
                        }
                    else:
                        payload = {
                            "total_count": 101,
                            "runners": [runner(index) for index in range(1, 101)],
                        }
                    return Completed(stdout=json.dumps(payload))
                raise AssertionError(command)

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                downloader=lambda url, path: downloaded.append((url, path)),
            )

            with self.assertRaisesRegex(RuntimeError, "stale eligible runner"):
                runtime.prepare_runner(binding)

            self.assertEqual(downloaded, [])
            self.assertFalse(Path(binding.runner_root).parent.exists())
            self.assertEqual(len(endpoints), 4)
            self.assertNotIn("page=2", endpoints[0])
            self.assertIn("page=2", endpoints[1])
            self.assertNotIn("page=2", endpoints[2])
            self.assertIn("page=2", endpoints[3])


if __name__ == "__main__":
    unittest.main()
