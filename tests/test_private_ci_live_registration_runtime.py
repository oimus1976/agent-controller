import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest import mock

from agent_controller.private_ci_live_registration import (
    REGISTRATION_TOKEN_ENVIRONMENT_NAME,
    frozen_live_registration_binding,
)
from agent_controller.private_ci_live_registration_runtime import (
    WindowsEphemeralRegistrationRuntime,
)


TOKEN = "one-time-registration-secret"


def completed(command, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def safe_local_probe():
    return json.dumps(
        {
            "target_identity_enabled": True,
            "target_identity_admin": False,
            "runner_process_count": 0,
            "runner_service_count": 0,
            "runner_task_count": 0,
        }
    )


def make_runner_zip_bytes(*, traversal=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        if traversal:
            archive.writestr("../escape.txt", "bad")
        else:
            archive.writestr("config.cmd", "@echo off\r\n")
            archive.writestr("run.cmd", "@echo off\r\n")
            archive.writestr("bin/Runner.Listener.exe", b"runner")
    return stream.getvalue()


class PrivateCiLiveRegistrationRuntimeTests(unittest.TestCase):
    def binding_for(self, root):
        return replace(
            frozen_live_registration_binding(),
            runner_root=str(Path(root) / "generation" / "runner"),
        )

    def test_prepare_runner_uses_fresh_root_pinned_package_and_zero_eligible_precheck(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            package_bytes = make_runner_zip_bytes()
            package_sha = hashlib.sha256(package_bytes).hexdigest()
            calls = []

            def command_runner(*command, **kwargs):
                calls.append((command, kwargs))
                if command == ("hostname.exe",):
                    return completed(command, stdout="WOBBUFFET\n")
                if command == ("whoami.exe",):
                    return completed(command, stdout="WOBBUFFET\\c-admin\n")
                if command[0] == "powershell.exe":
                    return completed(command, stdout=safe_local_probe())
                if command[0:2] == ("gh.exe", "api"):
                    return completed(
                        command,
                        stdout=json.dumps({"total_count": 0, "runners": []}),
                    )
                raise AssertionError(command)

            def downloader(url, destination):
                calls.append((("DOWNLOAD", url), {"destination": str(destination)}))
                destination.write_bytes(package_bytes)

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                downloader=downloader,
            )
            with mock.patch(
                "agent_controller.private_ci_live_registration_runtime.RUNNER_PACKAGE_SHA256",
                package_sha,
            ):
                runtime.prepare_runner(binding)

            root = Path(binding.runner_root)
            self.assertTrue((root / "config.cmd").is_file())
            self.assertTrue((root / "run.cmd").is_file())
            self.assertTrue((root / "bin" / "Runner.Listener.exe").is_file())
            self.assertFalse((root / ".runner").exists())
            self.assertFalse((root / "_work").exists())
            self.assertTrue(any(call[0][0] == "DOWNLOAD" for call in calls))

    def test_prepare_runner_blocks_stale_eligible_runner_before_download(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            downloaded = []

            def command_runner(*command, **kwargs):
                if command == ("hostname.exe",):
                    return completed(command, stdout="WOBBUFFET\n")
                if command == ("whoami.exe",):
                    return completed(command, stdout="WOBBUFFET\\c-admin\n")
                if command[0] == "powershell.exe":
                    return completed(command, stdout=safe_local_probe())
                if command[0:2] == ("gh.exe", "api"):
                    return completed(
                        command,
                        stdout=json.dumps(
                            {
                                "total_count": 1,
                                "runners": [
                                    {
                                        "id": 1,
                                        "name": "stale",
                                        "status": "offline",
                                        "busy": False,
                                        "labels": [{"name": binding.runner_label}],
                                    }
                                ],
                            }
                        ),
                    )
                raise AssertionError(command)

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                downloader=lambda url, path: downloaded.append(True),
            )
            with self.assertRaisesRegex(RuntimeError, "stale eligible runner"):
                runtime.prepare_runner(binding)
            self.assertEqual(downloaded, [])
            self.assertFalse(Path(binding.runner_root).exists())

    def test_prepare_runner_blocks_same_name_without_label_before_download(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            downloaded = []

            def command_runner(*command, **kwargs):
                if command == ("hostname.exe",):
                    return completed(command, stdout="WOBBUFFET\n")
                if command == ("whoami.exe",):
                    return completed(command, stdout="WOBBUFFET\\c-admin\n")
                if command[0] == "powershell.exe":
                    return completed(command, stdout=safe_local_probe())
                if command[0:2] == ("gh.exe", "api"):
                    return completed(
                        command,
                        stdout=json.dumps(
                            {
                                "total_count": 1,
                                "runners": [
                                    {
                                        "id": 2,
                                        "name": binding.runner_name,
                                        "status": "offline",
                                        "busy": False,
                                        "labels": [],
                                    }
                                ],
                            }
                        ),
                    )
                raise AssertionError(command)

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                downloader=lambda url, path: downloaded.append(True),
            )
            with self.assertRaisesRegex(RuntimeError, "stale eligible runner"):
                runtime.prepare_runner(binding)
            self.assertEqual(downloaded, [])
            self.assertFalse(Path(binding.runner_root).parent.exists())

    def test_registration_token_uses_fixed_repository_endpoint_and_never_enters_argv(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / "config.cmd").write_text("@echo off\n", encoding="utf-8")
            seen = []

            def command_runner(*command, **kwargs):
                seen.append((command, kwargs))
                if command[0:4] == (
                    "gh.exe",
                    "api",
                    "--method",
                    "POST",
                ):
                    return completed(command, stdout=json.dumps({"token": TOKEN}))
                if command[0:2] == ("gh.exe", "api"):
                    return completed(
                        command,
                        stdout=json.dumps({"total_count": 0, "runners": []}),
                    )
                if command[0] == "cmd.exe":
                    env = kwargs["env"]
                    self.assertEqual(env[REGISTRATION_TOKEN_ENVIRONMENT_NAME], TOKEN)
                    self.assertFalse(any(TOKEN in item for item in command))
                    return completed(command, stdout="configured\n")
                raise AssertionError(command)

            runtime = WindowsEphemeralRegistrationRuntime(binding, command_runner=command_runner)
            token = runtime.acquire_registration_token(binding.repository)
            self.assertEqual(token, TOKEN)
            execution = runtime.run_registration(binding, token)
            self.assertEqual(execution.exit_code, 0)

            runner_reads = [
                command
                for command, _ in seen
                if command[0:2] == ("gh.exe", "api") and "actions/runners?" in command[-1]
            ]
            self.assertEqual(len(runner_reads), 2)
            token_calls = [
                command
                for command, _ in seen
                if command[0:4] == ("gh.exe", "api", "--method", "POST")
            ]
            self.assertEqual(
                token_calls,
                [
                    (
                        "gh.exe",
                        "api",
                        "--method",
                        "POST",
                        f"repos/{binding.repository}/actions/runners/registration-token",
                    )
                ],
            )
            config_calls = [command for command, _ in seen if command[0] == "cmd.exe"]
            self.assertEqual(len(config_calls), 1)
            config_call = config_calls[0]
            self.assertIn("--ephemeral", config_call)
            self.assertIn("--no-default-labels", config_call)
            self.assertIn("--disableupdate", config_call)
            self.assertNotIn("--token", config_call)

    def test_credential_handoff_scan_detects_plaintext_token(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            runtime = WindowsEphemeralRegistrationRuntime(binding)
            (root / "safe.txt").write_text("safe", encoding="utf-8")
            self.assertTrue(runtime.credential_handoff_cleared(binding, TOKEN))
            (root / "bad.txt").write_text(f"secret={TOKEN}", encoding="utf-8")
            self.assertFalse(runtime.credential_handoff_cleared(binding, TOKEN))

    def test_local_runner_settings_must_prove_ephemeral_disableupdate_name_and_workfolder(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            settings = {
                "AgentName": binding.runner_name,
                "WorkFolder": binding.work_folder,
                "Ephemeral": True,
                "DisableUpdate": True,
            }
            (root / ".runner").write_text(json.dumps(settings), encoding="utf-8")

            def command_runner(*command, **kwargs):
                if command[0:2] == ("gh.exe", "api"):
                    return completed(
                        command,
                        stdout=json.dumps(
                            {
                                "total_count": 1,
                                "runners": [
                                    {
                                        "id": 7,
                                        "name": binding.runner_name,
                                        "status": "offline",
                                        "busy": False,
                                        "labels": [{"name": binding.runner_label}],
                                    }
                                ],
                            }
                        ),
                    )
                raise AssertionError(command)

            runtime = WindowsEphemeralRegistrationRuntime(binding, command_runner=command_runner)
            runners = runtime.read_runners(binding.repository)
            self.assertEqual(len(runners), 1)
            self.assertTrue(runners[0].ephemeral)

            settings["Ephemeral"] = False
            (root / ".runner").write_text(json.dumps(settings), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "not ephemeral"):
                runtime.read_runners(binding.repository)

    def test_package_path_traversal_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            archive = Path(temporary_directory) / "runner.zip"
            archive.write_bytes(make_runner_zip_bytes(traversal=True))
            destination = Path(temporary_directory) / "out"
            destination.mkdir()
            with self.assertRaisesRegex(RuntimeError, "path traversal"):
                WindowsEphemeralRegistrationRuntime._safe_extract(archive, destination)
            self.assertFalse((Path(temporary_directory) / "escape.txt").exists())


if __name__ == "__main__":
    unittest.main()
