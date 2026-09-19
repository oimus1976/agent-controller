import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from dataclasses import replace
from pathlib import Path
from unittest import mock

from agent_controller.private_ci_live_registration import (
    REGISTRATION_TOKEN_ENVIRONMENT_NAME,
    RunnerReadbackFailure,
    frozen_live_registration_binding,
)
from agent_controller.private_ci_live_registration_runtime import (
    POST_REGISTRATION_READBACK_DELAY_SECONDS,
    POST_REGISTRATION_READBACK_MAX_ATTEMPTS,
    POST_REGISTRATION_READBACK_MAX_DELAY_SECONDS,
    POST_REGISTRATION_READBACK_MAX_ELAPSED_SECONDS,
    RESULT_SCHEMA,
    WindowsEphemeralRegistrationRuntime,
    result_payload,
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

    def test_result_payload_records_readback_attempts_and_v2_schema(self):
        binding = frozen_live_registration_binding()
        plan = SimpleNamespace(binding=binding)
        result = SimpleNamespace(
            candidate_sha256="c" * 64,
            status=SimpleNamespace(value="REGISTERED"),
            reason_codes=(),
            child_exit_code=0,
            runner_id=21,
            stdout="",
            stderr="",
        )

        payload = result_payload(
            plan=plan,
            plan_sha256_value="p" * 64,
            result=result,
            runner_readback_attempts=2,
        )

        self.assertEqual(
            RESULT_SCHEMA,
            "agent-controller.private-ci-live-registration-result.v2",
        )
        self.assertEqual(payload["schema"], RESULT_SCHEMA)
        self.assertEqual(payload["runner_readback_attempts"], 2)

        with self.assertRaisesRegex(ValueError, "readback attempts"):
            result_payload(
                plan=plan,
                plan_sha256_value="p" * 64,
                result=result,
                runner_readback_attempts=POST_REGISTRATION_READBACK_MAX_ATTEMPTS + 1,
            )

        with self.assertRaisesRegex(ValueError, "requires readback attempt"):
            result_payload(
                plan=plan,
                plan_sha256_value="p" * 64,
                result=result,
                runner_readback_attempts=0,
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

    def test_none_native_stream_stays_empty_when_secret_redaction_is_enabled(self):
        binding = frozen_live_registration_binding()

        def command_runner(*command, **kwargs):
            return completed(
                command,
                stdout=None,
                stderr=None,
            )

        runtime = WindowsEphemeralRegistrationRuntime(
            binding,
            command_runner=command_runner,
        )
        result = runtime._run_text(
            "fake-native.exe",
            redact_secrets=(TOKEN,),
        )

        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertFalse(result.secret_output_redacted)
        self.assertEqual(result.decoding_errors, ())

    def test_native_output_falls_back_to_windows_preferred_encoding(self):
        binding = frozen_live_registration_binding()

        def command_runner(*command, **kwargs):
            return completed(
                command,
                stdout="登録完了".encode("cp932"),
                stderr=b"",
            )

        runtime = WindowsEphemeralRegistrationRuntime(
            binding,
            command_runner=command_runner,
        )
        with mock.patch(
            "agent_controller.private_ci_live_registration_runtime.locale.getpreferredencoding",
            return_value="cp932",
        ):
            result = runtime._run_text("fake-native.exe")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "登録完了")
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.decoding_errors, ())

    def test_undecodable_native_output_is_explicit_and_keeps_exit_code(self):
        binding = frozen_live_registration_binding()

        def command_runner(*command, **kwargs):
            return completed(
                command,
                returncode=37,
                stdout=b"\x81",
                stderr=b"",
            )

        runtime = WindowsEphemeralRegistrationRuntime(
            binding,
            command_runner=command_runner,
        )
        with mock.patch(
            "agent_controller.private_ci_live_registration_runtime.locale.getpreferredencoding",
            return_value="cp932",
        ):
            result = runtime._run_text("fake-native.exe")

        self.assertEqual(result.returncode, 37)
        self.assertEqual(result.stdout, "\\x81")
        self.assertEqual(result.decoding_errors, ("stdout",))

    def test_registration_marks_native_decode_uncertainty_without_losing_exit_code(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / "config.cmd").write_text("@echo off\n", encoding="utf-8")

            def command_runner(*command, **kwargs):
                self.assertEqual(command[0], "cmd.exe")
                return completed(
                    command,
                    returncode=0,
                    stdout=b"\x81",
                    stderr=b"",
                )

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
            )
            with mock.patch(
                "agent_controller.private_ci_live_registration_runtime.locale.getpreferredencoding",
                return_value="cp932",
            ):
                execution = runtime.run_registration(binding, TOKEN)

            self.assertEqual(execution.exit_code, 0)
            self.assertTrue(execution.output_decoding_uncertain)
            self.assertEqual(execution.stdout, "\\x81")

    def test_native_output_redacts_secret_bytes_before_multibyte_decode(self):
        binding = frozen_live_registration_binding()
        secret = "Asecret-token"

        def command_runner(*command, **kwargs):
            return completed(
                command,
                stdout=b"\x81" + secret.encode("ascii") + b"\r\n",
                stderr=b"\x81" + secret.encode("ascii"),
            )

        runtime = WindowsEphemeralRegistrationRuntime(
            binding,
            command_runner=command_runner,
        )
        with mock.patch(
            "agent_controller.private_ci_live_registration_runtime.locale.getpreferredencoding",
            return_value="cp932",
        ):
            result = runtime._run_text(
                "fake-native.exe",
                redact_secrets=(secret,),
            )

        self.assertTrue(result.secret_output_redacted)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn("secret-token", result.stdout)
        self.assertIn("***", result.stdout)
        self.assertNotIn(secret, result.stderr)
        self.assertNotIn("secret-token", result.stderr)
        self.assertIn("***", result.stderr)

    def test_registration_propagates_predecode_secret_redaction_as_leak_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / "config.cmd").write_text("@echo off\n", encoding="utf-8")

            def command_runner(*command, **kwargs):
                self.assertEqual(command[0], "cmd.exe")
                return completed(
                    command,
                    returncode=0,
                    stdout=b"\x81" + TOKEN.encode("ascii"),
                    stderr=b"",
                )

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
            )
            with mock.patch(
                "agent_controller.private_ci_live_registration_runtime.locale.getpreferredencoding",
                return_value="cp932",
            ):
                execution = runtime.run_registration(binding, TOKEN)

            self.assertEqual(execution.exit_code, 0)
            self.assertTrue(execution.secret_output_redacted)
            self.assertNotIn(TOKEN, execution.stdout)
            self.assertIn("***", execution.stdout)

    def test_post_registration_readback_stabilizes_from_zero_to_exact_runner(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / ".runner").write_text(
                json.dumps(
                    {
                        "AgentName": binding.runner_name,
                        "WorkFolder": binding.work_folder,
                        "Ephemeral": True,
                        "DisableUpdate": True,
                    }
                ),
                encoding="utf-8",
            )
            gh_calls = []
            sleeps = []

            def command_runner(*command, **kwargs):
                self.assertEqual(command[0:2], ("gh.exe", "api"))
                gh_calls.append(command)
                if len(gh_calls) <= 2:
                    payload = {"total_count": 0, "runners": []}
                else:
                    payload = {
                        "total_count": 1,
                        "runners": [
                            {
                                "id": 21,
                                "name": binding.runner_name,
                                "status": "offline",
                                "busy": False,
                                "labels": [{"name": binding.runner_label}],
                            }
                        ],
                    }
                return completed(command, stdout=json.dumps(payload))

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                sleeper=sleeps.append,
            )
            runners = runtime.read_runners(binding.repository)

            self.assertEqual(runtime.last_readback_attempts, 2)
            self.assertEqual(len(gh_calls), 4)
            self.assertEqual(sleeps, [POST_REGISTRATION_READBACK_DELAY_SECONDS])
            self.assertEqual(len(runners), 1)
            self.assertEqual(runners[0].runner_id, 21)

    def test_post_registration_revalidates_local_binding_before_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            settings_path = root / ".runner"
            settings = {
                "AgentName": binding.runner_name,
                "WorkFolder": binding.work_folder,
                "Ephemeral": True,
                "DisableUpdate": True,
            }
            settings_path.write_text(json.dumps(settings), encoding="utf-8")
            gh_calls = []

            def command_runner(*command, **kwargs):
                gh_calls.append(command)
                if len(gh_calls) <= 2:
                    payload = {"total_count": 0, "runners": []}
                else:
                    payload = {
                        "total_count": 1,
                        "runners": [
                            {
                                "id": 21,
                                "name": binding.runner_name,
                                "status": "offline",
                                "busy": False,
                                "labels": [{"name": binding.runner_label}],
                            }
                        ],
                    }
                return completed(command, stdout=json.dumps(payload))

            def sleeper(seconds):
                settings["AgentName"] = "drifted-name"
                settings_path.write_text(json.dumps(settings), encoding="utf-8")

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                sleeper=sleeper,
            )
            with self.assertRaisesRegex(RuntimeError, "local runner name mismatch"):
                runtime.read_runners(binding.repository)

            self.assertEqual(runtime.last_readback_attempts, 2)
            self.assertEqual(len(gh_calls), 4)

    def test_post_registration_sweep_instability_exhausts_bounded_attempts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / ".runner").write_text(
                json.dumps(
                    {
                        "AgentName": binding.runner_name,
                        "WorkFolder": binding.work_folder,
                        "Ephemeral": True,
                        "DisableUpdate": True,
                    }
                ),
                encoding="utf-8",
            )
            gh_calls = []
            sleeps = []

            def command_runner(*command, **kwargs):
                self.assertEqual(command[0:2], ("gh.exe", "api"))
                gh_calls.append(command)
                if len(gh_calls) % 2:
                    payload = {"total_count": 0, "runners": []}
                else:
                    payload = {
                        "total_count": 1,
                        "runners": [
                            {
                                "id": 21,
                                "name": binding.runner_name,
                                "status": "offline",
                                "busy": False,
                                "labels": [{"name": binding.runner_label}],
                            }
                        ],
                    }
                return completed(command, stdout=json.dumps(payload))

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                sleeper=sleeps.append,
            )
            with self.assertRaises(RunnerReadbackFailure) as raised:
                runtime.read_runners(binding.repository)

            self.assertEqual(
                raised.exception.reason_code,
                "RUNNER_READBACK_STABILIZATION_EXHAUSTED",
            )
            self.assertEqual(
                runtime.last_readback_attempts,
                POST_REGISTRATION_READBACK_MAX_ATTEMPTS,
            )
            self.assertEqual(
                len(gh_calls),
                POST_REGISTRATION_READBACK_MAX_ATTEMPTS * 2,
            )
            self.assertEqual(
                sleeps,
                [POST_REGISTRATION_READBACK_DELAY_SECONDS]
                * (POST_REGISTRATION_READBACK_MAX_ATTEMPTS - 1),
            )
            self.assertEqual(
                sum(sleeps),
                POST_REGISTRATION_READBACK_MAX_DELAY_SECONDS,
            )

    def test_post_registration_readback_enforces_wall_clock_budget(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / ".runner").write_text(
                json.dumps(
                    {
                        "AgentName": binding.runner_name,
                        "WorkFolder": binding.work_folder,
                        "Ephemeral": True,
                        "DisableUpdate": True,
                    }
                ),
                encoding="utf-8",
            )
            now = [0.0]
            sleeps = []
            observed_timeouts = []

            def clock():
                return now[0]

            def sleeper(seconds):
                sleeps.append(seconds)
                now[0] += seconds

            def command_runner(*command, **kwargs):
                observed_timeouts.append(kwargs.get("timeout"))
                return completed(
                    command,
                    stdout=json.dumps({"total_count": 0, "runners": []}),
                )

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                sleeper=sleeper,
                monotonic_clock=clock,
            )
            with mock.patch(
                "agent_controller.private_ci_live_registration_runtime."
                "POST_REGISTRATION_READBACK_MAX_ELAPSED_SECONDS",
                2.0,
            ):
                with self.assertRaises(RunnerReadbackFailure) as raised:
                    runtime.read_runners(binding.repository)

            self.assertEqual(
                raised.exception.reason_code,
                "RUNNER_READBACK_TIME_BUDGET_EXHAUSTED",
            )
            self.assertEqual(now[0], 2.0)
            self.assertEqual(sleeps, [1.0, 1.0])
            self.assertEqual(runtime.last_readback_attempts, 2)
            self.assertEqual(observed_timeouts[:4], [2.0, 2.0, 1.0, 1.0])
            self.assertEqual(now[0], 2.0)
            self.assertLessEqual(
                2.0,
                POST_REGISTRATION_READBACK_MAX_ELAPSED_SECONDS,
            )

    def test_post_registration_stable_zero_exhausts_visibility_bound(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / ".runner").write_text(
                json.dumps(
                    {
                        "AgentName": binding.runner_name,
                        "WorkFolder": binding.work_folder,
                        "Ephemeral": True,
                        "DisableUpdate": True,
                    }
                ),
                encoding="utf-8",
            )
            sleeps = []

            def command_runner(*command, **kwargs):
                return completed(
                    command,
                    stdout=json.dumps({"total_count": 0, "runners": []}),
                )

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                sleeper=sleeps.append,
            )
            with self.assertRaises(RunnerReadbackFailure) as raised:
                runtime.read_runners(binding.repository)

            self.assertEqual(
                raised.exception.reason_code,
                "RUNNER_VISIBILITY_STABILIZATION_EXHAUSTED",
            )
            self.assertEqual(
                runtime.last_readback_attempts,
                POST_REGISTRATION_READBACK_MAX_ATTEMPTS,
            )
            self.assertEqual(
                len(sleeps),
                POST_REGISTRATION_READBACK_MAX_ATTEMPTS - 1,
            )

    def test_post_registration_wrong_identity_fails_immediately_without_retry(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / ".runner").write_text(
                json.dumps(
                    {
                        "AgentName": binding.runner_name,
                        "WorkFolder": binding.work_folder,
                        "Ephemeral": True,
                        "DisableUpdate": True,
                    }
                ),
                encoding="utf-8",
            )
            gh_calls = []
            sleeps = []

            def command_runner(*command, **kwargs):
                gh_calls.append(command)
                return completed(
                    command,
                    stdout=json.dumps(
                        {
                            "total_count": 1,
                            "runners": [
                                {
                                    "id": 22,
                                    "name": "wrong-name",
                                    "status": "offline",
                                    "busy": False,
                                    "labels": [{"name": binding.runner_label}],
                                }
                            ],
                        }
                    ),
                )

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                sleeper=sleeps.append,
            )
            with self.assertRaises(RunnerReadbackFailure) as raised:
                runtime.read_runners(binding.repository)

            self.assertEqual(
                raised.exception.reason_code,
                "RUNNER_READBACK_IDENTITY_MISMATCH",
            )
            self.assertEqual(runtime.last_readback_attempts, 1)
            self.assertEqual(len(gh_calls), 2)
            self.assertEqual(sleeps, [])

    def test_post_registration_duplicate_eligible_runners_fail_immediately(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            binding = self.binding_for(temporary_directory)
            root = Path(binding.runner_root)
            root.mkdir(parents=True)
            (root / ".runner").write_text(
                json.dumps(
                    {
                        "AgentName": binding.runner_name,
                        "WorkFolder": binding.work_folder,
                        "Ephemeral": True,
                        "DisableUpdate": True,
                    }
                ),
                encoding="utf-8",
            )
            sleeps = []

            def command_runner(*command, **kwargs):
                return completed(
                    command,
                    stdout=json.dumps(
                        {
                            "total_count": 2,
                            "runners": [
                                {
                                    "id": 21,
                                    "name": binding.runner_name,
                                    "status": "offline",
                                    "busy": False,
                                    "labels": [{"name": binding.runner_label}],
                                },
                                {
                                    "id": 22,
                                    "name": "duplicate",
                                    "status": "offline",
                                    "busy": False,
                                    "labels": [{"name": binding.runner_label}],
                                },
                            ],
                        }
                    ),
                )

            runtime = WindowsEphemeralRegistrationRuntime(
                binding,
                command_runner=command_runner,
                sleeper=sleeps.append,
            )
            with self.assertRaises(RunnerReadbackFailure) as raised:
                runtime.read_runners(binding.repository)

            self.assertEqual(
                raised.exception.reason_code,
                "RUNNER_READBACK_ELIGIBLE_COUNT_UNSAFE",
            )
            self.assertEqual(runtime.last_readback_attempts, 1)
            self.assertEqual(sleeps, [])

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
