import json
import unittest

from agent_controller.private_ci_live_registration import frozen_live_registration_binding
from agent_controller.private_ci_live_registration_runtime import (
    WindowsEphemeralRegistrationRuntime,
)


class Completed:
    def __init__(self, *, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TokenBoundaryCollisionTests(unittest.TestCase):
    def test_collision_immediately_before_token_post_blocks_without_post(self):
        binding = frozen_live_registration_binding()
        posts = []
        gets = []

        def command_runner(*command, **kwargs):
            if command[0:4] == ("gh.exe", "api", "--method", "POST"):
                posts.append(command)
                return Completed(stdout=json.dumps({"token": "must-not-be-issued"}))
            if command[0:2] == ("gh.exe", "api"):
                gets.append(command)
                runner = {
                    "id": 99,
                    "name": binding.runner_name,
                    "status": "offline",
                    "busy": False,
                    "labels": [{"name": binding.runner_label}],
                }
                return Completed(
                    stdout=json.dumps({"total_count": 1, "runners": [runner]})
                )
            raise AssertionError(command)

        runtime = WindowsEphemeralRegistrationRuntime(binding, command_runner=command_runner)
        with self.assertRaisesRegex(RuntimeError, "stale eligible runner"):
            runtime.acquire_registration_token(binding.repository)

        self.assertEqual(posts, [])
        self.assertGreaterEqual(len(gets), 2)  # two stable-snapshot sweeps


if __name__ == "__main__":
    unittest.main()
