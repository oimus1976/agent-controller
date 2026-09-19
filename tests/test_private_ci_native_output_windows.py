import os
import sys
import unittest
from unittest import mock

from agent_controller.private_ci_live_registration import frozen_live_registration_binding
from agent_controller.private_ci_live_registration_runtime import (
    WindowsEphemeralRegistrationRuntime,
)


@unittest.skipUnless(os.name == "nt", "Windows native-output regression")
class WindowsNativeOutputRegressionTests(unittest.TestCase):
    def setUp(self):
        self.runtime = WindowsEphemeralRegistrationRuntime(
            frozen_live_registration_binding()
        )

    def test_real_subprocess_cp932_output_does_not_raise_reader_thread_decode_error(self):
        script = (
            "import os;"
            "os.write(1, '登録完了'.encode('cp932'));"
            "os.write(2, '警告'.encode('cp932'))"
        )
        with mock.patch(
            "agent_controller.private_ci_live_registration_runtime.locale.getpreferredencoding",
            return_value="cp932",
        ):
            result = self.runtime._run_text(sys.executable, "-c", script)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "登録完了")
        self.assertEqual(result.stderr, "警告")
        self.assertEqual(result.decoding_errors, ())

    def test_real_subprocess_undecodable_output_keeps_exact_exit_code_and_uncertainty(self):
        script = "import os,sys;os.write(1,b'\\x81');sys.exit(37)"
        with mock.patch(
            "agent_controller.private_ci_live_registration_runtime.locale.getpreferredencoding",
            return_value="cp932",
        ):
            result = self.runtime._run_text(sys.executable, "-c", script)

        self.assertEqual(result.returncode, 37)
        self.assertEqual(result.stdout, "\\x81")
        self.assertEqual(result.decoding_errors, ("stdout",))


if __name__ == "__main__":
    unittest.main()
