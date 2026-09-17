import importlib.util
import io
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_private_ci_live_registration.py"
SPEC = importlib.util.spec_from_file_location("run_private_ci_live_registration", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class FakeTty(io.StringIO):
    def __init__(self, value="", *, tty=True):
        super().__init__(value)
        self._tty = tty

    def isatty(self):
        return self._tty


class HumanAuthorizationGateTests(unittest.TestCase):
    def test_noninteractive_input_is_blocked(self):
        stdin = FakeTty("a" * 64 + "\n", tty=False)
        stdout = FakeTty(tty=True)
        with self.assertRaisesRegex(RuntimeError, "controlling terminal"):
            MODULE._require_interactive_human_authorization(
                "a" * 64,
                stdin=stdin,
                stdout=stdout,
            )

    def test_noninteractive_output_is_blocked(self):
        stdin = FakeTty("a" * 64 + "\n", tty=True)
        stdout = FakeTty(tty=False)
        with self.assertRaisesRegex(RuntimeError, "controlling terminal"):
            MODULE._require_interactive_human_authorization(
                "a" * 64,
                stdin=stdin,
                stdout=stdout,
            )

    def test_wrong_digest_is_blocked(self):
        stdin = FakeTty("b" * 64 + "\n", tty=True)
        stdout = FakeTty(tty=True)
        with self.assertRaisesRegex(RuntimeError, "confirmation mismatch"):
            MODULE._require_interactive_human_authorization(
                "a" * 64,
                stdin=stdin,
                stdout=stdout,
            )

    def test_exact_digest_on_tty_is_accepted(self):
        digest = "a" * 64
        stdin = FakeTty(digest + "\n", tty=True)
        stdout = FakeTty(tty=True)
        MODULE._require_interactive_human_authorization(
            digest,
            stdin=stdin,
            stdout=stdout,
        )
        rendered = stdout.getvalue()
        self.assertIn(digest, rendered)
        self.assertIn("type the exact plan SHA-256", rendered)


if __name__ == "__main__":
    unittest.main()
