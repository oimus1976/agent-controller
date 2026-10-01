import unittest
from pathlib import Path


class PrivateCiPilotFreezeCliTests(unittest.TestCase):
    """Static no-live-mutation surface boundary for the pilot freeze script.

    Readback ordering, fail-closed behavior and fresh-identity generation are
    exercised by ``test_private_ci_pilot_freeze_behavior``.
    """

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.path = cls.repo_root / "scripts" / "create_private_ci_pilot_freeze.py"
        cls.source = cls.path.read_text(encoding="utf-8")

    def test_freeze_generation_has_no_live_mutation_surface(self):
        forbidden = (
            "--method",
            "registration-token",
            "config.cmd",
            "run.cmd",
            "/dispatches",
            "SELF_HOSTED_PRIVATE_CI_PASS",
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, self.source)
        self.assertIn(
            "NO_RUNNER_REGISTRATION_OR_WORKFLOW_DISPATCH_PERFORMED",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
