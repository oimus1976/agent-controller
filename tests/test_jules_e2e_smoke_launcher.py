from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_jules_e2e_smoke.py"


class JulesE2ESmokeLauncherTests(unittest.TestCase):
    def test_documented_direct_script_command_imports_from_repo_root(self) -> None:
        env = os.environ.copy()
        env.pop("JULES_API_KEY", None)
        env.pop("GITHUB_TOKEN", None)
        env.pop("PYTHONPATH", None)

        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )

        self.assertEqual(2, result.returncode)
        self.assertIn("Live smoke preflight failed before session creation", result.stderr)
        self.assertNotIn("ModuleNotFoundError", result.stderr)
        self.assertNotIn("No module named 'agent_controller'", result.stderr)
        self.assertFalse((ROOT / ".jules_e2e_smoke_state.json").exists())

    def test_codex_observe_virtualenv_is_ignored_but_arbitrary_untracked_file_is_not(self) -> None:
        ignored = subprocess.run(
            ["git", "check-ignore", "--quiet", ".venv-codex-observe/probe.txt"],
            cwd=ROOT,
            check=False,
        )
        arbitrary = subprocess.run(
            ["git", "check-ignore", "--quiet", "unexpected-live-smoke-probe.txt"],
            cwd=ROOT,
            check=False,
        )

        self.assertEqual(0, ignored.returncode)
        self.assertEqual(1, arbitrary.returncode)


if __name__ == "__main__":
    unittest.main()
