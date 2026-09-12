"""Regression tests for the trusted pre-check that runs before actions/checkout."""

import base64
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_self_hosted_fallback_workflow import (
    WORKFLOW,
    parse_strict_workflow_structure,
)


class PreCheckoutReparseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        blocks = parse_strict_workflow_structure(cls.text)
        preflight = blocks["Preflight trusted control and disposable target identities"]
        start_marker = "if ([string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE)"
        end_marker = '"validated_control_sid=$controlSid"'
        cls.gate = preflight[preflight.index(start_marker):preflight.index(end_marker)]

    def test_precheckout_reparse_gate_is_before_checkout(self):
        gate_marker = "pre-check workspace reparse point"
        checkout_marker = "      - name: Checkout exact target SHA\n"
        self.assertIn(gate_marker, self.text)
        self.assertLess(self.text.index(gate_marker), self.text.index(checkout_marker))
        self.assertIn("[IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)", self.gate)
        self.assertIn("[IO.DirectoryInfo]::new($workspacePath)", self.gate)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", self.gate)

    @unittest.skipUnless(sys.platform == "win32", "Windows junction regression")
    def test_junction_workspace_or_ancestor_is_rejected_before_mutation_marker(self):
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("Windows PowerShell is unavailable")

        with tempfile.TemporaryDirectory(prefix="issue197-precheckout-") as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            junction = root / "workspace-link"
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"could not create junction fixture: {created.stderr or created.stdout}")

            scenarios = (
                ("ordinary", root / "ordinary-workspace", True),
                ("junction-workspace", junction, False),
                ("junction-ancestor", junction / "not-yet-created", False),
            )
            (root / "ordinary-workspace").mkdir()

            for name, workspace, accepted in scenarios:
                with self.subTest(name=name):
                    marker = root / f"mutation-{name}.txt"
                    workspace_literal = str(workspace).replace("'", "''")
                    marker_literal = str(marker).replace("'", "''")
                    script = (
                        "$ErrorActionPreference = 'Stop'\n"
                        f"$env:GITHUB_WORKSPACE = '{workspace_literal}'\n"
                        "try {\n"
                        + self.gate
                        + f"\nSet-Content -LiteralPath '{marker_literal}' -Value 'CHECKOUT_MARKER'\n"
                        + "'ACCEPT'\n} catch { 'REJECT' }\n"
                    )
                    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
                    result = subprocess.run(
                        [
                            powershell,
                            "-NoProfile",
                            "-NonInteractive",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-EncodedCommand",
                            encoded,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    verdict = result.stdout.strip().splitlines()[-1]
                    self.assertEqual(verdict, "ACCEPT" if accepted else "REJECT")
                    self.assertEqual(marker.exists(), accepted)


if __name__ == "__main__":
    unittest.main()
