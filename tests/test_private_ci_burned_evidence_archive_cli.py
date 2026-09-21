import ast
import unittest
from pathlib import Path


class PrivateCiBurnedEvidenceArchiveCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.cli_path = (
            cls.repo_root / "scripts" / "archive_private_ci_burned_evidence.py"
        )
        cls.ps_path = (
            cls.repo_root / "scripts" / "Archive-PrivateCiBurnedEvidence.ps1"
        )

    def test_python_cli_parses(self):
        source = self.cli_path.read_text(encoding="utf-8")
        ast.parse(source, filename=str(self.cli_path))

    def test_plan_is_read_only_and_has_no_live_pilot_surface(self):
        source = self.cli_path.read_text(encoding="utf-8")
        plan_start = source.index("def command_plan")
        apply_start = source.index("def command_apply_internal", plan_start)
        region = source[plan_start:apply_start]
        for forbidden in (
            "unlink(",
            "remove(",
            "rmtree(",
            "registration-token",
            "/dispatches",
            "config.cmd",
            "run.cmd",
            "SELF_HOSTED_PRIVATE_CI_PASS",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, region)

    def test_apply_requires_expected_plan_sha_and_elevation(self):
        source = self.cli_path.read_text(encoding="utf-8")
        self.assertIn("--expected-plan-sha256", source)
        self.assertIn("_require_windows_elevated_boundary()", source)
        self.assertIn("apply_archive_plan(", source)


    def test_plan_carries_reviewed_plan_and_encoded_bootstrap_across_uac_boundary(self):
        source = self.cli_path.read_text(encoding="utf-8")
        self.assertIn("plan_base64 = base64.b64encode(raw)", source)
        self.assertIn("encoded_bootstrap = base64.b64encode(", source)
        self.assertIn("-EncodedCommand", source)
        self.assertIn(
            "AGENT_CONTROLLER_ARCHIVE_PLAN_BASE64",
            source,
        )
        self.assertNotIn(" -File ", source)
        self.assertIn("_decode_reviewed_plan(", source)
        self.assertIn("parse_archive_plan_bytes(raw)", source)

    def test_elevated_apply_does_not_rerun_mutable_checkout_git_or_powershell(self):
        source = self.cli_path.read_text(encoding="utf-8")
        apply_start = source.index("def command_apply_internal")
        apply_region = source[apply_start:]
        self.assertNotIn("_require_controller_source_exact()", apply_region)
        self.assertNotIn('"git.exe"', apply_region)
        self.assertNotIn('"powershell.exe"', apply_region)
        self.assertIn("_require_windows_elevated_boundary()", apply_region)


    def test_cli_has_no_caller_supplied_source_path(self):
        source = self.cli_path.read_text(encoding="utf-8")
        self.assertNotIn("--source", source)
        self.assertNotIn("--path", source)
        self.assertNotIn("--filename", source)

    def test_powershell_bootstrap_snapshots_reviewed_sources_before_python_import(self):
        source = self.ps_path.read_text(encoding="utf-8")
        self.assertIn("__EXPECTED_PLAN_SHA256__", source)
        self.assertIn("AGENT_CONTROLLER_ARCHIVE_PLAN_BASE64", source)
        self.assertIn("$Plan.controller_sources", source)
        self.assertIn("$ExpectedSourcePaths", source)
        self.assertIn("[IO.FileShare]::Read", source)
        self.assertIn("Snapshot source SHA mismatch", source)
        self.assertIn("runpy.run_path", source)
        self.assertIn("-I -B -c", source)
        self.assertNotIn("& python.exe", source)
        self.assertNotIn("-m scripts.archive_private_ci_burned_evidence", source)
        for forbidden in (
            "registration-token",
            "/dispatches",
            "config.cmd",
            "run.cmd",
            "Remove-LocalUser",
            "Remove-Service",
            "SELF_HOSTED_PRIVATE_CI_PASS",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
