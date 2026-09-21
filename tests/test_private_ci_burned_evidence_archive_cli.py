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

    def test_planner_has_no_controller_import_before_source_verification(self):
        source = self.cli_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(self.cli_path))
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                self.assertFalse(
                    (node.module or "").startswith("agent_controller"),
                    msg=f"top-level controller import: {node.module}",
                )
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertFalse(
                        alias.name.startswith("agent_controller"),
                        msg=f"top-level controller import: {alias.name}",
                    )

        plan_start = source.index("def command_plan")
        apply_start = source.index("def command_apply_internal", plan_start)
        region = source[plan_start:apply_start]
        first_verify = region.index("_require_controller_source_exact()")
        module_load = region.index("_load_bound_archive_module(")
        self.assertLess(first_verify, module_load)
        self.assertIn("_read_bound_controller_source(", source)

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

    def test_encoded_bootstrap_uses_plan_bound_source_bytes(self):
        source = self.cli_path.read_text(encoding="utf-8")
        plan_start = source.index("def command_plan")
        apply_start = source.index("def command_apply_internal", plan_start)
        region = source[plan_start:apply_start]
        self.assertIn("bootstrap_binding = plan.controller_sources[0]", region)
        self.assertIn("_read_bound_controller_source(", region)
        self.assertIn("bootstrap_binding", region)
        self.assertNotIn("bootstrap_path.read_text", region)
        self.assertNotIn("Archive-PrivateCiBurnedEvidence.ps1\").read_text", region)

    def test_elevated_apply_does_not_rerun_mutable_checkout_git_or_powershell(self):
        source = self.cli_path.read_text(encoding="utf-8")
        apply_start = source.index("def command_apply_internal")
        apply_region = source[apply_start:]
        self.assertNotIn("_require_controller_source_exact()", apply_region)
        self.assertNotIn('"git.exe"', apply_region)
        self.assertNotIn('"powershell.exe"', apply_region)
        self.assertIn("_require_windows_elevated_boundary()", apply_region)


    def test_bootstrap_verifies_reviewed_sources_before_elevated_python(self):
        source = self.ps_path.read_text(encoding="utf-8")
        source_hash = source.index(
            "Reviewed controller source SHA mismatch"
        )
        snapshot_hash = source.index("Snapshot source SHA mismatch")
        child = source.index("& $PythonPath -I -S -B -c")
        self.assertLess(source_hash, snapshot_hash)
        self.assertLess(snapshot_hash, child)
        self.assertIn(
            "[Environment]::GetFolderPath",
            source,
        )
        self.assertNotIn("$env:WINDIR", source)
        self.assertNotIn("$env:COMPUTERNAME", source)

    def test_bootstrap_requires_trusted_runtime_and_namespace_lock(self):
        source = self.ps_path.read_text(encoding="utf-8")
        runtime_gate = source.index(
            "Assert-TrustedPythonRuntime -PythonPath $PythonPath"
        )
        namespace_lock = source.index(
            "Set-PrivateDirectoryAcl -LiteralPath $EvidenceRoot"
        )
        child = source.index("& $PythonPath -I -S -B -c")
        restore = source.index(
            "Set-Acl -LiteralPath $EvidenceRoot -AclObject $OriginalEvidenceAcl"
        )
        path_sanitize = source.index("$env:PATH = ($TrustedPathParts -join ';')")
        location_sanitize = source.index("Set-Location -LiteralPath $SnapshotRoot")
        self.assertLess(runtime_gate, child)
        self.assertLess(namespace_lock, child)
        self.assertLess(path_sanitize, child)
        self.assertLess(location_sanitize, child)
        self.assertGreater(restore, child)
        self.assertIn(
            "Elevated Python runtime is not under trusted Program Files.",
            source,
        )
        self.assertIn("Get-ChildItem -LiteralPath $RuntimeRoot -Recurse", source)
        self.assertIn("$ExpectedEvidenceRoot", source)
        self.assertIn("restore PATH failed", source)
        self.assertIn("evidence ACL restore failed", source)
        self.assertIn("Burned evidence archive cleanup incomplete", source)

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
        self.assertIn("-I -S -B -c", source)
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
