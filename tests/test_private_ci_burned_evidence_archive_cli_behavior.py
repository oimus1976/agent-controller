"""Behavior tests for scripts/archive_private_ci_burned_evidence.py.

These tests call the real ``command_plan`` and ``command_apply_internal``
entry points. Git, Windows identity/elevation, the Python runtime binding and
the reviewed archive module are replaced with recording fakes. The reviewed
controller sources are real files in a temporary tree, bound with the real
source-binding and bound-read helpers, and the UAC transport is built by the
real encoder and decoded back here.

They replace source-text assertions (Issue #246 section A) that only checked
substrings or their offsets in the script source.
"""

import base64
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPO_ROOT / "scripts" / "archive_private_ci_burned_evidence.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "archive_private_ci_burned_evidence_behavior_under_test",
        CLI_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses resolve string annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CLI = _load_cli()
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PLAN_RAW = b'{"schema":"burned-archive-plan-behavior-test","items":[]}\n'
PLAN_SHA = hashlib.sha256(PLAN_RAW).hexdigest()
MAIN_SHA = "9" * 40
PYTHON = r"C:\Program Files\Python312\python.exe"
PYTHON_SHA = "p" * 64


class _Recorder:
    def __init__(self):
        self.events = []

    def fake(self, name, result=None, effect=None):
        def call(*args, **kwargs):
            self.events.append(name)
            if effect is not None:
                return effect(*args, **kwargs)
            return result

        return call

    def index(self, name, occurrence=1):
        seen = 0
        for position, event in enumerate(self.events):
            if event == name:
                seen += 1
                if seen == occurrence:
                    return position
        raise AssertionError(f"{name!r} occurrence {occurrence} not in {self.events}")


def _forbidden(name):
    def call(*args, **kwargs):
        raise AssertionError(f"{name} must not be called")

    return call


def _decode_uac_bootstrap(stdout):
    """Decode the printed UAC command back to the rendered bootstrap text."""
    line = next(
        line for line in stdout.splitlines() if line.startswith("uac_apply_command=")
    )
    encoded = re.search(r"-EncodedCommand ([A-Za-z0-9+/=]+)", line).group(1)
    stub = base64.b64decode(encoded, validate=True).decode("utf-16-le")
    payload = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", stub).group(1)
    expected_sha = re.search(r"if\(\$s -cne '([0-9a-f]{64})'\)", stub).group(1)
    rendered_raw = gzip.decompress(base64.b64decode(payload, validate=True))
    return line, stub, expected_sha, rendered_raw


class _ArchiveCliHarness(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "agent-controller"
        for relative in CLI.REVIEWED_CONTROLLER_SOURCE_PATHS:
            target = self.root.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT.joinpath(*PurePosixPath(relative).parts), target)
        self.blob_ids = {
            relative: CLI._git_blob_sha1(
                self.root.joinpath(*PurePosixPath(relative).parts).read_bytes()
            )
            for relative in CLI.REVIEWED_CONTROLLER_SOURCE_PATHS
        }
        self.bootstrap_path = self.root / "scripts" / "Archive-PrivateCiBurnedEvidence.ps1"
        self.recorder = _Recorder()

    def _source_path(self, relative):
        return self.root.joinpath(*PurePosixPath(relative).parts)

    def _run(self, call, patches):
        stdout = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(CLI, name, value))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            try:
                return call(), stdout.getvalue()
            except BaseException:
                self.stdout = stdout.getvalue()
                raise


class ArchivePlanBehaviorTests(_ArchiveCliHarness):
    def setUp(self):
        super().setUp()
        self.build_plan_calls = []
        self.plan_result = "default"

    def _exact(self, *args, **kwargs):
        return MAIN_SHA, self.root, dict(self.blob_ids)

    def _fake_archive(self):
        def build_archive_plan(**kwargs):
            self.recorder.events.append("build_archive_plan")
            self.build_plan_calls.append(kwargs)
            if self.plan_result is None:
                return None
            return SimpleNamespace(
                controller_sources=kwargs["controller_sources"],
                archive_directory=r"C:\archive\burned",
                python_executable=kwargs["python_executable"],
                python_sha256=kwargs["python_sha256"],
                items=(),
            )

        return SimpleNamespace(
            ControllerSourceBinding=lambda **kw: SimpleNamespace(**kw),
            build_archive_plan=build_archive_plan,
            archive_plan_bytes=lambda plan: PLAN_RAW,
        )

    def _plan_patches(self, overrides=None):
        rec = self.recorder
        patches = {
            "_require_controller_source_exact": rec.fake("source_exact", effect=self._exact),
            "_python_binding": rec.fake("python_binding", (PYTHON, PYTHON_SHA)),
            "_load_bound_archive_module": rec.fake(
                "load_reviewed_module",
                effect=lambda root, records: self._fake_archive(),
            ),
            "_trusted_windows_powershell_path": mock.Mock(return_value=Path(POWERSHELL)),
            "_completed": _forbidden("_completed"),
            "_require_windows_elevated_boundary": _forbidden(
                "_require_windows_elevated_boundary"
            ),
        }
        patches.update(overrides or {})
        return patches

    def _plan(self, overrides=None):
        return self._run(CLI.command_plan, self._plan_patches(overrides))

    def test_source_is_verified_twice_before_reviewed_module_is_loaded(self):
        code, stdout = self._plan()
        self.assertEqual(code, 0)
        rec = self.recorder
        self.assertEqual(rec.events.count("source_exact"), 2)
        self.assertLess(rec.index("source_exact", 2), rec.index("load_reviewed_module"))
        self.assertEqual(rec.events.count("load_reviewed_module"), 1)
        self.assertIn("BURNED_CANONICAL_ARCHIVE_PLAN_READY", stdout)
        self.assertIn("NO_MUTATION_PERFORMED", stdout)

    def test_source_drift_between_verifications_blocks_before_module_load(self):
        drifted = dict(self.blob_ids)
        drifted["agent_controller/private_ci_burned_evidence_archive.py"] = "0" * 40
        answers = iter([
            (MAIN_SHA, self.root, dict(self.blob_ids)),
            (MAIN_SHA, self.root, drifted),
        ])
        exact = self.recorder.fake("source_exact", effect=lambda: next(answers))
        with self.assertRaisesRegex(RuntimeError, "controller source drift during archive planning"):
            self._plan({"_require_controller_source_exact": exact})
        self.assertNotIn("load_reviewed_module", self.recorder.events)
        self.assertNotIn("BURNED_CANONICAL_ARCHIVE_PLAN_READY", self.stdout)

    def test_empty_inventory_is_never_reported_as_success(self):
        self.plan_result = None
        with self.assertRaisesRegex(
            RuntimeError,
            "empty canonical inventory cannot be proven atomically",
        ):
            self._plan()
        self.assertIn("build_archive_plan", self.recorder.events)
        self.assertNotIn("BURNED_CANONICAL_ARCHIVE_PLAN_READY", self.stdout)
        self.assertNotIn("NO_MUTATION_PERFORMED", self.stdout)

    def test_uac_command_carries_exact_reviewed_plan_inside_verified_bootstrap(self):
        code, stdout = self._plan()
        self.assertEqual(code, 0)
        line, stub, expected_sha, rendered_raw = _decode_uac_bootstrap(stdout)

        self.assertIn(f"Start-Process '{POWERSHELL}' -Verb RunAs -Wait", line)
        # The decoding stub checks the SHA-256 of the exact bootstrap it runs.
        self.assertEqual(expected_sha, hashlib.sha256(rendered_raw).hexdigest())
        self.assertNotIn("$env:", stub)

        rendered = rendered_raw.decode("utf-8")
        self.assertNotIn("__EXPECTED_PLAN_SHA256__", rendered)
        self.assertNotIn("__EXPECTED_PLAN_BASE64__", rendered)
        embedded_sha = re.search(r"\$ExpectedPlanSha256 = '([0-9a-f]{64})'", rendered).group(1)
        embedded_plan = re.search(r"\$ExpectedPlanBase64 = '([A-Za-z0-9+/=]+)'", rendered).group(1)
        self.assertEqual(embedded_sha, PLAN_SHA)
        self.assertEqual(base64.b64decode(embedded_plan, validate=True), PLAN_RAW)
        self.assertIn(f"archive_plan_sha256={PLAN_SHA}", stdout)

    def test_bootstrap_is_rendered_from_bound_source_bytes(self):
        code, stdout = self._plan()
        self.assertEqual(code, 0)
        _, _, _, rendered_raw = _decode_uac_bootstrap(stdout)
        # Decode bytes, not read_text(): a Windows CRLF checkout must compare
        # exactly as the CLI renders it.
        template = self.bootstrap_path.read_bytes().decode("utf-8")
        expected = (
            template
            .replace("__EXPECTED_PLAN_SHA256__", PLAN_SHA)
            .replace("__EXPECTED_PLAN_BASE64__", base64.b64encode(PLAN_RAW).decode("ascii"))
        )
        self.assertEqual(rendered_raw.decode("utf-8"), expected)

    def test_bootstrap_changed_after_binding_is_rejected(self):
        for label, tamper in (
            ("same-size edit", lambda raw: raw.replace(b"Stop", b"Stap", 1)),
            ("appended bytes", lambda raw: raw + b"\n# appended\n"),
        ):
            with self.subTest(change=label):
                self.setUp()

                def load_then_tamper(root, records, tamper=tamper):
                    self.recorder.events.append("load_reviewed_module")
                    self.bootstrap_path.write_bytes(tamper(self.bootstrap_path.read_bytes()))
                    return self._fake_archive()

                with self.assertRaisesRegex(RuntimeError, "reviewed controller source (SHA|size) drift"):
                    self._plan({"_load_bound_archive_module": load_then_tamper})
                self.assertNotIn("uac_apply_command=", self.stdout)

    def test_non_canonical_source_is_rejected_before_module_load(self):
        path = self._source_path("agent_controller/private_ci_burned_evidence_archive.py")
        path.write_bytes(path.read_bytes() + b"\n# local edit\n")
        with self.assertRaisesRegex(RuntimeError, "is not canonical blob"):
            self._plan()
        self.assertNotIn("load_reviewed_module", self.recorder.events)

    def test_bootstrap_template_markers_must_occur_exactly_once(self):
        for marker in ("__EXPECTED_PLAN_SHA256__", "__EXPECTED_PLAN_BASE64__"):
            with self.subTest(marker=marker):
                self.setUp()
                raw = self.bootstrap_path.read_bytes() + f"\n# {marker}\n".encode("utf-8")
                self.bootstrap_path.write_bytes(raw)
                self.blob_ids["scripts/Archive-PrivateCiBurnedEvidence.ps1"] = CLI._git_blob_sha1(raw)
                with self.assertRaisesRegex(RuntimeError, "template marker invalid"):
                    self._plan()
                self.assertNotIn("uac_apply_command=", self.stdout)


class ArchiveApplyInternalBehaviorTests(_ArchiveCliHarness):
    def setUp(self):
        super().setUp()
        records = [
            {
                "relative_path": relative,
                "sha256": hashlib.sha256(self._source_path(relative).read_bytes()).hexdigest(),
                "size": self._source_path(relative).stat().st_size,
            }
            for relative in CLI.REVIEWED_CONTROLLER_SOURCE_PATHS
        ]
        self.plan_raw = json.dumps({"schema": "test", "controller_sources": records}).encode("utf-8")
        self.plan_sha = hashlib.sha256(self.plan_raw).hexdigest()
        self.plan_b64 = base64.b64encode(self.plan_raw).decode("ascii")
        self.apply_calls = []
        self.result_status = "PASS_MARKER"

    def _fake_archive(self, root, records):
        self.recorder.events.append("load_reviewed_module")
        self.loaded_records = records

        def apply_archive_plan(**kwargs):
            self.recorder.events.append("apply_archive_plan")
            self.apply_calls.append(kwargs)
            return SimpleNamespace(
                status=self.result_status,
                archive_directory=r"C:\archive\burned",
                items=(),
            )

        return SimpleNamespace(
            parse_archive_plan_bytes=self.recorder.fake(
                "parse_plan",
                SimpleNamespace(python_executable=PYTHON, python_sha256=PYTHON_SHA),
            ),
            apply_archive_plan=apply_archive_plan,
            ARCHIVE_RETIREMENT_PASS="PASS_MARKER",
        )

    def _apply_patches(self, overrides=None):
        rec = self.recorder
        patches = {
            "_controller_repo_root": mock.Mock(return_value=self.root),
            "_require_windows_elevated_boundary": rec.fake("elevated_boundary"),
            "_load_bound_archive_module": self._fake_archive,
            "_python_binding": rec.fake("python_binding", (PYTHON, PYTHON_SHA)),
            # The elevated apply runs only from the reviewed snapshot: it must
            # never re-run git, PowerShell, or the mutable-checkout checks.
            "_require_controller_source_exact": _forbidden("_require_controller_source_exact"),
            "_completed": _forbidden("_completed"),
            "_trusted_git_path": _forbidden("_trusted_git_path"),
            "_trusted_windows_powershell_path": _forbidden("_trusted_windows_powershell_path"),
        }
        patches.update(overrides or {})
        return patches

    def _apply(self, sha=None, b64=None, overrides=None):
        return self._run(
            lambda: CLI.command_apply_internal(
                self.plan_sha if sha is None else sha,
                self.plan_b64 if b64 is None else b64,
            ),
            self._apply_patches(overrides),
        )

    def test_apply_orders_elevation_reviewed_load_runtime_binding_then_apply(self):
        code, stdout = self._apply()
        self.assertEqual(code, 0)
        rec = self.recorder
        order = ["elevated_boundary", "load_reviewed_module", "parse_plan", "python_binding", "apply_archive_plan"]
        positions = [rec.index(step) for step in order]
        self.assertEqual(positions, sorted(positions), rec.events)
        self.assertEqual(
            [r.relative_path for r in self.loaded_records],
            list(CLI.REVIEWED_CONTROLLER_SOURCE_PATHS),
        )
        self.assertEqual(self.apply_calls[0]["expected_plan_sha256"], self.plan_sha)
        self.assertIn("APPROVAL_AND_CONSUMPTION_AUTHORITY_UNCHANGED", stdout)

    def test_plan_digest_or_encoding_mismatch_blocks_before_elevation_check(self):
        cases = {
            "digest of different bytes": ("0" * 64, None, RuntimeError, "SHA-256 mismatch"),
            "malformed digest": ("A" * 64, None, ValueError, "SHA-256 invalid"),
            "non-base64 plan": (None, "not base64!", ValueError, "base64 invalid"),
        }
        for label, (sha, b64, error, message) in cases.items():
            with self.subTest(case=label):
                self.setUp()
                with self.assertRaisesRegex(error, message):
                    self._apply(sha=sha, b64=b64)
                self.assertEqual(self.recorder.events, [])

    def test_failed_elevation_check_loads_nothing_and_applies_nothing(self):
        refused = self.recorder.fake(
            "elevated_boundary",
            effect=mock.Mock(side_effect=RuntimeError("archive apply identity mismatch")),
        )
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            self._apply(overrides={"_require_windows_elevated_boundary": refused})
        self.assertEqual(self.recorder.events, ["elevated_boundary"])

    def test_runtime_drift_never_applies(self):
        for label, binding, message in (
            ("executable", (r"C:\Other\python.exe", PYTHON_SHA), "Python executable drift"),
            ("digest", (PYTHON, "q" * 64), "Python SHA-256 drift"),
        ):
            with self.subTest(drift=label):
                self.setUp()
                with self.assertRaisesRegex(RuntimeError, message):
                    self._apply(overrides={
                        "_python_binding": self.recorder.fake("python_binding", binding),
                    })
                self.assertNotIn("apply_archive_plan", self.recorder.events)

    def test_bootstrap_invocation_dispatches_to_apply_with_reviewed_arguments(self):
        # The elevated PowerShell bootstrap invokes the CLI with a fixed
        # argument shape. Replay that exact shape through the real main().
        bootstrap = self.bootstrap_path.read_bytes().decode("utf-8")
        invocation = re.search(
            # Stdout/stderr redirections (Issue #259) are not CLI arguments.
            r"& \$PythonPath -I -S -B -c \$Loader \$SnapshotRoot (.+?)(?:\s+[12]>.*)?$",
            bootstrap,
            re.MULTILINE,
        ).group(1).split()
        argv = [
            {
                "$ExpectedPlanSha256": self.plan_sha,
                "$ExpectedPlanBase64": self.plan_b64,
            }.get(token, token)
            for token in invocation
        ]
        self.assertEqual(argv[0], "apply-internal")

        stderr = io.StringIO()
        with mock.patch.object(CLI.sys, "argv", [str(CLI_PATH), *argv]), \
                contextlib.redirect_stderr(stderr):
            code, stdout = self._run(CLI.main, self._apply_patches())
        self.assertEqual(code, 0, stderr.getvalue())
        self.assertEqual(self.apply_calls[0]["expected_plan_sha256"], self.plan_sha)
        self.assertIn("PASS_MARKER", stdout)

    def test_apply_without_pass_status_is_not_reported_as_pass(self):
        self.result_status = "PARTIAL"
        with self.assertRaisesRegex(RuntimeError, "did not reach PASS"):
            self._apply()
        self.assertNotIn("PASS_MARKER", self.stdout)
        self.assertNotIn("APPROVAL_AND_CONSUMPTION_AUTHORITY_UNCHANGED", self.stdout)


if __name__ == "__main__":
    unittest.main()
