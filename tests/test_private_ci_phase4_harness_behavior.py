"""Behavior tests for the #225 Phase 4 harness and registration handoff builder.

These tests call the real ``command_plan`` / ``command_apply`` /
``main`` entry points. The Windows, PowerShell, GitHub and ACL boundaries are
replaced with recording fakes, and the tests assert the order in which the
harness actually performs its checks and effects. That includes the
fail-closed paths: when a check fails, no later effect may happen.

They replace source-text ordering assertions (Issue #246 section A), which
only compared substring offsets in the script source.
"""

import contextlib
import hashlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(
        f"{name}_behavior_under_test",
        SCRIPTS / f"{name}.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


PHASE4 = _load("run_private_ci_phase4")
HANDOFF = _load("build_private_ci_registration_handoff")


class _Recorder:
    """Ordered log of boundary calls shared by every fake in a test."""

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

    def count(self, name):
        return self.events.count(name)


class Phase4HarnessBehaviorTests(unittest.TestCase):
    CANDIDATE = "Write-Output 'candidate'\n"
    APPROVAL_SHA = "a" * 64
    CONSUMPTION_SHA = "c" * 64

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.evidence_root = base / "evidence"
        self.controller_root = base / "controller"
        self.runner_root = base / "generation" / "runner"
        for directory in (
            self.evidence_root,
            self.controller_root / "scripts",
            self.runner_root,
        ):
            directory.mkdir(parents=True)

        self.handoff_path = self.evidence_root / PHASE4.HANDOFF_FILENAME
        self.candidate_path = self.evidence_root / PHASE4.PHASE4_CANDIDATE_FILENAME
        self.plan_path = self.evidence_root / PHASE4.PHASE4_PLAN_FILENAME
        self.result_path = self.evidence_root / PHASE4.PHASE4_RESULT_FILENAME
        self.transcript_path = self.evidence_root / PHASE4.PHASE4_TRANSCRIPT_FILENAME
        self.probe_path = (
            self.controller_root / "scripts" / PHASE4.PHASE4_TARGET_PROBE_FILENAME
        )

        self.plan_raw = b'{"phase4": "plan"}\n'
        self.plan_sha = hashlib.sha256(self.plan_raw).hexdigest()
        self.handoff_path.write_bytes(b'{"handoff": 1}\n')
        self.candidate_path.write_bytes(self.CANDIDATE.encode("utf-8"))
        self.plan_path.write_bytes(self.plan_raw)
        self.probe_path.write_bytes(b"# probe\n")
        self.approval_raw = b'{"approval": 1}\n'
        self.approval_path = self.evidence_root / f"approval-{self.plan_sha}.json"
        self.approval_path.write_bytes(self.approval_raw)

        self.binding = SimpleNamespace(
            runner_root=str(self.runner_root),
            work_folder="_work",
        )
        self.plan = SimpleNamespace(
            binding=self.binding,
            candidate=self.CANDIDATE,
            candidate_sha256="d" * 64,
            target_probe_sha256="e" * 64,
        )
        self.handoff = SimpleNamespace(binding=self.binding)
        self.recorder = _Recorder()

    # -- harness ---------------------------------------------------------

    def _run_candidate(self, *command, cwd=None):
        self.assertEqual(command[-1], str(self.candidate_path))
        self.assertIn("-File", command)
        for filename in (
            PHASE4.PHASE4_TARGET_PROBE_RESULT_FILENAME,
            PHASE4.PHASE4_TARGET_PROBE_STDOUT_FILENAME,
            PHASE4.PHASE4_TARGET_PROBE_STDERR_FILENAME,
        ):
            (self.runner_root / filename).write_bytes(b"probe-output\n")
        return SimpleNamespace(
            returncode=0,
            stdout="PHASE4_TARGET_ENVIRONMENT_PASS\n",
            stderr="",
        )

    def _patches(self, overrides=None):
        rec = self.recorder
        real_write = PHASE4._write_exclusive

        def recording_write(path, content):
            rec.events.append(f"write:{Path(path).name}")
            real_write(path, content)

        patches = {
            "authoritative_path": mock.Mock(side_effect=lambda name: self.evidence_root / name),
            "_controller_repo_root": mock.Mock(return_value=self.controller_root),
            "_approval_path": mock.Mock(return_value=self.approval_path),
            "_acl_state": mock.Mock(return_value=object()),
            "validate_approval_acl_state": mock.Mock(),
            "parse_phase4_plan_bytes": mock.Mock(return_value=self.plan),
            "parse_registration_handoff_bytes": mock.Mock(return_value=self.handoff),
            "validate_frozen_phase4_plan": mock.Mock(return_value=()),
            "_require_non_elevated_broker": rec.fake("non_elevated_broker"),
            "_require_controller_source_exact": rec.fake("controller_source"),
            "_require_remote_binding_exact": rec.fake("remote_binding"),
            "_require_generation_snapshot_exact": rec.fake("generation_snapshot", "g" * 64),
            "_require_phase4_approval": rec.fake(
                "approval",
                (self.approval_raw, self.APPROVAL_SHA),
            ),
            "_configure_authority": mock.Mock(return_value=(b"k" * 32, b"e" * 32)),
            "build_phase4_target_environment_spec": mock.Mock(return_value=object()),
            "operator_step_spec_sha256": mock.Mock(return_value="s" * 64),
            "_powershell_attestation": rec.fake("ast_attestation", object()),
            "_authenticate_handoff": rec.fake("authenticate_handoff", object()),
            "validate_operator_step": rec.fake(
                "operator_gate",
                SimpleNamespace(passed=True, reason_codes=(), status=None),
            ),
            "phase4_consumption_marker_path": mock.Mock(
                return_value=self.evidence_root / "not-yet-consumed.json"
            ),
            "_acquire_phase4_ownership": rec.fake("ownership"),
            "_validate_phase4_consumption": rec.fake(
                "consumption_readback",
                (b"consumed\n", self.CONSUMPTION_SHA),
            ),
            "_completed": rec.fake("execute_candidate", effect=self._run_candidate),
            "parse_target_probe_result_bytes": rec.fake("probe_result_validation"),
            "runner_generation_snapshot_sha256": mock.Mock(return_value="f" * 64),
            "Phase4ResultEvidence": mock.Mock(side_effect=lambda **kw: SimpleNamespace(**kw)),
            "phase4_result_bytes": mock.Mock(return_value=b'{"result": 1}\n'),
            "_write_exclusive": recording_write,
            "phase4_target_probe_sha256": mock.Mock(return_value="e" * 64),
            "render_phase4_target_environment_candidate": mock.Mock(return_value=self.CANDIDATE),
            "build_reviewed_phase4_plan": mock.Mock(return_value=self.plan),
            "phase4_plan_bytes": mock.Mock(return_value=self.plan_raw),
        }
        patches.update(overrides or {})
        stack = contextlib.ExitStack()
        for name, value in patches.items():
            stack.enter_context(mock.patch.object(PHASE4, name, value))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return stack

    def _apply(self, overrides=None):
        with self._patches(overrides):
            return PHASE4.command_apply(self.plan_sha)

    # -- command_apply ordering -------------------------------------------

    def test_apply_orders_checks_ownership_revalidation_execution_and_publication(self):
        self.assertEqual(self._apply(), 0)
        rec = self.recorder

        # Fresh exact generation snapshot before the human approval is read.
        self.assertLess(rec.index("generation_snapshot"), rec.index("approval"))
        # Operator gate before any protected effect.
        self.assertLess(rec.index("approval"), rec.index("operator_gate"))
        self.assertLess(rec.index("operator_gate"), rec.index("ownership"))
        # Durable consumption readback immediately follows ownership.
        self.assertLess(rec.index("ownership"), rec.index("consumption_readback"))
        # Controller, remote and generation snapshot are re-read after
        # consumption and before the candidate executes.
        for check in ("controller_source", "remote_binding", "generation_snapshot"):
            with self.subTest(revalidated=check):
                self.assertEqual(rec.count(check), 2)
                self.assertLess(rec.index("consumption_readback"), rec.index(check, 2))
                self.assertLess(rec.index(check, 2), rec.index("execute_candidate"))
        # Probe result validated before the result is published.
        self.assertLess(rec.index("execute_candidate"), rec.index("probe_result_validation"))
        self.assertLess(
            rec.index("probe_result_validation"),
            rec.index(f"write:{self.result_path.name}"),
        )
        self.assertEqual(rec.count("execute_candidate"), 1)
        self.assertEqual(self.result_path.read_bytes(), b'{"result": 1}\n')
        self.assertTrue(self.transcript_path.exists())

    def test_generation_snapshot_drift_blocks_before_approval_or_any_effect(self):
        drift = mock.Mock(side_effect=RuntimeError("Phase 4 runner generation snapshot drift"))
        with self.assertRaisesRegex(RuntimeError, "generation snapshot drift"):
            self._apply({"_require_generation_snapshot_exact": drift})
        for effect in ("approval", "ownership", "execute_candidate"):
            with self.subTest(effect=effect):
                self.assertNotIn(effect, self.recorder.events)
        self.assertFalse(self.result_path.exists())

    def test_artifact_changed_after_ownership_never_executes_candidate(self):
        cases = {
            "plan": (lambda: self.plan_path, "Phase 4 plan changed"),
            "handoff": (lambda: self.handoff_path, "registration handoff changed"),
            "candidate": (lambda: self.candidate_path, "Phase 4 candidate changed"),
            "probe": (lambda: self.probe_path, "Phase 4 target probe changed"),
            "approval": (lambda: self.approval_path, "Phase 4 approval changed"),
        }
        for label, (path_of, message) in cases.items():
            with self.subTest(changed=label):
                self.setUp()
                target = path_of()

                def tamper(*args, target=target, **kwargs):
                    target.write_bytes(target.read_bytes() + b"tampered\n")

                ownership = self.recorder.fake("ownership", effect=tamper)
                with self.assertRaisesRegex(RuntimeError, message):
                    self._apply({"_acquire_phase4_ownership": ownership})
                self.assertIn("consumption_readback", self.recorder.events)
                self.assertNotIn("execute_candidate", self.recorder.events)
                self.assertFalse(self.result_path.exists())

    def test_post_consumption_revalidation_failure_never_executes_candidate(self):
        for check in (
            "_require_controller_source_exact",
            "_require_remote_binding_exact",
            "_require_generation_snapshot_exact",
        ):
            with self.subTest(check=check):
                self.setUp()
                calls = {"n": 0}

                def second_call_fails(*args, **kwargs):
                    calls["n"] += 1
                    self.recorder.events.append(check)
                    if calls["n"] == 2:
                        raise RuntimeError("drift after consumption")
                    return "g" * 64

                with self.assertRaisesRegex(RuntimeError, "drift after consumption"):
                    self._apply({check: second_call_fails})
                self.assertLess(
                    self.recorder.index("consumption_readback"),
                    self.recorder.index(check, 2),
                )
                self.assertNotIn("execute_candidate", self.recorder.events)
                self.assertFalse(self.result_path.exists())

    def test_ownership_failure_never_reads_consumption_or_executes(self):
        refused = mock.Mock(
            side_effect=RuntimeError("Phase 4 protected ownership acquisition failed")
        )
        with self.assertRaisesRegex(RuntimeError, "ownership acquisition failed"):
            self._apply({"_acquire_phase4_ownership": refused})
        self.assertNotIn("consumption_readback", self.recorder.events)
        self.assertNotIn("execute_candidate", self.recorder.events)

    def test_failed_elevated_ownership_helper_blocks_before_consumption(self):
        # Keep the real _acquire_phase4_ownership. Only its elevated
        # PowerShell child is faked, and that child exits non-zero.
        def completed(*command, cwd=None):
            self.recorder.events.append("powershell")
            self.assertIn("-Command", command)
            self.assertIn("Consume-PrivateCiPhase4Approval.ps1", command[-1])
            return SimpleNamespace(returncode=1, stdout="", stderr="denied")

        with self.assertRaisesRegex(RuntimeError, "ownership acquisition failed"):
            self._apply({
                "_acquire_phase4_ownership": PHASE4._acquire_phase4_ownership,
                "_completed": completed,
            })
        self.assertEqual(self.recorder.count("powershell"), 1)
        self.assertNotIn("consumption_readback", self.recorder.events)
        self.assertFalse(self.result_path.exists())

    def test_invalid_probe_result_is_never_published(self):
        invalid = self.recorder.fake(
            "probe_result_validation",
            effect=mock.Mock(side_effect=ValueError("probe result invalid")),
        )
        with self.assertRaisesRegex(ValueError, "probe result invalid"):
            self._apply({"parse_target_probe_result_bytes": invalid})
        self.assertIn("execute_candidate", self.recorder.events)
        self.assertFalse(self.result_path.exists())

    # -- command_plan -----------------------------------------------------

    def _clear_plan_outputs(self):
        self.candidate_path.unlink()
        self.plan_path.unlink()

    def test_plan_requires_exact_generation_snapshot_before_writing_candidate(self):
        self._clear_plan_outputs()
        with self._patches():
            self.assertEqual(PHASE4.command_plan(), 0)
        rec = self.recorder
        self.assertLess(
            rec.index("generation_snapshot"),
            rec.index(f"write:{self.candidate_path.name}"),
        )
        self.assertLess(
            rec.index(f"write:{self.candidate_path.name}"),
            rec.index(f"write:{self.plan_path.name}"),
        )

    def test_plan_generation_snapshot_drift_writes_no_artifacts(self):
        self._clear_plan_outputs()
        drift = mock.Mock(side_effect=RuntimeError("Phase 4 runner generation snapshot drift"))
        with self._patches({"_require_generation_snapshot_exact": drift}):
            with self.assertRaisesRegex(RuntimeError, "generation snapshot drift"):
                PHASE4.command_plan()
        self.assertFalse(self.candidate_path.exists())
        self.assertFalse(self.plan_path.exists())


class RegistrationHandoffBuilderBehaviorTests(unittest.TestCase):
    HANDOFF_RAW = b'{"registration": "handoff"}\n'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.evidence_root = base / "evidence"
        self.consumption_root = base / "authority"
        self.runner_root = base / "generation" / "runner"
        for directory in (self.evidence_root, self.consumption_root, self.runner_root):
            directory.mkdir(parents=True)
        for filename in (
            HANDOFF.PHASE0_FILENAME,
            HANDOFF.REGISTRATION_PLAN_FILENAME,
            HANDOFF.REGISTRATION_RESULT_FILENAME,
            "approval.json",
        ):
            (self.evidence_root / filename).write_bytes(filename.encode("utf-8"))
        self.marker_path = self.consumption_root / "marker.consumed.json"
        self.marker_path.write_bytes(b"marker\n")
        (self.runner_root / ".runner").write_bytes(b"{}\n")
        self.pending_path = self.evidence_root / HANDOFF.HANDOFF_PENDING_FILENAME
        self.handoff_path = self.evidence_root / HANDOFF.HANDOFF_FILENAME

        self.binding = SimpleNamespace(
            runner_root=str(self.runner_root),
            work_folder="_work",
            runner_id=7,
        )
        self.evidence = SimpleNamespace(binding=self.binding)
        self.recorder = _Recorder()
        self.builder_kwargs = {}

    def _publish(self, **kwargs):
        self.assertEqual(
            kwargs["expected_handoff_sha256"],
            hashlib.sha256(self.HANDOFF_RAW).hexdigest(),
        )
        self.assertEqual(self.pending_path.read_bytes(), self.HANDOFF_RAW)
        self.handoff_path.write_bytes(self.HANDOFF_RAW)

    def _build(self, **kwargs):
        self.builder_kwargs = kwargs
        return self.evidence

    def _main(self, overrides=None):
        rec = self.recorder
        real_write = HANDOFF._write_exclusive
        real_require_file = HANDOFF._require_regular_nonreparse_file

        def recording_write(path, content):
            rec.events.append(f"write:{Path(path).name}")
            real_write(path, content)

        def recording_require_file(path, description):
            if Path(path) == self.handoff_path:
                rec.events.append("protected_readback")
            real_require_file(path, description)

        patches = {
            "authoritative_path": lambda name: self.evidence_root / name,
            "approval_filename": mock.Mock(return_value="approval.json"),
            "consumption_marker_path": mock.Mock(return_value=self.marker_path),
            "CONSUMPTION_ROOT": self.consumption_root,
            "parse_plan_bytes": mock.Mock(return_value=SimpleNamespace(binding=self.binding)),
            "_acl_state": mock.Mock(return_value=object()),
            "validate_approval_acl_state": mock.Mock(),
            "validate_consumption_container_acl_state": mock.Mock(),
            "validate_consumption_acl_state": mock.Mock(),
            "runner_generation_snapshot_bytes": rec.fake("generation_snapshot", b"snapshot\n"),
            "build_registration_handoff_evidence": rec.fake("build_evidence", effect=self._build),
            "_require_host_identity": rec.fake("host_identity"),
            "_require_controller_source_exact": rec.fake("controller_source"),
            "_require_remote_binding_exact": rec.fake("remote_binding"),
            "registration_handoff_bytes": mock.Mock(return_value=self.HANDOFF_RAW),
            "_write_exclusive": recording_write,
            "_publish_protected_handoff": rec.fake("publish", effect=self._publish),
            "_require_regular_nonreparse_file": recording_require_file,
        }
        patches.update(overrides or {})
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(HANDOFF, name, value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = HANDOFF.main()
        return code, stderr.getvalue()

    def test_snapshot_is_frozen_into_evidence_and_readback_precedes_publication(self):
        code, stderr = self._main()
        self.assertEqual(code, 0, stderr)
        rec = self.recorder
        pending = f"write:{self.pending_path.name}"
        order = [
            "generation_snapshot",
            "build_evidence",
            "host_identity",
            "controller_source",
            "remote_binding",
            pending,
            "publish",
            "protected_readback",
        ]
        positions = [rec.index(step) for step in order]
        self.assertEqual(positions, sorted(positions), rec.events)
        self.assertEqual(
            self.builder_kwargs["runner_generation_snapshot_bytes"],
            b"snapshot\n",
        )
        self.assertEqual(self.handoff_path.read_bytes(), self.HANDOFF_RAW)
        self.assertFalse(self.pending_path.exists())

    def test_fresh_readback_failure_blocks_before_pending_write_or_publication(self):
        for check in (
            "_require_host_identity",
            "_require_controller_source_exact",
            "_require_remote_binding_exact",
        ):
            with self.subTest(check=check):
                self.setUp()
                failing = mock.Mock(side_effect=RuntimeError(f"{check} drift"))
                code, stderr = self._main({check: failing})
                self.assertEqual(code, 2)
                self.assertIn(f"BLOCKED: {check} drift", stderr)
                self.assertFalse(self.pending_path.exists())
                self.assertNotIn("publish", self.recorder.events)
                self.assertFalse(self.handoff_path.exists())

    def test_protected_handoff_that_differs_from_pending_bytes_is_rejected(self):
        def publish_different(**kwargs):
            self.recorder.events.append("publish")
            self.handoff_path.write_bytes(b'{"registration": "other"}\n')

        code, stderr = self._main({"_publish_protected_handoff": publish_different})
        self.assertEqual(code, 2)
        self.assertIn("changed during publication", stderr)

    def test_existing_output_is_never_overwritten(self):
        self.handoff_path.write_bytes(b"previous\n")
        code, stderr = self._main()
        self.assertEqual(code, 2)
        self.assertIn("do not overwrite automatically", stderr)
        self.assertEqual(self.handoff_path.read_bytes(), b"previous\n")
        self.assertNotIn("build_evidence", self.recorder.events)


if __name__ == "__main__":
    unittest.main()
