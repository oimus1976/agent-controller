"""Behavior tests for scripts/create_private_ci_pilot_freeze.py.

These tests run the real ``main()`` end to end. Only the process boundary
(``gh.exe`` / ``git.exe`` / ``powershell.exe`` via ``_completed``), the
authoritative output directory, the controller tree location and the local
runner-root probe are faked. The script's own readback validation, the
workflow runner-exclusivity validator, the runner pagination readback, and the
real freeze builder and serializer all execute.

They replace source-text assertions (Issue #246 section A) that only checked
substrings or their offsets in the script source.
"""

import base64
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "create_private_ci_pilot_freeze.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "create_private_ci_pilot_freeze_behavior_under_test",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FREEZE = _load()
REPOSITORY = "oimus1976/example-private"
PR_NUMBER = 17
WORKFLOW_PATH = ".github/workflows/private-ci-windows-pilot.yml"
TARGET_SHA = "1" * 40
WORKFLOW_SHA = "2" * 40
CONTROLLER_MAIN = "3" * 40
CONTROLLER_TREE = PureWindowsPath(r"C:\Users\c-admin\agent-controller-pilot")
TRUSTED_WORKFLOW = "jobs:\n  pilot:\n    runs-on: private-ci-windows-pilot\n"
HOSTED_WORKFLOW = "jobs:\n  test:\n    runs-on: ubuntu-latest\n"


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class _Completed:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _WindowsPathProbe:
    """Stand-in for Path() on the freeze's Windows runner root.

    Evaluates Windows paths correctly on any host and never touches the real
    filesystem, so a stale local generation can be simulated deterministically.
    """

    def __init__(self, harness, value):
        self._harness = harness
        self._path = PureWindowsPath(value)

    @property
    def parent(self):
        return _WindowsPathProbe(self._harness, self._path.parent)

    def exists(self):
        self._harness.events.append("local_identity_probe")
        return str(self._path) in self._harness.existing_windows_paths


class PilotFreezeBehaviorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.evidence_root = Path(temporary.name)
        self.output = self.evidence_root / FREEZE.PILOT_FREEZE_FILENAME
        self.events = []
        self.existing_windows_paths = set()
        self.local = {
            "host": "WOBBUFFET",
            "broker_identity": r"WOBBUFFET\c-admin",
            "target_enabled": True,
            "target_admin": False,
            "runner_process_count": 0,
            "runner_service_count": 0,
            "runner_task_count": 0,
        }
        self.git = {
            "rev-parse": _Completed(stdout=CONTROLLER_MAIN + "\n"),
            "status": _Completed(stdout=""),
            "ls-remote": _Completed(stdout=f"{CONTROLLER_MAIN}\trefs/heads/main\n"),
        }
        self.github = {
            f"repos/{REPOSITORY}": {"visibility": "private", "default_branch": "main"},
            f"repos/{REPOSITORY}/pulls/{PR_NUMBER}": {
                "state": "open",
                "draft": True,
                "head": {"sha": TARGET_SHA, "repo": {"full_name": REPOSITORY}},
                "base": {"ref": "main"},
            },
            f"repos/{REPOSITORY}/branches/main": {"commit": {"sha": WORKFLOW_SHA}},
            f"repos/{REPOSITORY}/contents/{WORKFLOW_PATH}?ref={WORKFLOW_SHA}": {
                "type": "file",
                "path": WORKFLOW_PATH,
                "encoding": "base64",
                "content": _b64(TRUSTED_WORKFLOW),
            },
            f"repos/{REPOSITORY}/contents/.github/workflows?ref={WORKFLOW_SHA}": [
                {"type": "file", "path": WORKFLOW_PATH},
                {"type": "file", "path": ".github/workflows/tests.yml"},
            ],
            f"repos/{REPOSITORY}/contents/.github/workflows/tests.yml?ref={WORKFLOW_SHA}": {
                "type": "file",
                "path": ".github/workflows/tests.yml",
                "encoding": "base64",
                "content": _b64(HOSTED_WORKFLOW),
            },
            f"repos/{REPOSITORY}/actions/runners?per_page=100": {
                "total_count": 1,
                "runners": [
                    {
                        "id": 41,
                        "name": "unrelated-runner",
                        "os": "Linux",
                        "status": "offline",
                        "busy": False,
                        "labels": [{"name": "self-hosted"}, {"name": "linux"}],
                    }
                ],
            },
        }

    # -- fake process boundary -------------------------------------------

    def _completed(self, *command, cwd=None):
        program = command[0]
        if program == "gh.exe":
            endpoint = command[2]
            self.events.append(f"gh:{endpoint.split('?')[0]}")
            if endpoint not in self.github:
                return _Completed(returncode=1)
            return _Completed(stdout=json.dumps(self.github[endpoint]))
        if program == "git.exe":
            verb = next(part for part in command[1:] if part in self.git)
            self.events.append(f"git:{verb}")
            return self.git[verb]
        if program == "powershell.exe":
            self.events.append("local_zero_residual")
            return _Completed(stdout=json.dumps(self.local))
        raise AssertionError(f"unexpected process: {command}")

    def _main(self, argv=None):
        argv = argv or [
            "--repository", REPOSITORY,
            "--pull-request-number", str(PR_NUMBER),
            "--workflow-path", WORKFLOW_PATH,
        ]
        stdout, stderr = io.StringIO(), io.StringIO()
        patches = {
            "_completed": self._completed,
            "authoritative_path": lambda name: self.evidence_root / name,
            "_controller_repo_root": lambda: CONTROLLER_TREE,
            "Path": lambda value: _WindowsPathProbe(self, value),
        }
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(FREEZE, name, value))
            stack.enter_context(mock.patch.object(FREEZE.sys, "argv", [str(SCRIPT), *argv]))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = FREEZE.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def _index(self, event_name):
        # Exact match: a prefix match would let the trusted workflow file read
        # (".../contents/.github/workflows/<file>") stand in for the later
        # workflow inventory read and silently weaken the ordering check.
        try:
            return self.events.index(event_name)
        except ValueError:
            raise AssertionError(f"{event_name!r} not in {self.events}") from None

    # -- tests ------------------------------------------------------------

    def test_freeze_is_written_once_after_all_fresh_readbacks_in_order(self):
        code, stdout, stderr = self._main()
        self.assertEqual(code, 0, stderr)
        order = [
            "git:rev-parse",
            "git:ls-remote",
            "local_zero_residual",
            f"gh:repos/{REPOSITORY}/pulls/{PR_NUMBER}",
            f"gh:repos/{REPOSITORY}/contents/.github/workflows",
            "local_identity_probe",
            f"gh:repos/{REPOSITORY}/actions/runners",
        ]
        positions = [self._index(step) for step in order]
        self.assertEqual(positions, sorted(positions), self.events)
        self.assertTrue(self.output.is_file())
        self.assertIn("PILOT_IDENTITY_FREEZE_CREATED", stdout)
        self.assertIn("NO_RUNNER_REGISTRATION_OR_WORKFLOW_DISPATCH_PERFORMED", stdout)

    def test_target_and_workflow_sha_come_from_fresh_readback(self):
        code, _, stderr = self._main()
        self.assertEqual(code, 0, stderr)
        frozen = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(frozen["target_sha"], TARGET_SHA)
        self.assertEqual(frozen["workflow_sha"], WORKFLOW_SHA)
        self.assertEqual(frozen["controller_main_sha"], CONTROLLER_MAIN)
        self.assertEqual(frozen["controller_tree"], str(CONTROLLER_TREE))

    def test_caller_cannot_supply_target_or_workflow_sha(self):
        for flag in ("--target-sha", "--workflow-sha"):
            with self.subTest(flag=flag):
                self.events.clear()
                with self.assertRaises(SystemExit) as raised, \
                        contextlib.redirect_stderr(io.StringIO()):
                    self._main([
                        "--repository", REPOSITORY,
                        "--pull-request-number", str(PR_NUMBER),
                        "--workflow-path", WORKFLOW_PATH,
                        flag, "f" * 40,
                    ])
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(self.events, [])
                self.assertFalse(self.output.exists())

    def test_each_run_generates_a_fresh_identity(self):
        first_code, _, _ = self._main()
        first = json.loads(self.output.read_text(encoding="utf-8"))
        self.output.unlink()
        second_code, _, _ = self._main()
        second = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual((first_code, second_code), (0, 0))
        self.assertNotEqual(first["runner_name"], second["runner_name"])
        self.assertNotEqual(first["environment_generation"], second["environment_generation"])

    def test_existing_freeze_is_never_overwritten_and_nothing_is_read(self):
        self.output.write_bytes(b"previous\n")
        code, _, stderr = self._main()
        self.assertEqual(code, 2)
        self.assertIn("already exists; do not overwrite automatically", stderr)
        self.assertEqual(self.output.read_bytes(), b"previous\n")
        self.assertEqual(self.events, [])

    def _assert_blocked(self, message):
        code, stdout, stderr = self._main()
        self.assertEqual(code, 2, stdout)
        self.assertIn(message, stderr)
        self.assertFalse(self.output.exists())
        self.assertNotIn("PILOT_IDENTITY_FREEZE_CREATED", stdout)

    def test_controller_not_current_clean_main_blocks_before_any_other_readback(self):
        cases = {
            "dirty tree": ("status", _Completed(stdout=" M scripts/x.py\n"), "controller tree not clean"),
            "stale head": ("ls-remote", _Completed(stdout=f"{'4' * 40}\trefs/heads/main\n"), "HEAD is not current main"),
            "git failure": ("rev-parse", _Completed(returncode=128), "readback failed: controller-head"),
        }
        for label, (verb, result, message) in cases.items():
            with self.subTest(case=label):
                self.setUp()
                self.git[verb] = result
                self._assert_blocked(message)
                self.assertNotIn("local_zero_residual", self.events)
                self.assertFalse(any(e.startswith("gh:") for e in self.events))

    def test_local_residual_or_identity_mismatch_blocks_before_github_readback(self):
        cases = {
            "wrong host": ("host", "OTHER-HOST", "host mismatch"),
            "wrong broker": ("broker_identity", r"WOBBUFFET\someone", "broker identity mismatch"),
            "target disabled": ("target_enabled", False, "target identity is not enabled"),
            "target is admin": ("target_admin", True, "target identity is admin or uncertain"),
            "admin uncertain": ("target_admin", None, "target identity is admin or uncertain"),
            "runner process": ("runner_process_count", 1, "residual state present: runner_process_count"),
            "runner service": ("runner_service_count", 1, "residual state present: runner_service_count"),
            "runner task": ("runner_task_count", 1, "residual state present: runner_task_count"),
        }
        for label, (field, value, message) in cases.items():
            with self.subTest(case=label):
                self.setUp()
                self.local[field] = value
                self._assert_blocked(message)
                self.assertFalse(any(e.startswith("gh:") for e in self.events))

    def test_target_boundary_violations_block(self):
        pr_key = f"repos/{REPOSITORY}/pulls/{PR_NUMBER}"
        workflow_key = f"repos/{REPOSITORY}/contents/{WORKFLOW_PATH}?ref={WORKFLOW_SHA}"

        def set_pr(**changes):
            return lambda: self.github[pr_key].update(changes)

        cases = {
            "public repository": (
                lambda: self.github[f"repos/{REPOSITORY}"].update(visibility="public"),
                "repository boundary invalid",
            ),
            "PR not draft": (set_pr(draft=False), "PR boundary invalid"),
            "PR closed": (set_pr(state="closed"), "PR boundary invalid"),
            "fork head": (set_pr(head={"sha": TARGET_SHA, "repo": {"full_name": "attacker/fork"}}), "PR boundary invalid"),
            "non-main base": (set_pr(base={"ref": "release"}), "PR boundary invalid"),
            "workflow path mismatch": (
                lambda: self.github[workflow_key].update(path=".github/workflows/other.yml"),
                "workflow path invalid",
            ),
        }
        for label, (mutate, message) in cases.items():
            with self.subTest(case=label):
                self.setUp()
                mutate()
                self._assert_blocked(message)
                self.assertNotIn(f"gh:repos/{REPOSITORY}/actions/runners", self.events)

    def test_competing_or_dynamic_workflow_runner_blocks(self):
        other = f"repos/{REPOSITORY}/contents/.github/workflows/tests.yml?ref={WORKFLOW_SHA}"
        for label, source in (
            ("competing pilot label", "jobs:\n  steal:\n    runs-on: private-ci-windows-pilot\n"),
            ("dynamic runner", "jobs:\n  dyn:\n    runs-on: ${{ inputs.runner }}\n"),
            ("generic self-hosted", "jobs:\n  sh:\n    runs-on: self-hosted\n"),
        ):
            with self.subTest(case=label):
                self.setUp()
                self.github[other]["content"] = _b64(source)
                self._assert_blocked("workflow runner exclusivity invalid")
                self.assertNotIn(f"gh:repos/{REPOSITORY}/actions/runners", self.events)

    def test_stale_local_generation_blocks_before_remote_runner_check(self):
        def mark_generation_existing(*args, **kwargs):
            freeze = real_build(*args, **kwargs)
            self.existing_windows_paths.add(str(PureWindowsPath(freeze.runner_root).parent))
            return freeze

        real_build = FREEZE.build_fresh_pilot_identity_freeze
        with mock.patch.object(FREEZE, "build_fresh_pilot_identity_freeze", mark_generation_existing):
            self._assert_blocked("generated local identity already exists")
        self.assertNotIn(f"gh:repos/{REPOSITORY}/actions/runners", self.events)

    def test_stale_eligible_remote_runner_blocks_write(self):
        runners_key = f"repos/{REPOSITORY}/actions/runners?per_page=100"
        self.github[runners_key]["runners"][0]["labels"] = [
            {"name": "self-hosted"},
            {"name": "private-ci-windows-pilot"},
        ]
        self._assert_blocked("stale eligible pilot runner exists")
        self.assertIn(f"gh:repos/{REPOSITORY}/actions/runners", self.events)


if __name__ == "__main__":
    unittest.main()
