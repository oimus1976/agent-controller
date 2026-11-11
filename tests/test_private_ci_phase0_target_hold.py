"""#316 target-hold orchestration with doubles; no target logon or credential."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path, PureWindowsPath

from agent_controller import private_ci_phase0_target_hold as hold_module
from agent_controller.private_ci_phase0_collector import (
    collect_validated_phase0_evidence,
)
from agent_controller.private_ci_phase0_target_hold import (
    TargetProfileHold,
    read_target_profile_state,
    target_state_idle,
    target_state_stable,
)
from agent_controller.private_ci_pilot_identity import pilot_identity_freeze_bytes
from scripts import collect_private_ci_phase0_with_target_hold as cli
from tests.test_private_ci_phase0_collector import FakeRunner, valid_freeze

SID = "S-1-5-21-111-222-333-1007"
GOOD_REPORT = {
    "status": "TARGET_HOLD_RELEASED", "target_started": True, "ready": True,
    "release_confirmed": True, "exit_confirmed": True, "target_exit_code": 0,
    "target_pid": 4242, "stderr_empty": True,
}


def state(**changes):
    base = {
        "sid": SID, "enabled": True, "admin": False, "mounted": False,
        "loaded": False, "sessions": 0, "profile": r"C:\Users\ac-runner",
        "profile_status": 0, "account_description": "",
        "profile_acl": "O:S-1-5-21D:(A;;FA;;;SY)", "hive_acl": "O:S-1-5-21D:(A;;FA;;;SY)",
    }
    base.update(changes)
    return base


HELD = dict(mounted=True, loaded=True, sessions=1)


class States:
    """Scripted observations; the last one repeats."""

    def __init__(self, *items):
        self.items = list(items)
        self.reads = 0

    def __call__(self):
        self.reads += 1
        item = self.items.pop(0) if len(self.items) > 1 else self.items[0]
        if isinstance(item, Exception):
            raise item
        return item


class FakeHold:
    """Frames before RELEASE, then frames after it. ``Ellipsis`` = deadline."""

    def __init__(self, before, after=(), exit_code=0, hangs=False):
        self.before = list(before)
        self.after = list(after)
        self.exit_code = exit_code
        self.hangs = hangs
        self.released = False
        self.killed = False
        self.command = None

    def read_line(self, timeout):
        frames = self.after if self.released else self.before
        if not frames:
            return None
        frame = frames.pop(0)
        if frame is Ellipsis:
            raise TimeoutError
        return frame

    def send_release(self):
        self.released = True

    def wait(self, timeout):
        return None if self.hangs else self.exit_code

    def kill(self):
        self.killed = True


def report(**changes):
    return "HOLD_REPORT " + json.dumps({**GOOD_REPORT, **changes})


def good_hold(**keywords):
    return FakeHold(
        ["HOLD_AWAITING_CREDENTIAL", "HOLD_STARTING_TARGET", "HOLD_READY 4242"],
        [report()],
        **keywords,
    )


def make(process, states):
    clock = [0.0]

    def factory(command):
        process.command = command
        return process

    def sleep(seconds):
        clock[0] += seconds

    return TargetProfileHold(
        hold_script=Path(r"C:\tree\scripts\Issue316-TargetProfileHold.ps1"),
        host="WOBBUFFET", state_reader=states, process_factory=factory,
        sleep=sleep, monotonic=lambda: clock[0],
    )


class TargetStateTests(unittest.TestCase):
    def test_idle_and_stable_are_strict(self):
        self.assertTrue(target_state_idle(state()))
        for change in (HELD, {"mounted": True}, {"loaded": True}, {"sessions": 1},
                       {"enabled": False}, {"admin": True}, {"mounted": "False"}):
            self.assertFalse(target_state_idle(state(**change)), change)
        self.assertFalse(target_state_idle(None))
        self.assertTrue(target_state_stable(state(), state(**HELD)))
        for key in hold_module.STABLE_STATE_KEYS:
            self.assertFalse(target_state_stable(state(), state(**{key: "drift"})), key)
        self.assertFalse(target_state_stable(state(), None))

    def test_state_reader_rejects_failure_and_bad_shape(self):
        def runner(payload, code=0):
            return lambda *command: subprocess.CompletedProcess(command, code, payload, "")

        self.assertEqual(read_target_profile_state(runner(json.dumps(state())), "ac-runner"), state())
        bad = [runner(json.dumps(state()), 1), runner("not json"), runner("[]"),
               runner(json.dumps({**state(), "extra": 1})),
               runner(json.dumps({**state(), "mounted": "False"})),
               runner(json.dumps({key: value for key, value in state().items() if key != "loaded"}))]
        for case in bad:
            with self.assertRaises(ValueError):
                read_target_profile_state(case, "ac-runner")
        with self.assertRaises(ValueError):
            read_target_profile_state(runner("{}"), "ac-runner'; whoami")

    def test_state_reader_is_noninteractive_and_read_only(self):
        seen = []

        def runner(*command):
            seen.append(command)
            return subprocess.CompletedProcess(command, 0, json.dumps(state()), "")

        read_target_profile_state(runner, "ac-runner")
        self.assertIn("-NonInteractive", seen[0])
        script = seen[0][-1]
        for verb in ("Set-Item", "Set-Acl", "Set-LocalUser", "New-Item", "Remove-", "reg.exe", "RegLoadKey", "Start-Process", "Stop-"):
            self.assertNotIn(verb, script)


class TargetProfileHoldTests(unittest.TestCase):
    def test_success_releases_then_verifies(self):
        process = good_hold()
        hold = make(process, States(state(), state(**HELD), state(**HELD), state()))
        hold.preflight()
        hold.acquire()
        self.assertEqual(process.command[-4:], ["-TargetSid", SID, "-HostName", "WOBBUFFET"])
        self.assertNotIn("-NonInteractive", process.command)
        self.assertTrue(hold.release_and_verify())
        self.assertTrue(process.released)
        self.assertTrue(hold.outcome["clean_release"])

    def test_not_idle_blocks_before_any_process(self):
        for busy in (HELD, {"mounted": True}, {"admin": True}, {"enabled": False}):
            process = good_hold()
            hold = make(process, States(state(**busy)))
            with self.assertRaisesRegex(RuntimeError, "not idle"):
                hold.preflight()
            with self.assertRaisesRegex(RuntimeError, "preflight missing"):
                hold.acquire()
            self.assertIsNone(process.command)

    def test_single_use(self):
        hold = make(good_hold(), States(state(), state(**HELD), state()))
        hold.preflight()
        hold.acquire()
        with self.assertRaisesRegex(RuntimeError, "no retry"):
            hold.acquire()
        self.assertTrue(hold.release_and_verify())
        with self.assertRaisesRegex(RuntimeError, "no retry"):
            hold.release_and_verify()

    def test_cancelled_credential_is_no_effect_not_partial(self):
        process = FakeHold(["HOLD_AWAITING_CREDENTIAL", "HOLD_BLOCKED_NO_EFFECT"], exit_code=3)
        hold = make(process, States(state()))
        hold.preflight()
        with self.assertRaisesRegex(RuntimeError, "credential not supplied"):
            hold.acquire()
        self.assertTrue(hold.release_and_verify())
        self.assertFalse(hold.outcome["acquired"])

    def test_failed_logon_report_is_no_effect(self):
        process = FakeHold(
            ["HOLD_AWAITING_CREDENTIAL", "HOLD_STARTING_TARGET",
             report(status="TARGET_START_FAILED", target_started=False, ready=False,
                    release_confirmed=False, exit_confirmed=False, target_exit_code=None)],
            exit_code=5,
        )
        hold = make(process, States(state()))
        hold.preflight()
        with self.assertRaisesRegex(RuntimeError, "reported failure"):
            hold.acquire()
        self.assertTrue(hold.release_and_verify())

    def test_hive_not_mounted_during_hold_never_acquires(self):
        hold = make(good_hold(), States(state(), state(), state()))
        hold.preflight()
        with self.assertRaisesRegex(RuntimeError, "not observed mounted"):
            hold.acquire()
        self.assertTrue(hold.release_and_verify())  # released cleanly; nothing left
        self.assertFalse(hold.outcome["acquired"])

    def test_unverified_release_after_acquire(self):
        cases = {
            "release unconfirmed": dict(after=[report(status="RELEASE_UNCONFIRMED", release_confirmed=False)], exit_code=5),
            "target exit unknown": dict(after=[report(status="STOP_PARTIAL_PROFILE_STATE", exit_confirmed=False, target_exit_code=None)], exit_code=5),
            "target exit nonzero": dict(after=[report(target_exit_code=5)], exit_code=5),
            "target stderr": dict(after=[report(stderr_empty=False)], exit_code=5),
            "hold exit nonzero": dict(after=[report()], exit_code=1),
            "no report": dict(after=[], exit_code=0),
            "malformed report": dict(after=["HOLD_REPORT {"], exit_code=0),
            "report deadline": dict(after=[Ellipsis], exit_code=0),
        }
        for name, keywords in cases.items():
            with self.subTest(name):
                process = FakeHold(
                    ["HOLD_AWAITING_CREDENTIAL", "HOLD_STARTING_TARGET", "HOLD_READY 4242"],
                    **keywords,
                )
                hold = make(process, States(state(), state(**HELD), state()))
                hold.preflight()
                hold.acquire()
                self.assertFalse(hold.release_and_verify())

    def test_hung_hold_is_killed_and_never_verified(self):
        process = good_hold(hangs=True)
        hold = make(process, States(state(), state(**HELD), state()))
        hold.preflight()
        hold.acquire()
        self.assertFalse(hold.release_and_verify())
        self.assertTrue(process.killed)

    def test_late_logon_is_partial_even_if_poststate_looks_idle(self):
        # Target stage entered, no ready frame, hold has to be killed: an
        # immediately idle readback does not disprove an in-flight logon.
        process = FakeHold(["HOLD_AWAITING_CREDENTIAL", "HOLD_STARTING_TARGET", Ellipsis], hangs=True)
        hold = make(process, States(state()))
        hold.preflight()
        with self.assertRaisesRegex(RuntimeError, "deadline: target-ready"):
            hold.acquire()
        self.assertFalse(hold.release_and_verify())
        self.assertTrue(hold.outcome["poststate_idle"])

    def test_logon_stage_seen_only_while_draining_is_still_partial(self):
        # Credential deadline in Python, human submits at that instant, hold
        # then dies without a report: never "no effect".
        process = FakeHold(["HOLD_AWAITING_CREDENTIAL", Ellipsis], ["HOLD_STARTING_TARGET"], exit_code=1)
        hold = make(process, States(state()))
        hold.preflight()
        with self.assertRaisesRegex(RuntimeError, "deadline: credential"):
            hold.acquire()
        self.assertFalse(hold.release_and_verify())
        self.assertTrue(hold.outcome["target_stage_entered"])

    def test_credential_deadline_with_hung_dialog_is_partial(self):
        process = FakeHold(["HOLD_AWAITING_CREDENTIAL", Ellipsis], [Ellipsis], hangs=True)
        hold = make(process, States(state()))
        hold.preflight()
        with self.assertRaises(RuntimeError):
            hold.acquire()
        self.assertFalse(hold.release_and_verify())
        self.assertTrue(process.killed)

    def test_poststate_must_become_idle_and_match_baseline(self):
        for name, after in {
            "still loaded": state(**HELD),
            "hive still mounted": state(mounted=True),
            "acl drift": state(profile_acl="O:BAD"),
            "admin drift": state(admin=True),
            "unreadable": ValueError("unreadable"),
        }.items():
            with self.subTest(name):
                hold = make(good_hold(), States(state(), state(**HELD), after))
                hold.preflight()
                hold.acquire()
                self.assertFalse(hold.release_and_verify())

    def test_poststate_waits_for_delayed_unload(self):
        states = States(state(), state(**HELD), state(**HELD), state(loaded=True), state())
        hold = make(good_hold(), states)
        hold.preflight()
        hold.acquire()
        self.assertTrue(hold.release_and_verify())
        self.assertEqual(states.reads, 5)


class OneShotCliTests(unittest.TestCase):
    def invoke(self, process, states, *, collector=None, preflight_only=False, sha=None, prepare=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hold_script = root / hold_module.HOLD_SCRIPT_NAME
            hold_script.write_text("# fixture", encoding="utf-8")
            freeze = valid_freeze()
            tree = PureWindowsPath(freeze.controller_tree)
            raw = pilot_identity_freeze_bytes(freeze)
            freeze_path = root / "freeze.json"
            freeze_path.write_bytes(raw)
            output = root / "canonical.json"
            if prepare:
                prepare(output, freeze_path)
            lines = []
            events = []

            def default_collector(controller_root, *, pilot_freeze):
                events.append("collect")
                self.assertFalse(output.exists())
                self.assertTrue(process.command)
                return collect_validated_phase0_evidence(
                    Path(pilot_freeze.controller_tree), pilot_freeze=pilot_freeze,
                    command_runner=FakeRunner(), path_exists=lambda _: False,
                )

            def hold_factory(**keywords):
                keywords.pop("progress")
                keywords.pop("state_reader")
                def factory(command):
                    process.command = command
                    return process
                return TargetProfileHold(
                    state_reader=states, process_factory=factory,
                    sleep=lambda _seconds: None, monotonic=_Clock(), **keywords,
                )

            code = cli.run(
                sha or hashlib.sha256(raw).hexdigest(), preflight_only=preflight_only,
                hold_factory=hold_factory, collector=collector or default_collector,
                controller_root=tree, hold_script=hold_script, output=output, freeze_path=freeze_path,
                log=lines.append,
            )
            written = output.read_bytes() if output.exists() else None
            return code, lines, written, events

    def test_pass_commits_only_after_verified_release(self):
        process = good_hold()
        code, lines, written, events = self.invoke(
            process, States(state(), state(**HELD), state(**HELD), state()))
        self.assertEqual(code, 0, lines)
        self.assertEqual(events, ["collect"])
        self.assertIn("PHASE0_PASS", lines)
        self.assertIn(f"evidence_sha256={hashlib.sha256(written).hexdigest()}", lines)
        self.assertLess(lines.index("collecting strict Phase 0 v3 evidence (staged in memory)"),
                        lines.index("PHASE0_PASS"))

    def test_preflight_only_starts_nothing(self):
        process = good_hold()
        code, lines, written, events = self.invoke(process, States(state()), preflight_only=True)
        self.assertEqual((code, written, events, process.command), (0, None, [], None))
        self.assertIn("NO_EFFECT_PERFORMED", lines)

    def test_blocked_before_effect(self):
        for name, keywords in {
            "bad digest": dict(sha="0" * 64),
            "digest shape": dict(sha="XYZ"),
            "target busy": dict(states=States(state(**HELD))),
            "slot occupied": dict(prepare=lambda output, _freeze: output.write_bytes(b"old")),
            "freeze missing": dict(prepare=lambda _output, freeze: freeze.unlink()),
        }.items():
            with self.subTest(name):
                process = good_hold()
                states = keywords.pop("states", States(state()))
                code, lines, written, events = self.invoke(process, states, **keywords)
                self.assertEqual(code, cli.EXIT_BLOCKED, lines)
                self.assertIsNone(process.command)
                self.assertEqual(events, [])
                self.assertNotIn("PHASE0_PASS", lines)
                self.assertIn(written, (None, b"old"))

    def test_collection_failure_releases_and_writes_nothing(self):
        def collector(controller_root, *, pilot_freeze):
            raise ValueError("phase0 blocked: target UserPolicy unreadable")

        process = good_hold()
        code, lines, written, _ = self.invoke(
            process, States(state(), state(**HELD), state()), collector=collector)
        self.assertEqual((code, written), (cli.EXIT_BLOCKED, None))
        self.assertTrue(process.released)
        self.assertIn("BLOCKED: phase0 blocked: target UserPolicy unreadable", lines)

    def test_unverified_restoration_stops_without_evidence(self):
        process = good_hold()
        code, lines, written, events = self.invoke(
            process, States(state(), state(**HELD), state(**HELD)))
        self.assertEqual((code, written, events), (cli.EXIT_STOP_PARTIAL, None, ["collect"]))
        self.assertNotIn("PHASE0_PASS", lines)
        self.assertTrue(any(line.startswith("STOP_PARTIAL_PROFILE_STATE") for line in lines))

    def test_readback_mismatch_has_its_own_stop(self):
        def corrupting_collector(controller_root, *, pilot_freeze):
            return collect_validated_phase0_evidence(
                Path(pilot_freeze.controller_tree), pilot_freeze=pilot_freeze,
                command_runner=FakeRunner(), path_exists=lambda _: False,
            )

        original = cli.write_exclusive
        cli.write_exclusive = lambda path, content: path.write_bytes(content + b"x")
        try:
            code, lines, written, _ = self.invoke(
                good_hold(), States(state(), state(**HELD), state()), collector=corrupting_collector)
        finally:
            cli.write_exclusive = original
        self.assertEqual(code, cli.EXIT_STOP_READBACK)
        self.assertIsNotNone(written)
        self.assertNotIn("PHASE0_PASS", lines)
        self.assertNotIn("NO_PHASE0_EVIDENCE_WRITTEN", lines)

    def test_cancelled_credential_is_blocked_not_partial(self):
        process = FakeHold(["HOLD_AWAITING_CREDENTIAL", "HOLD_BLOCKED_NO_EFFECT"], exit_code=3)
        code, lines, written, events = self.invoke(process, States(state()))
        self.assertEqual((code, written, events), (cli.EXIT_BLOCKED, None, []))


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 30.0
        return self.now


if __name__ == "__main__":
    unittest.main()
