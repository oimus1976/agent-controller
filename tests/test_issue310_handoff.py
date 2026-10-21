"""Portable prospective-byte tests. No API call, real proposal or target access."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import issue310_handoff as bridge


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts/Issue310-ExactHandoff.ps1"
CANDIDATE = ROOT / "docs/operations/issue-305-target-context/Issue305-TargetContextProbe.ps1"


def pin(path, raw):
    path.write_bytes(raw)
    return dict(path=str(path), bytes=len(raw), sha256=bridge.digest(raw))


def proposal(candidate_path):
    b = dict(
        host="WOBBUFFET", broker_identity=r"WOBBUFFET\c-admin", broker_sid=bridge.BROKER_SID,
        target_identity=r"WOBBUFFET\ac-runner", target_sid=bridge.TARGET_SID,
        profile_path=r"C:\Users\ac-runner", broker_runtime="5.1.26100.9711",
        broker_non_elevated=True, broker_x64=True, candidate_sha256=bridge.CANDIDATE_SHA,
        candidate_size=32421, candidate_path=str(candidate_path),
        working_directory=r"C:\WINDOWS\System32\WindowsPowerShell\v1.0",
        executable=dict(path=r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", sha256=bridge.PS_SHA),
        not_before_utc="2099-01-01T00:00:00Z", expires_utc="2099-01-01T00:10:00Z",
    )
    return dict(schema="issue305.decision-b-plan.NON_EXECUTABLE.v2", operation_id=bridge.OPERATION,
                repository="oimus1976/agent-controller", decision_a_status="APPROVED_UNUSED",
                a_binding_delta="APPROVED", decision_b=False, execution_authorized=False,
                live_binding=None, prospective_operation_binding=b)


def fixture(directory):
    candidate = CANDIDATE.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    candidate_pin = pin(directory / "candidate.ps1", candidate)
    p = proposal(directory / "candidate.ps1")
    spec = dict(schema="issue310.preparation.v1",
                proposal=pin(directory / "proposal.json", bridge.encode(p)),
                baseline=pin(directory / "baseline.json", bridge.encode({"synthetic": True})),
                candidate=candidate_pin, entry=pin(directory / "entry.ps1", ENTRY.read_bytes()),
                authority=dict(main_sha="a" * 40, a_body_sha256="b" * 64, delta_body_sha256="c" * 64,
                               latest216=1, latest195=2),
                packet_path=str(directory / "packet.json"), plan_path=str(directory / "plan.json"))
    return p, spec


class Issue310PreparationTests(unittest.TestCase):
    def test_exact_deterministic_prospective_bytes_preserve_source(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            p, spec = fixture(Path(temp))
            before = Path(spec["proposal"]["path"]).read_bytes()
            first = bridge.assemble(spec)
            self.assertEqual(first, bridge.assemble(copy.deepcopy(spec)))
            live, packet = map(json.loads, first)
            self.assertEqual(live["schema"], "issue305.target-context-live.v1")
            self.assertTrue(live["decision_a"])
            self.assertTrue(live["decision_b"])
            self.assertFalse(packet["authority_granted"])
            self.assertEqual(packet["proposal"], spec["proposal"])
            self.assertEqual(packet["plan"]["sha256"], bridge.digest(first[0]))
            self.assertEqual(before, Path(spec["proposal"]["path"]).read_bytes())
            self.assertFalse(p["execution_authorized"])
            self.assertNotIn(b"\r", first[0])
            self.assertTrue(first[0].endswith(b"\n"))

    def test_patch_rename_or_forged_flags_do_not_supply_authority(self):
        for key, value in (("decision_b", True), ("decision_b", "false"),
                           ("execution_authorized", True), ("live_binding", {}),
                           ("decision_a_status", "CONSUMED"), ("a_binding_delta", "UNKNOWN"),
                           ("schema", "issue305.target-context-live.v1")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                p = proposal(Path("fixture")); p[key] = value
                bridge.prospective_plan(p)

    def test_exact_a_delta_identity_runtime_and_bounds(self):
        for key, value in (("target_sid", "S-1-5-21-1-2-3-1007"), ("host", "FAKE"),
                           ("broker_sid", "FAKE"), ("broker_x64", 1), ("candidate_sha256", "0" * 64),
                           ("broker_runtime", "5.1.999"), ("working_directory", r"C:\temp"),
                           ("expires_utc", "2099-01-01T00:10:01Z"), ("expires_utc", "2099-01-01T00:03:00Z")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                p = proposal(Path("fixture")); p["prospective_operation_binding"][key] = value
                bridge.prospective_plan(p)

    def test_raw_sha_size_and_source_are_never_silently_rehashed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            _, spec = fixture(Path(temp))
            for key in ("proposal", "baseline", "candidate", "entry"):
                for field, value in (("sha256", "0" * 64), ("bytes", 1)):
                    changed = copy.deepcopy(spec); changed[key][field] = value
                    with self.subTest(key=key, field=field), self.assertRaises(ValueError):
                        bridge.assemble(changed)

    def test_no_production_candidate_or_renderer_diff(self):
        raw = CANDIDATE.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        self.assertEqual((bridge.digest(raw), len(raw)), (bridge.CANDIDATE_SHA, 32421))
        text = ENTRY.read_text()
        for forbidden in ("Remove-Item", "Set-Acl", "RegLoadKey", "RegUnLoadKey", "-Verb RunAs", "Register-ScheduledTask", "PHASE0_PASS"):
            self.assertNotIn(forbidden, text)
        self.assertIn("[IO.FileMode]::CreateNew", text)
        self.assertIn("$Plan 180", text)
        self.assertIn("performed_via_github_app", text)


if __name__ == "__main__":
    unittest.main()
