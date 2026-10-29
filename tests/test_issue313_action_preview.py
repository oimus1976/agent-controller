"""Synthetic-only #313 preview tests: no host, API, credential or effect."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import issue313_action_preview as adapter


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def fixture():
    plan = {
        "schema": "issue305.target-context-live.v1", "host": "FAKE_HOST",
        "broker_identity": "FAKE_BROKER", "target_sid": "FAKE_SID",
        "profile_path": "FAKE_PROFILE", "executable": "FAKE_EXE",
        "executable_sha256": "a" * 64, "working_directory": "FAKE_WORKDIR",
        "candidate_sha256": "b" * 64, "candidate_size": 32,
        "decision_a": True, "decision_b": True,
        "not_before_utc": "2026-01-01T00:00:00Z",
        "expires_utc": "2026-01-01T00:10:00Z",
    }
    raw_plan = encode(plan)
    packet = {
        "schema": "issue310.prospective-handoff.v1",
        "operation_id": adapter.OPERATION, "authority_granted": False,
        "authority": {"main_sha": "c" * 40},
        "plan": {"path": "FAKE_PLAN", "sha256": hashlib.sha256(raw_plan).hexdigest(), "bytes": len(raw_plan)},
        "candidate": {"sha256": "b" * 64, "bytes": 32},
        "invocation": "UNTRUSTED_EXAMPLE_SHOULD_NOT_APPEAR",
        "claim_path": "FAKE_CLAIM_SHOULD_NOT_APPEAR",
    }
    return packet, plan


class ActionPreviewTests(unittest.TestCase):
    def test_valid_prospective_pair_is_deterministic_and_never_authorizes(self):
        packet, plan = fixture()
        a = adapter.preview(encode(packet), encode(plan))
        b = adapter.preview(encode(packet), encode(plan))
        self.assertEqual(a, b)
        self.assertEqual(a["status"], "PREVIEW_ONLY_NO_AUTHORITY")
        self.assertFalse(a["human_consent_verified"])
        self.assertFalse(a["native_freshness_verified"])
        self.assertFalse(a["execution_authorized"])
        self.assertEqual(a["next_human_action"], "UNAVAILABLE_UNTIL_TRUSTED_LOCAL_ENTRY_REVIEWED")
        text = json.dumps(a, ensure_ascii=False)
        for forbidden in ("FAKE_HOST", "FAKE_SID", "FAKE_PLAN", "FAKE_CLAIM", "UNTRUSTED_EXAMPLE", "FAKE_EXE"):
            self.assertNotIn(forbidden, text)

    def test_packet_tampering_or_authority_claim_is_rejected(self):
        packet, plan = fixture()
        for key, value in (("schema", "other"), ("operation_id", "other"),
                           ("authority_granted", True), ("authority_granted", "false")):
            with self.subTest(key=key), self.assertRaises(adapter.PreviewRejected):
                changed = copy.deepcopy(packet)
                changed[key] = value
                adapter.preview(encode(changed), encode(plan))

    def test_plan_pin_or_candidate_drift_rejected(self):
        packet, plan = fixture()
        for key, value in (("sha256", "0" * 64), ("bytes", 0), ("bytes", "100")):
            with self.subTest(key=key), self.assertRaises(adapter.PreviewRejected):
                changed = copy.deepcopy(packet)
                changed["plan"][key] = value
                adapter.preview(encode(changed), encode(plan))
        changed = copy.deepcopy(packet)
        changed["candidate"]["sha256"] = "0" * 64
        with self.assertRaises(adapter.PreviewRejected):
            adapter.preview(encode(changed), encode(plan))
        with self.assertRaises(adapter.PreviewRejected):
            adapter.preview(encode(packet), encode(plan) + b" ")

    def test_plan_forged_or_malformed_rejected(self):
        packet, plan = fixture()
        for key, value in (("decision_b", False), ("decision_a", "true"),
                           ("candidate_size", True), ("schema", "unknown")):
            with self.subTest(key=key), self.assertRaises(adapter.PreviewRejected):
                changed = copy.deepcopy(plan)
                changed[key] = value
                packet2 = copy.deepcopy(packet)
                raw = encode(changed)
                packet2["plan"] = {"path": "FAKE_PLAN", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
                adapter.preview(encode(packet2), raw)
        with self.assertRaises(adapter.PreviewRejected):
            adapter.preview(b"[]\n", encode(plan))
        with self.assertRaises(adapter.PreviewRejected):
            adapter.preview(encode(packet), b"{}\r\n")

    def test_expired_or_stale_authority_is_never_promoted_to_consent(self):
        packet, plan = fixture()  # intentionally expired prospective window
        for sha in ("c" * 40, "d" * 40):
            packet["authority"]["main_sha"] = sha
            result = adapter.preview(encode(packet), encode(plan))
            self.assertFalse(result["execution_authorized"])
            self.assertFalse(result["native_freshness_verified"])

    def test_duplicate_keys_and_nonfinite_numbers_rejected(self):
        packet, plan = fixture()
        raw_packet = encode(packet)
        duplicate = raw_packet.replace(b'"authority_granted": false,', b'"authority_granted": true, "authority_granted": false,')
        with self.assertRaisesRegex(adapter.PreviewRejected, "DUPLICATE_JSON_KEY"):
            adapter.preview(duplicate, encode(plan))
        nonfinite = raw_packet.replace(b'"authority_granted": false,', b'"extra": NaN, "authority_granted": false,')
        with self.assertRaisesRegex(adapter.PreviewRejected, "NON_FINITE_JSON_NUMBER"):
            adapter.preview(nonfinite, encode(plan))

    def test_cli_is_read_only_and_prints_no_command(self):
        packet, plan = fixture()
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / "packet.json", Path(temp) / "plan.json"
            a.write_bytes(encode(packet))
            b.write_bytes(encode(plan))
            before = (a.read_bytes(), b.read_bytes(), sorted(x.name for x in Path(temp).iterdir()))
            root = Path(__file__).resolve().parents[1]
            run = subprocess.run([sys.executable, str(root / "scripts" / "issue313_action_preview.py"), str(a), str(b)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["status"], "PREVIEW_ONLY_NO_AUTHORITY")
            for forbidden in ("EXECUTE_EXACT_OWNER_B", "-BCommentId", "Start-Process", "FAKE_SID"):
                self.assertNotIn(forbidden, run.stdout)
            self.assertEqual(before, (a.read_bytes(), b.read_bytes(), sorted(x.name for x in Path(temp).iterdir())))


if __name__ == "__main__":
    unittest.main()
