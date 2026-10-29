"""Read-only #313 action-card preview for a prospective #310 packet.

This module never establishes human consent, reads GitHub/native state, creates a
claim, or starts the diagnostic. In particular, its output is NOT an execution
admission token. The only effect of the CLI is printing non-secret JSON.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

OPERATION = "issue305-target-context-diagnostic-20261011-01"
MAX_INPUT_BYTES = 256 * 1024
PLAN_KEYS = {
    "schema", "host", "broker_identity", "target_sid", "profile_path",
    "executable", "executable_sha256", "working_directory",
    "candidate_sha256", "candidate_size", "decision_a", "decision_b",
    "not_before_utc", "expires_utc",
}


class PreviewRejected(ValueError):
    """The proposed bytes are not a recognizable non-authorizing #310 pair."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PreviewRejected("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(value):
    raise PreviewRejected("NON_FINITE_JSON_NUMBER")


def _parse(raw, label):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
        raise PreviewRejected(label + "_BYTES")
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise PreviewRejected(label + "_ENCODING")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreviewRejected(label + "_JSON") from exc
    if type(value) is not dict:
        raise PreviewRejected(label + "_OBJECT")
    return value


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def preview(packet_raw, plan_raw):
    """Return a non-authorizing, non-sensitive card from explicitly supplied bytes.

    This is only internal consistency checking. Source provenance, native
    freshness, owner presence, and authority remain UNKNOWN regardless of input.
    """
    packet = _parse(packet_raw, "PACKET")
    plan = _parse(plan_raw, "PLAN")
    if (packet.get("schema") != "issue310.prospective-handoff.v1"
            or packet.get("operation_id") != OPERATION
            or packet.get("authority_granted") is not False):
        raise PreviewRejected("NOT_NON_EXECUTABLE_PACKET")
    pin = packet.get("plan")
    if (type(pin) is not dict or set(pin) != {"path", "sha256", "bytes"}
            or type(pin["path"]) is not str
            or type(pin["bytes"]) is not int
            or pin["bytes"] != len(plan_raw)
            or pin["sha256"] != _digest(plan_raw)):
        raise PreviewRejected("PLAN_PIN_DRIFT")
    if (set(plan) != PLAN_KEYS
            or plan.get("schema") != "issue305.target-context-live.v1"
            or plan.get("decision_a") is not True
            or plan.get("decision_b") is not True
            or type(plan.get("candidate_size")) is not int
            or plan["candidate_size"] <= 0
            or not isinstance(plan.get("candidate_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", plan["candidate_sha256"])):
        raise PreviewRejected("PROSPECTIVE_PLAN_SHAPE")
    candidate = packet.get("candidate")
    if (type(candidate) is not dict
            or candidate.get("sha256") != plan["candidate_sha256"]
            or type(candidate.get("bytes")) is not int
            or candidate["bytes"] != plan["candidate_size"]):
        raise PreviewRejected("CANDIDATE_PIN_DRIFT")
    authority = packet.get("authority")
    if (type(authority) is not dict
            or not isinstance(authority.get("main_sha"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", authority["main_sha"])):
        raise PreviewRejected("AUTHORITY_REFERENCE_SHAPE")

    # Never expose local paths, identities, SIDs, or invocation/credential data.
    # The true flags in the *prospective plan* are NOT a real Decision B.
    return {
        "schema": "issue313.action-preview.NON_EXECUTABLE.v1",
        "status": "PREVIEW_ONLY_NO_AUTHORITY",
        "operation": "対象ユーザーのプロファイル状態を調べる診断を1回だけ行う案",
        "scope": "診断1回のみ。再試行、修復、Phase0、runner、dispatchは対象外。",
        "risks": [
            "通常のプロファイル読み込みに伴う書き込みが生じ得る。",
            "遅延ログオンや復元状態の不確実性が残り得る。",
            "状態不明時は停止し、自動再試行・強制修復をしない。",
        ],
        "next_human_action": "UNAVAILABLE_UNTIL_TRUSTED_LOCAL_ENTRY_REVIEWED",
        "native_freshness_verified": False,
        "human_consent_verified": False,
        "execution_authorized": False,
        "packet_sha256_for_agent_trace": _digest(packet_raw),
        "plan_sha256_for_agent_trace": _digest(plan_raw),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path, help="Existing prospective packet, read only")
    parser.add_argument("plan", type=Path, help="Existing prospective plan, read only")
    args = parser.parse_args()
    card = preview(args.packet.read_bytes(), args.plan.read_bytes())
    print(json.dumps(card, ensure_ascii=True, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
