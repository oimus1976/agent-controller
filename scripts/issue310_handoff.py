"""One #305 prospective handoff. Pure preparation; never runs PowerShell/targets.

Input pins are supplied by a later read-only binding, not discovered/refreshed here.
Output true flags describe prospective bytes, never a grant of authority.
"""
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

OPERATION = "issue305-target-context-diagnostic-20261011-01"
ROOT = r"C:\Users\Public\Documents\agent-controller-handoff"
CANDIDATE_SHA = "c135d9357f0ed82cf07fd41a6a68b3a71eeebea51899a0f51c852a543b2ec571"
TARGET_SID = "S-1-5-21-3783647055-311371106-158726857-1007"
BROKER_SID = "S-1-5-21-3783647055-311371106-158726857-1002"
PS_SHA = "60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f"
INVOCATION = "& '<powershell>' -NoProfile -ExecutionPolicy Bypass -File '<entry>' -Stage EXECUTE_EXACT_OWNER_B -PacketPath '<packet>' -ExpectedPacketSha256 <packet_sha256> -BCommentId <new_human_web_comment_id>"


def encode(value):
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(pin):
    if set(pin) != {"path", "sha256", "bytes"} or type(pin["bytes"]) is not int:
        raise ValueError("PIN_SHAPE")
    raw = Path(pin["path"]).read_bytes()
    if len(raw) != pin["bytes"] or digest(raw) != pin["sha256"]:
        raise ValueError("RAW_PIN_DRIFT")
    return raw


def utc(text):
    value = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    if value.strftime("%Y-%m-%dT%H:%M:%SZ") != text:
        raise ValueError("WINDOW_FORMAT")
    return value


def prospective_plan(proposal):
    if (proposal["schema"] != "issue305.decision-b-plan.NON_EXECUTABLE.v2"
            or proposal["operation_id"] != OPERATION
            or proposal["repository"] != "oimus1976/agent-controller"
            or proposal["decision_a_status"] != "APPROVED_UNUSED"
            or proposal["a_binding_delta"] != "APPROVED"
            or proposal["decision_b"] is not False
            or proposal["execution_authorized"] is not False
            or proposal["live_binding"] is not None):
        raise ValueError("NON_EXECUTABLE_SOURCE_REQUIRED")
    b = proposal["prospective_operation_binding"]
    expected = {
        "host": "WOBBUFFET", "broker_identity": r"WOBBUFFET\c-admin",
        "broker_sid": BROKER_SID, "target_identity": r"WOBBUFFET\ac-runner",
        "target_sid": TARGET_SID, "profile_path": r"C:\Users\ac-runner",
        "broker_runtime": "5.1.26100.9711", "broker_non_elevated": True,
        "broker_x64": True, "candidate_sha256": CANDIDATE_SHA, "candidate_size": 32421,
        "working_directory": r"C:\WINDOWS\System32\WindowsPowerShell\v1.0",
    }
    for key, value in expected.items():
        if type(b[key]) is not type(value) or b[key] != value:
            raise ValueError("A_OR_DELTA_DRIFT:" + key)
    if b["executable"]["path"] != expected["working_directory"] + r"\powershell.exe" or b["executable"]["sha256"] != PS_SHA:
        raise ValueError("AMENDED_EXECUTABLE_DRIFT")
    seconds = (utc(b["expires_utc"]) - utc(b["not_before_utc"])).total_seconds()
    if not 240 <= seconds <= 600:
        raise ValueError("WINDOW_BUDGET")
    return dict(
        schema="issue305.target-context-live.v1", host=b["host"],
        broker_identity=b["broker_identity"], target_sid=b["target_sid"],
        profile_path=b["profile_path"], executable=b["executable"]["path"],
        executable_sha256=PS_SHA, working_directory=b["working_directory"],
        candidate_sha256=CANDIDATE_SHA, candidate_size=32421,
        decision_a=True, decision_b=True,
        not_before_utc=b["not_before_utc"], expires_utc=b["expires_utc"],
    )


def assemble(spec):
    if set(spec) != {"schema", "proposal", "baseline", "candidate", "entry", "authority", "packet_path", "plan_path"} or spec["schema"] != "issue310.preparation.v1":
        raise ValueError("SPEC_SHAPE")
    proposal = json.loads(read_pin(spec["proposal"]))
    baseline = json.loads(read_pin(spec["baseline"]))
    plan = prospective_plan(proposal)
    if proposal["prospective_operation_binding"]["candidate_path"] != spec["candidate"]["path"]:
        raise ValueError("CANDIDATE_PATH_DRIFT")
    if spec["candidate"]["sha256"] != CANDIDATE_SHA or spec["candidate"]["bytes"] != 32421:
        raise ValueError("CANDIDATE_PIN")
    read_pin(spec["candidate"])
    read_pin(spec["entry"])
    raw_plan = encode(plan)
    packet = dict(spec, schema="issue310.prospective-handoff.v1", operation_id=OPERATION,
                  authority_granted=False, invocation=INVOCATION,
                  plan=dict(path=spec["plan_path"], bytes=len(raw_plan), sha256=digest(raw_plan)),
                  expected_facts=baseline, broker_sid=BROKER_SID,
                  claim_path=ROOT + "\\" + OPERATION + ".claim",
                  result_path=ROOT + "\\" + OPERATION + ".handoff-result.json")
    return raw_plan, encode(packet)


def approval_text(packet, raw_packet):
    plan = json.loads(read_pin(packet["plan"]))
    return "\n".join([
        "ISSUE310 EXECUTE_EXACT_OWNER_B", "operation_id=" + OPERATION,
        "packet_sha256=" + digest(raw_packet), "packet_bytes=" + str(len(raw_packet)),
        "plan_sha256=" + packet["plan"]["sha256"], "entry_sha256=" + packet["entry"]["sha256"],
        "not_before_utc=" + plan["not_before_utc"], "expires_utc=" + plan["expires_utc"],
        "I authorize exactly one diagnostic with the pinned invocation, normal profile-load writes and residual delayed-logon risk; no retry, repair, Phase0, runner or dispatch.",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("--expected-spec-sha256", required=True)
    args = parser.parse_args()
    raw_spec = args.spec.read_bytes()
    if digest(raw_spec) != args.expected_spec_sha256:
        raise ValueError("SPEC_DIGEST")
    spec = json.loads(raw_spec)
    plan, packet = assemble(spec)
    # Never overwrite/repair or rehash an existing packet; partial output is retained.
    with Path(spec["plan_path"]).open("xb") as stream:
        stream.write(plan)
    with Path(spec["packet_path"]).open("xb") as stream:
        stream.write(packet)
    print("PREPARED_FOR_OWNER_B: prospective bytes only; authority=false")
    print("packet_sha256=" + digest(packet) + " packet_bytes=" + str(len(packet)))
    # No B/window creation, API call, credential handling or process launch.


if __name__ == "__main__":
    main()
