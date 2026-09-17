#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_controller.operator_step_gate import (
    PowerShellAstAttestation,
    ast_attestation_auth_message,
    authenticate_ast_attestation,
    authenticate_prior_evidence,
    configure_controller_authority,
    prior_evidence_auth_message,
)
from agent_controller.private_ci_live_registration import (
    PHASE0_OPERATION_ID,
    PHASE0_STEP_ID,
    execute_live_registration,
    frozen_live_registration_binding,
    phase0_evidence_sha256,
    render_live_registration_candidate,
)
from agent_controller.private_ci_live_registration_runtime import (
    WindowsEphemeralRegistrationRuntime,
    authoritative_path,
    build_reviewed_plan,
    canonical_json_bytes,
    parse_plan_bytes,
    plan_bytes,
    result_payload,
    validate_frozen_plan,
)
from agent_controller.private_ci_phase0_evidence import (
    Phase0Evidence,
    validate_phase0_evidence_bytes,
)

PHASE0_FILENAME = "issue216-phase0-canonical.json"
CANDIDATE_FILENAME = "issue217-live-registration-candidate.ps1"
PLAN_FILENAME = "issue217-live-registration-plan.json"
RESULT_FILENAME = "issue217-live-registration-result.json"
TRANSCRIPT_FILENAME = "issue217-live-registration.log"
HUMAN_AUTHORIZATION_METHOD = "interactive-exact-plan-sha256-confirmation"
CONSUMED_SCHEMA = "agent-controller.private-ci-live-registration-consumed.v1"

TUPLE_FIELDS = (
    "observed_effect_families",
    "automatic_variable_collisions",
    "unresolved_placeholders",
    "forbidden_convenience_paths",
)


def _completed(*command: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=None if cwd is None else str(cwd),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _controller_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _phase0_path() -> Path:
    return authoritative_path(PHASE0_FILENAME)


def _candidate_path() -> Path:
    return authoritative_path(CANDIDATE_FILENAME)


def _plan_path() -> Path:
    return authoritative_path(PLAN_FILENAME)


def _result_path() -> Path:
    return authoritative_path(RESULT_FILENAME)


def _transcript_path() -> Path:
    return authoritative_path(TRANSCRIPT_FILENAME)


def _require_repo_matches_phase0(evidence: Phase0Evidence) -> None:
    repo = _controller_repo_root()
    if str(repo).lower() != evidence.controller_tree.lower():
        raise RuntimeError("controller execution tree path does not match Phase 0 evidence")
    head = _completed("git.exe", "-C", str(repo), "rev-parse", "HEAD")
    if head.returncode != 0 or head.stdout.strip() != evidence.controller_main_sha:
        raise RuntimeError("controller execution tree HEAD drift")
    status = _completed(
        "git.exe",
        "-C",
        str(repo),
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status.returncode != 0 or status.stdout.strip():
        raise RuntimeError("controller execution tree is not clean")
    remote = _completed(
        "git.exe",
        "ls-remote",
        "https://github.com/oimus1976/agent-controller.git",
        "refs/heads/main",
    )
    if remote.returncode != 0:
        raise RuntimeError("controller GitHub main readback failed")
    remote_sha = remote.stdout.split()[0] if remote.stdout.split() else ""
    if remote_sha != evidence.controller_main_sha:
        raise RuntimeError("controller GitHub main drift")


def _gh_json(*arguments: str) -> object:
    completed = _completed("gh.exe", "api", *arguments)
    if completed.returncode != 0:
        raise RuntimeError("GitHub readback failed")
    return json.loads(completed.stdout)


def _require_frozen_target_still_exact(evidence: Phase0Evidence) -> None:
    repo = _gh_json(f"repos/{evidence.repository}")
    if type(repo) is not dict:
        raise RuntimeError("repository readback invalid")
    if repo.get("visibility") != "private" or repo.get("default_branch") != "main":
        raise RuntimeError("repository visibility/default branch drift")

    pr = _gh_json(f"repos/{evidence.repository}/pulls/{evidence.pull_request_number}")
    if type(pr) is not dict:
        raise RuntimeError("PR readback invalid")
    if pr.get("state") != "open" or pr.get("draft") is not True:
        raise RuntimeError("PR state drift")
    head = pr.get("head")
    base = pr.get("base")
    if type(head) is not dict or type(base) is not dict:
        raise RuntimeError("PR ref readback invalid")
    head_repo = head.get("repo")
    if type(head_repo) is not dict or head_repo.get("full_name") != evidence.repository:
        raise RuntimeError("PR head repository drift")
    if head.get("sha") != evidence.pull_request_head_sha or base.get("ref") != "main":
        raise RuntimeError("PR exact-head/base drift")

    branch = _gh_json(f"repos/{evidence.repository}/branches/main")
    if type(branch) is not dict or type(branch.get("commit")) is not dict:
        raise RuntimeError("trusted workflow branch readback invalid")
    if branch["commit"].get("sha") != evidence.workflow_sha:
        raise RuntimeError("trusted workflow SHA drift")

    runners = _gh_json(f"repos/{evidence.repository}/actions/runners?per_page=100")
    if type(runners) is not dict or type(runners.get("runners")) is not list:
        raise RuntimeError("runner readback invalid")
    matching = []
    for runner in runners["runners"]:
        if type(runner) is not dict or type(runner.get("labels")) is not list:
            raise RuntimeError("runner readback item invalid")
        labels = {
            item.get("name")
            for item in runner["labels"]
            if type(item) is dict and type(item.get("name")) is str
        }
        if evidence.runner_label in labels or runner.get("name") == evidence.runner_name:
            matching.append(runner)
    if matching:
        raise RuntimeError("pilot runner already registered before live authorization")


def _powershell_attestation(candidate_path: Path, spec_sha256: str, ast_key: bytes):
    producer = _controller_repo_root() / "scripts" / "Invoke-PrivateCiAstAttestation.ps1"
    completed = _completed(
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(producer),
        "-CandidatePath",
        str(candidate_path),
        "-SpecSha256",
        spec_sha256,
    )
    if completed.returncode != 0:
        raise RuntimeError("PowerShell AST producer failed")
    raw = json.loads(completed.stdout)
    if type(raw) is not dict:
        raise RuntimeError("PowerShell AST producer output invalid")
    for field in TUPLE_FIELDS:
        value = raw.get(field)
        if type(value) is list:
            raw[field] = tuple(value)
    report = PowerShellAstAttestation(**raw)
    tag = hmac.new(ast_key, ast_attestation_auth_message(report), hashlib.sha256).hexdigest()
    return authenticate_ast_attestation(report, auth_tag=tag)


def _configure_authority() -> tuple[bytes, bytes]:
    ast_key = secrets.token_bytes(32)
    evidence_key = secrets.token_bytes(32)
    configure_controller_authority(
        ast_hmac_key=ast_key,
        evidence_hmac_key=evidence_key,
    )
    return ast_key, evidence_key


def _authenticate_phase0(
    evidence: Phase0Evidence,
    evidence_bytes: bytes,
    evidence_key: bytes,
):
    evidence_sha = phase0_evidence_sha256(evidence_bytes)
    message = prior_evidence_auth_message(
        repository=evidence.repository,
        pull_request_number=evidence.pull_request_number,
        target_sha=evidence.pull_request_head_sha,
        producer_operation_id=PHASE0_OPERATION_ID,
        producer_step_id=PHASE0_STEP_ID,
        evidence_sha256=evidence_sha,
    )
    tag = hmac.new(evidence_key, message, hashlib.sha256).hexdigest()
    return authenticate_prior_evidence(
        repository=evidence.repository,
        pull_request_number=evidence.pull_request_number,
        target_sha=evidence.pull_request_head_sha,
        producer_operation_id=PHASE0_OPERATION_ID,
        producer_step_id=PHASE0_STEP_ID,
        evidence_bytes=evidence_bytes,
        auth_tag=tag,
    )


def _write_exclusive(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _consumed_marker_path(plan_sha: str) -> Path:
    return authoritative_path(f"issue217-live-registration-{plan_sha}.consumed.json")


def _acquire_apply_ownership(plan_sha: str, phase0_sha: str) -> None:
    payload = {
        "schema": CONSUMED_SCHEMA,
        "plan_sha256": plan_sha,
        "phase0_evidence_sha256": phase0_sha,
        "consumed_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        _write_exclusive(_consumed_marker_path(plan_sha), canonical_json_bytes(payload))
    except FileExistsError as error:
        raise RuntimeError("live apply ownership already claimed") from error


def _require_live_outputs_absent(plan_sha: str) -> None:
    for path in (
        _result_path(),
        _transcript_path(),
        _consumed_marker_path(plan_sha),
    ):
        if path.exists():
            raise RuntimeError(f"live registration output already exists: {path.name}")


def _require_interactive_human_authorization(
    expected_plan_sha256: str,
    *,
    stdin=None,
    stdout=None,
) -> None:
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    if not input_stream.isatty() or not output_stream.isatty():
        raise RuntimeError("human authorization requires an interactive controlling terminal")
    output_stream.write("\n#216 LIVE REGISTRATION HUMAN AUTHORIZATION\n")
    output_stream.write("Review the exact plan SHA-256 below before authorizing:\n")
    output_stream.write(expected_plan_sha256 + "\n")
    output_stream.write("To authorize this exact plan, type the exact plan SHA-256 and press Enter:\n> ")
    output_stream.flush()
    confirmation = input_stream.readline()
    if confirmation == "":
        raise RuntimeError("human authorization confirmation unavailable")
    if confirmation.rstrip("\r\n") != expected_plan_sha256:
        raise RuntimeError("human authorization confirmation mismatch")


def command_plan() -> int:
    phase0_bytes = _phase0_path().read_bytes()
    evidence = validate_phase0_evidence_bytes(phase0_bytes)
    _require_repo_matches_phase0(evidence)
    _require_frozen_target_still_exact(evidence)

    ast_key, _ = _configure_authority()
    binding = frozen_live_registration_binding()
    candidate = render_live_registration_candidate(binding)
    candidate_path = _candidate_path()
    plan_path = _plan_path()
    if candidate_path.exists() or plan_path.exists():
        raise RuntimeError("plan artifacts already exist; do not overwrite automatically")
    _write_exclusive(candidate_path, candidate.encode("utf-8"))

    evidence_sha = phase0_evidence_sha256(phase0_bytes)
    from agent_controller.private_ci_live_registration import build_live_registration_spec
    spec = build_live_registration_spec(binding, phase0_evidence_sha256=evidence_sha)
    from agent_controller.operator_step_gate import operator_step_spec_sha256
    ast = _powershell_attestation(
        candidate_path,
        operator_step_spec_sha256(spec),
        ast_key,
    )
    plan = build_reviewed_plan(
        phase0_evidence_bytes=phase0_bytes,
        ast_attestation=ast,
    )
    raw_plan = plan_bytes(plan)
    _write_exclusive(plan_path, raw_plan)
    digest = hashlib.sha256(raw_plan).hexdigest()

    print("PASS_TO_OPERATOR")
    print(f"plan={plan_path}")
    print(f"plan_sha256={digest}")
    print(f"candidate_sha256={plan.candidate_sha256}")
    print(f"phase0_evidence_sha256={plan.phase0_evidence_sha256}")
    print("NO_LIVE_PILOT_EFFECT_PERFORMED")
    return 0


def command_apply(expected_plan_sha256: str) -> int:
    if (
        len(expected_plan_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_plan_sha256)
    ):
        raise RuntimeError("expected plan SHA-256 invalid")

    plan_raw = _plan_path().read_bytes()
    actual_plan_sha = hashlib.sha256(plan_raw).hexdigest()
    if actual_plan_sha != expected_plan_sha256:
        raise RuntimeError("human-authorized plan SHA-256 mismatch")
    plan = parse_plan_bytes(plan_raw)

    _require_interactive_human_authorization(actual_plan_sha)

    phase0_bytes = _phase0_path().read_bytes()
    evidence = validate_phase0_evidence_bytes(phase0_bytes)
    reasons = validate_frozen_plan(plan, phase0_evidence_bytes=phase0_bytes)
    if reasons:
        raise RuntimeError("live plan drift: " + ",".join(reasons))
    _require_repo_matches_phase0(evidence)
    _require_frozen_target_still_exact(evidence)
    _require_live_outputs_absent(actual_plan_sha)

    candidate_path = _candidate_path()
    if candidate_path.read_text(encoding="utf-8") != plan.candidate:
        raise RuntimeError("candidate artifact drift")

    ast_key, evidence_key = _configure_authority()
    ast = _powershell_attestation(candidate_path, plan.spec_sha256, ast_key)
    prior = _authenticate_phase0(evidence, phase0_bytes, evidence_key)
    runtime = WindowsEphemeralRegistrationRuntime(plan.binding)

    _acquire_apply_ownership(
        actual_plan_sha,
        plan.phase0_evidence_sha256,
    )

    started_at = datetime.now(timezone.utc).isoformat()
    result = execute_live_registration(
        plan.binding,
        phase0_evidence_bytes=phase0_bytes,
        candidate=plan.candidate,
        ast_attestation=ast,
        prior_evidence_capability=prior,
        prepare_runner=runtime.prepare_runner,
        acquire_registration_token=runtime.acquire_registration_token,
        run_registration=runtime.run_registration,
        credential_handoff_cleared=runtime.credential_handoff_cleared,
        read_runners=runtime.read_runners,
    )
    ended_at = datetime.now(timezone.utc).isoformat()

    payload = result_payload(
        plan=plan,
        plan_sha256_value=actual_plan_sha,
        result=result,
    )
    payload["started_at"] = started_at
    payload["ended_at"] = ended_at
    payload["human_authorization"] = HUMAN_AUTHORIZATION_METHOD
    payload["registration_token_recorded"] = False
    result_bytes = canonical_json_bytes(payload)
    _write_exclusive(_result_path(), result_bytes)

    transcript = (
        f"started_at={started_at}\n"
        f"ended_at={ended_at}\n"
        f"plan_sha256={actual_plan_sha}\n"
        f"phase0_evidence_sha256={plan.phase0_evidence_sha256}\n"
        f"candidate_sha256={result.candidate_sha256}\n"
        f"status={result.status.value}\n"
        f"reason_codes={','.join(result.reason_codes)}\n"
        f"child_exit_code={result.child_exit_code}\n"
        f"runner_id={result.runner_id}\n"
        f"human_authorization={HUMAN_AUTHORIZATION_METHOD}\n"
        "registration_token_recorded=false\n"
        "--- child stdout (redacted) ---\n"
        f"{result.stdout}\n"
        "--- child stderr (redacted) ---\n"
        f"{result.stderr}\n"
    ).encode("utf-8")
    _write_exclusive(_transcript_path(), transcript)

    print(result.status.value)
    if result.reason_codes:
        print("reason_codes=" + ",".join(result.reason_codes))
    print(f"result={_result_path()}")
    print(f"transcript={_transcript_path()}")
    return 0 if result.registered else 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded #217 private-CI live registration harness"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan")
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--expected-plan-sha256", required=True)
    options = parser.parse_args()

    try:
        if options.command == "plan":
            return command_plan()
        if options.command == "apply":
            return command_apply(options.expected_plan_sha256)
        raise RuntimeError("unsupported command")
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
