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
from agent_controller.private_ci_consumption_marker import (
    CONSUMPTION_ROOT,
    CONSUMPTION_SCHEMA,
    consumption_marker_path,
    parse_consumption_marker_bytes,
    validate_consumption_acl_state,
    validate_consumption_container_acl_state,
)
from agent_controller.private_ci_human_approval import (
    approval_filename,
    approval_sha256,
    parse_approval_bytes,
    validate_approval_acl_state,
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
from agent_controller.private_ci_runner_readback import read_all_runner_items

PHASE0_FILENAME = "issue216-phase0-canonical.json"
CANDIDATE_FILENAME = "issue217-live-registration-candidate.ps1"
PLAN_FILENAME = "issue217-live-registration-plan.json"
RESULT_FILENAME = "issue217-live-registration-result.json"
TRANSCRIPT_FILENAME = "issue217-live-registration.log"
HUMAN_AUTHORIZATION_METHOD = "uac-elevated-acl-protected-approval-v1"
CONSUMED_SCHEMA = CONSUMPTION_SCHEMA
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

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


def _approval_path(plan_sha256: str) -> Path:
    return authoritative_path(approval_filename(plan_sha256))


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


def _require_exact_phase0_host(evidence: Phase0Evidence) -> None:
    host = _completed("hostname.exe")
    if host.returncode != 0:
        raise RuntimeError("host readback failed")
    if host.stdout.strip().casefold() != evidence.host.casefold():
        raise RuntimeError("Phase 0 host mismatch")

    identity = _completed("whoami.exe")
    if identity.returncode != 0:
        raise RuntimeError("broker identity readback failed")
    if identity.stdout.strip().casefold() != evidence.broker_identity.casefold():
        raise RuntimeError("Phase 0 broker identity mismatch")


def _require_non_elevated_broker() -> None:
    script = r"""
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $Identity
[ordered]@{
    elevated = [bool]$Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} | ConvertTo-Json -Compress
""".strip()
    completed = _completed(
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    )
    if completed.returncode != 0:
        raise RuntimeError("broker elevation readback failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("broker elevation readback invalid") from error
    if type(payload) is not dict or type(payload.get("elevated")) is not bool:
        raise RuntimeError("broker elevation readback shape invalid")
    if payload["elevated"]:
        raise RuntimeError("live apply must run non-elevated after separate UAC approval")


def _approval_acl_state(path: Path) -> object:
    quoted_path = str(path).replace("'", "''")
    script = rf"""
$Acl = Get-Acl -LiteralPath '{quoted_path}'
$OwnerAccount = New-Object -TypeName Security.Principal.NTAccount -ArgumentList $Acl.Owner
$OwnerSid = $OwnerAccount.Translate([Security.Principal.SecurityIdentifier]).Value
$MutationMask = [int](
    [Security.AccessControl.FileSystemRights]::Write -bor
    [Security.AccessControl.FileSystemRights]::Modify -bor
    [Security.AccessControl.FileSystemRights]::FullControl -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
)
$Rules = @($Acl.Access | ForEach-Object {{
    $Sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    $Rights = [int]$_.FileSystemRights
    [ordered]@{{
        sid = $Sid
        access_type = [string]$_.AccessControlType
        inherited = [bool]$_.IsInherited
        can_mutate = [bool](($Rights -band $MutationMask) -ne 0)
    }}
}})
[ordered]@{{
    protected = [bool]$Acl.AreAccessRulesProtected
    owner_sid = $OwnerSid
    rules = $Rules
}} | ConvertTo-Json -Depth 5 -Compress
""".strip()
    completed = _completed(
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    )
    if completed.returncode != 0:
        raise RuntimeError("ACL readback failed")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("ACL readback invalid") from error


def _require_regular_nonreparse_file(path: Path, description: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"{description} missing or not a regular file")
    try:
        stat_result = path.lstat()
    except OSError as error:
        raise RuntimeError(f"{description} stat failed") from error
    if getattr(stat_result, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError(f"{description} reparse point blocked")


def _require_human_approval(expected_plan_sha256: str) -> str:
    _require_non_elevated_broker()
    path = _approval_path(expected_plan_sha256)
    _require_regular_nonreparse_file(path, "human approval artifact")

    raw = path.read_bytes()
    parse_approval_bytes(raw, expected_plan_sha256=expected_plan_sha256)
    validate_approval_acl_state(_approval_acl_state(path))

    reread = path.read_bytes()
    if reread != raw:
        raise RuntimeError("human approval artifact changed during validation")
    return approval_sha256(raw)


def _gh_json(*arguments: str) -> object:
    completed = _completed("gh.exe", "api", *arguments)
    if completed.returncode != 0:
        raise RuntimeError("GitHub readback failed")
    return json.loads(completed.stdout)


def _github_runner_items(repository: str) -> tuple[dict[str, object], ...]:
    base = f"repos/{repository}/actions/runners?per_page=100"

    def fetch_page(page: int) -> object:
        endpoint = base if page == 1 else f"{base}&page={page}"
        return _gh_json(endpoint)

    return read_all_runner_items(fetch_page)


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

    matching = []
    for runner in _github_runner_items(evidence.repository):
        if type(runner.get("labels")) is not list:
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
    return consumption_marker_path(plan_sha)


def _validate_protected_consumption_marker(
    plan_sha: str,
    phase0_sha: str,
    approval_sha: str,
) -> None:
    marker_path = _consumed_marker_path(plan_sha)
    _require_regular_nonreparse_file(marker_path, "protected consumption marker")
    if not CONSUMPTION_ROOT.is_dir() or CONSUMPTION_ROOT.is_symlink():
        raise RuntimeError("protected consumption authority container missing or invalid")
    try:
        root_stat = CONSUMPTION_ROOT.lstat()
    except OSError as error:
        raise RuntimeError("protected consumption authority container stat failed") from error
    if getattr(root_stat, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError("protected consumption authority container reparse point blocked")

    raw = marker_path.read_bytes()
    parse_consumption_marker_bytes(
        raw,
        expected_plan_sha256=plan_sha,
        expected_phase0_evidence_sha256=phase0_sha,
        expected_human_approval_sha256=approval_sha,
    )
    validate_consumption_container_acl_state(_approval_acl_state(CONSUMPTION_ROOT))
    validate_consumption_acl_state(_approval_acl_state(marker_path))
    if marker_path.read_bytes() != raw:
        raise RuntimeError("protected consumption marker changed during validation")


def _acquire_apply_ownership(
    plan_sha: str,
    phase0_sha: str,
    approval_sha: str,
) -> None:
    helper = _controller_repo_root() / "scripts" / "Consume-PrivateCiLiveRegistrationApproval.ps1"
    if not helper.is_file():
        raise RuntimeError("protected consumption helper missing")
    quoted_helper = str(helper).replace("'", "''")
    command = (
        "$Child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru "
        "-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"
        f"'{quoted_helper}','-PlanSha256','{plan_sha}','-Phase0Sha256','{phase0_sha}',"
        f"'-ApprovalSha256','{approval_sha}'); exit $Child.ExitCode"
    )
    completed = _completed(
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
    )
    if completed.returncode != 0:
        raise RuntimeError("protected live apply ownership acquisition failed")
    _validate_protected_consumption_marker(plan_sha, phase0_sha, approval_sha)


def _require_live_outputs_absent(plan_sha: str) -> None:
    for path in (
        _result_path(),
        _transcript_path(),
        _consumed_marker_path(plan_sha),
    ):
        if path.exists():
            raise RuntimeError(f"live registration output already exists: {path.name}")


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
    print(
        "approval_issuer="
        + str(_controller_repo_root() / "scripts" / "Approve-PrivateCiLiveRegistration.ps1")
    )
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

    human_approval_sha = _require_human_approval(actual_plan_sha)

    phase0_bytes = _phase0_path().read_bytes()
    evidence = validate_phase0_evidence_bytes(phase0_bytes)
    reasons = validate_frozen_plan(plan, phase0_evidence_bytes=phase0_bytes)
    if reasons:
        raise RuntimeError("live plan drift: " + ",".join(reasons))
    _require_exact_phase0_host(evidence)
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
        human_approval_sha,
    )

    _validate_protected_consumption_marker(
        actual_plan_sha,
        plan.phase0_evidence_sha256,
        human_approval_sha,
    )
    if _require_human_approval(actual_plan_sha) != human_approval_sha:
        raise RuntimeError("human approval artifact changed after apply ownership")

    started_at = datetime.now(timezone.utc).isoformat()

    def revalidate_mutation_target(_binding: object) -> None:
        _require_frozen_target_still_exact(evidence)

    result = execute_live_registration(
        plan.binding,
        phase0_evidence_bytes=phase0_bytes,
        candidate=plan.candidate,
        ast_attestation=ast,
        prior_evidence_capability=prior,
        revalidate_mutation_target=revalidate_mutation_target,
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
    payload["human_approval_sha256"] = human_approval_sha
    payload["registration_token_recorded"] = False
    result_bytes = canonical_json_bytes(payload)
    _write_exclusive(_result_path(), result_bytes)

    transcript = (
        f"started_at={started_at}\n"
        f"ended_at={ended_at}\n"
        f"plan_sha256={actual_plan_sha}\n"
        f"phase0_evidence_sha256={plan.phase0_evidence_sha256}\n"
        f"human_approval_sha256={human_approval_sha}\n"
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
