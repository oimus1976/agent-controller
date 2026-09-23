#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import locale
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
    operator_step_spec_sha256,
    prior_evidence_auth_message,
    validate_operator_step,
)
from agent_controller.private_ci_consumption_marker import (
    CONSUMPTION_ROOT,
    read_consumption_acl_state,
    validate_consumption_acl_state,
    validate_consumption_container_acl_state,
)
from agent_controller.private_ci_human_approval import (
    approval_sha256,
    parse_approval_bytes,
    validate_approval_acl_state,
)
from agent_controller.private_ci_live_registration_runtime import (
    authoritative_path,
)
from agent_controller.private_ci_phase4_authority import (
    parse_phase4_consumption_marker_bytes,
    phase4_approval_filename,
    phase4_consumption_marker_path,
)
from agent_controller.private_ci_phase4_contract import (
    PHASE4_TARGET_PROBE_FILENAME,
    PHASE4_TARGET_PROBE_RESULT_FILENAME,
    PHASE4_TARGET_PROBE_STDERR_FILENAME,
    PHASE4_TARGET_PROBE_STDOUT_FILENAME,
    REGISTRATION_HANDOFF_OPERATION_ID,
    REGISTRATION_HANDOFF_STEP_ID,
    build_phase4_target_environment_spec,
    parse_registration_handoff_bytes,
    phase4_target_probe_sha256,
    render_phase4_target_environment_candidate,
)
from agent_controller.private_ci_phase4_result import (
    PHASE4_RESULT_SCHEMA,
    PHASE4_RESULT_STATUS,
    Phase4ResultEvidence,
    parse_target_probe_result_bytes,
    phase4_result_bytes,
    sha256_bytes,
)
from agent_controller.private_ci_phase4_runtime import (
    build_reviewed_phase4_plan,
    parse_phase4_plan_bytes,
    phase4_plan_bytes,
    validate_frozen_phase4_plan,
)
from agent_controller.private_ci_runner_readback import read_all_runner_items
from agent_controller.private_ci_runner_tree_snapshot import (
    runner_generation_snapshot_sha256,
)


HANDOFF_FILENAME = "issue225-registration-handoff.json"
PHASE4_CANDIDATE_FILENAME = "issue225-phase4-target-environment-candidate.ps1"
PHASE4_PLAN_FILENAME = "issue225-phase4-plan.json"
PHASE4_RESULT_FILENAME = "issue225-phase4-result.json"
PHASE4_TRANSCRIPT_FILENAME = "issue225-phase4-target-environment.log"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
TUPLE_FIELDS = (
    "observed_effect_families",
    "automatic_variable_collisions",
    "unresolved_placeholders",
    "forbidden_convenience_paths",
)
_ATOMIC_MUTATING_FILE_SYSTEM_RIGHTS = (
    "WriteData",
    "AppendData",
    "WriteAttributes",
    "WriteExtendedAttributes",
    "Delete",
    "DeleteSubdirectoriesAndFiles",
    "ChangePermissions",
    "TakeOwnership",
)


def _controller_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _completed(
    *command: str,
    cwd: Path | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(command),
        cwd=None if cwd is None else str(cwd),
        check=False,
        capture_output=True,
        text=text,
        encoding="utf-8" if text else None,
        errors="replace" if text else None,
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


def _require_digest(value: str, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RuntimeError(f"{label} SHA-256 invalid")
    return value


def _require_regular_nonreparse_file(path: Path, description: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"{description} missing or not a regular file")
    try:
        stat_result = path.lstat()
    except OSError as error:
        raise RuntimeError(f"{description} stat failed") from error
    if getattr(stat_result, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError(f"{description} reparse point blocked")


def _acl_state(path: Path) -> object:
    try:
        return read_consumption_acl_state(path)
    except ValueError as error:
        raise RuntimeError(f"ACL readback failed: {path}") from error


def _gh_json(endpoint: str) -> object:
    completed = _completed("gh.exe", "api", endpoint)
    if completed.returncode != 0:
        raise RuntimeError(f"GitHub readback failed: {endpoint}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"GitHub readback invalid: {endpoint}") from error


def _github_runner_items(repository: str) -> tuple[dict[str, object], ...]:
    base = f"repos/{repository}/actions/runners?per_page=100"

    def fetch_page(page: int) -> object:
        endpoint = base if page == 1 else f"{base}&page={page}"
        return _gh_json(endpoint)

    return read_all_runner_items(fetch_page)


def _require_remote_binding_exact(binding) -> None:
    repo = _gh_json(f"repos/{binding.repository}")
    if (
        type(repo) is not dict
        or repo.get("visibility") != "private"
        or repo.get("default_branch") != "main"
    ):
        raise RuntimeError("Phase 4 repository drift")

    pr = _gh_json(
        f"repos/{binding.repository}/pulls/{binding.pull_request_number}"
    )
    if type(pr) is not dict:
        raise RuntimeError("Phase 4 PR readback invalid")
    head = pr.get("head")
    base = pr.get("base")
    if (
        pr.get("state") != "open"
        or pr.get("draft") is not True
        or type(head) is not dict
        or type(base) is not dict
        or type(head.get("repo")) is not dict
        or head["repo"].get("full_name") != binding.repository
        or head.get("sha") != binding.target_sha
        or base.get("ref") != "main"
    ):
        raise RuntimeError("Phase 4 PR binding drift")

    branch = _gh_json(f"repos/{binding.repository}/branches/main")
    if (
        type(branch) is not dict
        or type(branch.get("commit")) is not dict
        or branch["commit"].get("sha") != binding.workflow_sha
    ):
        raise RuntimeError("Phase 4 workflow SHA drift")
    workflow = _gh_json(
        (
            f"repos/{binding.repository}/contents/{binding.workflow_path}"
            f"?ref={binding.workflow_sha}"
        )
    )
    if (
        type(workflow) is not dict
        or workflow.get("type") != "file"
        or workflow.get("path") != binding.workflow_path
    ):
        raise RuntimeError("Phase 4 workflow path drift")

    eligible: list[dict[str, object]] = []
    for runner in _github_runner_items(binding.repository):
        labels = runner.get("labels")
        if type(labels) is not list:
            raise RuntimeError("Phase 4 runner label readback invalid")
        names = {
            label.get("name")
            for label in labels
            if type(label) is dict and type(label.get("name")) is str
        }
        if (
            runner.get("id") == binding.runner_id
            or runner.get("name") == binding.runner_name
            or binding.runner_label in names
        ):
            eligible.append(runner)
    if len(eligible) != 1:
        raise RuntimeError("Phase 4 eligible runner count unsafe")
    runner = eligible[0]
    labels = {
        label.get("name")
        for label in runner["labels"]
        if type(label) is dict and type(label.get("name")) is str
    }
    if (
        runner.get("id") != binding.runner_id
        or runner.get("name") != binding.runner_name
        or binding.runner_label not in labels
        or runner.get("busy") is not False
        or runner.get("status") != "offline"
    ):
        raise RuntimeError("Phase 4 runner binding drift")


def _require_controller_source_exact(binding) -> None:
    repo = _controller_repo_root()
    if str(repo).casefold() != binding.controller_tree.casefold():
        raise RuntimeError("Phase 4 controller tree mismatch")
    head = _completed("git.exe", "-C", str(repo), "rev-parse", "HEAD")
    if head.returncode != 0 or head.stdout.strip() != binding.controller_main_sha:
        raise RuntimeError("Phase 4 controller HEAD drift")
    status = _completed(
        "git.exe",
        "-C",
        str(repo),
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status.returncode != 0 or status.stdout.strip():
        raise RuntimeError("Phase 4 controller tree not clean")
    remote = _completed(
        "git.exe",
        "ls-remote",
        "https://github.com/oimus1976/agent-controller.git",
        "refs/heads/main",
    )
    parts = remote.stdout.split()
    remote_sha = parts[0] if remote.returncode == 0 and parts else ""
    if remote_sha != binding.controller_main_sha:
        raise RuntimeError("Phase 4 controller main drift")


def _require_non_elevated_broker(binding) -> None:
    host = _completed("hostname.exe")
    identity = _completed("whoami.exe")
    if (
        host.returncode != 0
        or host.stdout.strip().casefold() != binding.host.casefold()
    ):
        raise RuntimeError("Phase 4 host mismatch")
    if (
        identity.returncode != 0
        or identity.stdout.strip().casefold()
        != binding.broker_identity.casefold()
    ):
        raise RuntimeError("Phase 4 broker identity mismatch")

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
        raise RuntimeError("Phase 4 broker elevation readback failed")
    payload = json.loads(completed.stdout)
    if type(payload) is not dict or type(payload.get("elevated")) is not bool:
        raise RuntimeError("Phase 4 broker elevation readback invalid")
    if payload["elevated"]:
        raise RuntimeError("Phase 4 apply must run non-elevated")


def _configure_authority() -> tuple[bytes, bytes]:
    ast_key = secrets.token_bytes(32)
    evidence_key = secrets.token_bytes(32)
    configure_controller_authority(
        ast_hmac_key=ast_key,
        evidence_hmac_key=evidence_key,
    )
    return ast_key, evidence_key


def _powershell_attestation(
    candidate_path: Path,
    spec_sha256: str,
    ast_key: bytes,
):
    producer = (
        _controller_repo_root()
        / "scripts"
        / "Invoke-PrivateCiAstAttestation.ps1"
    )
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
        raise RuntimeError("Phase 4 PowerShell AST producer failed")
    raw = json.loads(completed.stdout)
    if type(raw) is not dict:
        raise RuntimeError("Phase 4 AST producer output invalid")
    for field in TUPLE_FIELDS:
        if type(raw.get(field)) is list:
            raw[field] = tuple(raw[field])
    report = PowerShellAstAttestation(**raw)
    tag = hmac.new(
        ast_key,
        ast_attestation_auth_message(report),
        hashlib.sha256,
    ).hexdigest()
    return authenticate_ast_attestation(report, auth_tag=tag)


def _authenticate_handoff(
    *,
    handoff_bytes: bytes,
    binding,
    evidence_key: bytes,
):
    handoff_sha = hashlib.sha256(handoff_bytes).hexdigest()
    message = prior_evidence_auth_message(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        producer_operation_id=REGISTRATION_HANDOFF_OPERATION_ID,
        producer_step_id=REGISTRATION_HANDOFF_STEP_ID,
        evidence_sha256=handoff_sha,
    )
    tag = hmac.new(
        evidence_key,
        message,
        hashlib.sha256,
    ).hexdigest()
    return authenticate_prior_evidence(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        producer_operation_id=REGISTRATION_HANDOFF_OPERATION_ID,
        producer_step_id=REGISTRATION_HANDOFF_STEP_ID,
        evidence_bytes=handoff_bytes,
        auth_tag=tag,
    )


def _approval_path(plan_sha: str) -> Path:
    return authoritative_path(phase4_approval_filename(plan_sha))


def _require_phase4_approval(plan_sha: str, binding) -> tuple[bytes, str]:
    path = _approval_path(plan_sha)
    _require_regular_nonreparse_file(path, "Phase 4 human approval")
    raw = path.read_bytes()
    approval = parse_approval_bytes(
        raw,
        expected_plan_sha256=plan_sha,
    )
    if approval.host != binding.host:
        raise RuntimeError("Phase 4 approval host mismatch")
    if approval.approver_identity != binding.broker_identity:
        raise RuntimeError("Phase 4 approval identity mismatch")
    validate_approval_acl_state(_acl_state(path))
    if path.read_bytes() != raw:
        raise RuntimeError("Phase 4 approval changed during validation")
    return raw, approval_sha256(raw)


def _acquire_phase4_ownership(
    *,
    plan_sha: str,
    handoff_sha: str,
    approval_sha: str,
) -> None:
    helper = (
        _controller_repo_root()
        / "scripts"
        / "Consume-PrivateCiPhase4Approval.ps1"
    )
    quoted = str(helper).replace("'", "''")
    command = (
        "$Child = Start-Process -FilePath 'powershell.exe' -Verb RunAs "
        "-Wait -PassThru -ArgumentList @("
        "'-NoProfile','-ExecutionPolicy','Bypass','-File',"
        f"'{quoted}','-PlanSha256','{plan_sha}',"
        f"'-RegistrationHandoffSha256','{handoff_sha}',"
        f"'-ApprovalSha256','{approval_sha}'"
        "); exit $Child.ExitCode"
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
        raise RuntimeError("Phase 4 protected ownership acquisition failed")


def _validate_phase4_consumption(
    *,
    handoff_sha: str,
    plan_sha: str,
    approval_sha: str,
) -> tuple[bytes, str]:
    path = phase4_consumption_marker_path(handoff_sha)
    _require_regular_nonreparse_file(
        path,
        "Phase 4 protected consumption marker",
    )
    if not CONSUMPTION_ROOT.is_dir() or CONSUMPTION_ROOT.is_symlink():
        raise RuntimeError("Phase 4 authority root invalid")
    raw = path.read_bytes()
    parse_phase4_consumption_marker_bytes(
        raw,
        expected_plan_sha256=plan_sha,
        expected_registration_handoff_sha256=handoff_sha,
        expected_human_approval_sha256=approval_sha,
    )
    validate_consumption_container_acl_state(_acl_state(CONSUMPTION_ROOT))
    validate_consumption_acl_state(_acl_state(path))
    if path.read_bytes() != raw:
        raise RuntimeError("Phase 4 consumption marker changed")
    return raw, hashlib.sha256(raw).hexdigest()


def _probe_paths(binding) -> tuple[Path, Path, Path]:
    root = Path(binding.runner_root)
    return (
        root / PHASE4_TARGET_PROBE_RESULT_FILENAME,
        root / PHASE4_TARGET_PROBE_STDOUT_FILENAME,
        root / PHASE4_TARGET_PROBE_STDERR_FILENAME,
    )



def _require_generation_snapshot_exact(handoff) -> str:
    runner_root = Path(handoff.binding.runner_root)
    generation_root = runner_root.parent
    observed = runner_generation_snapshot_sha256(
        generation_root=generation_root,
        runner_root=runner_root,
        work_folder=handoff.binding.work_folder,
    )
    if observed != handoff.runner_generation_snapshot_sha256:
        raise RuntimeError(
            "Phase 4 runner generation snapshot drift"
        )
    return observed

def command_plan() -> int:
    handoff_path = authoritative_path(HANDOFF_FILENAME)
    candidate_path = authoritative_path(PHASE4_CANDIDATE_FILENAME)
    plan_path = authoritative_path(PHASE4_PLAN_FILENAME)
    probe_path = _controller_repo_root() / "scripts" / PHASE4_TARGET_PROBE_FILENAME

    _require_regular_nonreparse_file(
        handoff_path,
        "protected registration handoff",
    )
    validate_approval_acl_state(_acl_state(handoff_path))
    _require_regular_nonreparse_file(probe_path, "tracked Phase 4 target probe")
    if candidate_path.exists() or plan_path.exists():
        raise RuntimeError(
            "Phase 4 plan artifacts already exist; do not overwrite automatically"
        )

    handoff_raw = handoff_path.read_bytes()
    handoff = parse_registration_handoff_bytes(handoff_raw)
    _require_generation_snapshot_exact(handoff)
    probe_raw = probe_path.read_bytes()
    probe_sha = phase4_target_probe_sha256(probe_raw)
    candidate = render_phase4_target_environment_candidate(
        handoff.binding,
        handoff,
        target_probe_sha256=probe_sha,
    )
    _write_exclusive(candidate_path, candidate.encode("utf-8"))

    handoff_sha = hashlib.sha256(handoff_raw).hexdigest()
    spec = build_phase4_target_environment_spec(
        handoff.binding,
        registration_handoff_sha256=handoff_sha,
    )
    ast_key, _ = _configure_authority()
    ast = _powershell_attestation(
        candidate_path,
        operator_step_spec_sha256(spec),
        ast_key,
    )
    plan = build_reviewed_phase4_plan(
        registration_handoff_bytes=handoff_raw,
        target_probe_bytes=probe_raw,
        ast_attestation=ast,
    )
    raw_plan = phase4_plan_bytes(plan)
    _write_exclusive(plan_path, raw_plan)
    plan_sha = hashlib.sha256(raw_plan).hexdigest()

    print("PASS_TO_OPERATOR")
    print(f"phase4_plan={plan_path}")
    print(f"phase4_plan_sha256={plan_sha}")
    print(f"candidate_sha256={plan.candidate_sha256}")
    print(f"registration_handoff_sha256={handoff_sha}")
    print(
        "approval_issuer="
        + str(
            _controller_repo_root()
            / "scripts"
            / "Approve-PrivateCiPhase4.ps1"
        )
    )
    print("NO_PHASE4_LIVE_EFFECT_PERFORMED")
    return 0


def command_apply(expected_plan_sha256: str) -> int:
    expected_plan_sha = _require_digest(
        expected_plan_sha256,
        "expected Phase 4 plan",
    )
    handoff_path = authoritative_path(HANDOFF_FILENAME)
    candidate_path = authoritative_path(PHASE4_CANDIDATE_FILENAME)
    plan_path = authoritative_path(PHASE4_PLAN_FILENAME)
    result_path = authoritative_path(PHASE4_RESULT_FILENAME)
    transcript_path = authoritative_path(PHASE4_TRANSCRIPT_FILENAME)
    probe_source = _controller_repo_root() / "scripts" / PHASE4_TARGET_PROBE_FILENAME

    for path, description in (
        (handoff_path, "protected registration handoff"),
        (candidate_path, "Phase 4 candidate"),
        (plan_path, "Phase 4 plan"),
        (probe_source, "tracked Phase 4 target probe"),
    ):
        _require_regular_nonreparse_file(path, description)
    validate_approval_acl_state(_acl_state(handoff_path))
    if result_path.exists() or transcript_path.exists():
        raise RuntimeError("Phase 4 result already exists")

    plan_raw = plan_path.read_bytes()
    plan_sha = hashlib.sha256(plan_raw).hexdigest()
    if plan_sha != expected_plan_sha:
        raise RuntimeError("human-authorized Phase 4 plan SHA-256 mismatch")
    plan = parse_phase4_plan_bytes(plan_raw)
    handoff_raw = handoff_path.read_bytes()
    handoff_sha = hashlib.sha256(handoff_raw).hexdigest()
    handoff = parse_registration_handoff_bytes(handoff_raw)
    probe_raw = probe_source.read_bytes()
    reasons = validate_frozen_phase4_plan(
        plan,
        registration_handoff_bytes=handoff_raw,
        target_probe_bytes=probe_raw,
    )
    if reasons:
        raise RuntimeError("Phase 4 plan drift: " + ",".join(reasons))
    candidate_raw = candidate_path.read_bytes()
    if candidate_raw != plan.candidate.encode("utf-8"):
        raise RuntimeError("Phase 4 candidate artifact drift")

    _require_non_elevated_broker(plan.binding)
    _require_controller_source_exact(plan.binding)
    _require_remote_binding_exact(plan.binding)
    _require_generation_snapshot_exact(handoff)
    approval_raw, approval_sha = _require_phase4_approval(
        plan_sha,
        plan.binding,
    )

    ast_key, evidence_key = _configure_authority()
    spec = build_phase4_target_environment_spec(
        plan.binding,
        registration_handoff_sha256=handoff_sha,
    )
    ast = _powershell_attestation(
        candidate_path,
        operator_step_spec_sha256(spec),
        ast_key,
    )
    prior = _authenticate_handoff(
        handoff_bytes=handoff_raw,
        binding=plan.binding,
        evidence_key=evidence_key,
    )
    gate = validate_operator_step(
        spec,
        plan.candidate,
        ast_attestation=ast,
        prior_evidence_capability=prior,
    )
    if not gate.passed:
        reasons_text = ",".join(gate.reason_codes) or gate.status.value
        raise RuntimeError("Phase 4 live gate blocked: " + reasons_text)

    marker_path = phase4_consumption_marker_path(handoff_sha)
    if marker_path.exists():
        raise RuntimeError("registration handoff already consumed by Phase 4")

    _acquire_phase4_ownership(
        plan_sha=plan_sha,
        handoff_sha=handoff_sha,
        approval_sha=approval_sha,
    )
    consumption_raw, consumption_sha = _validate_phase4_consumption(
        handoff_sha=handoff_sha,
        plan_sha=plan_sha,
        approval_sha=approval_sha,
    )

    if plan_path.read_bytes() != plan_raw:
        raise RuntimeError("Phase 4 plan changed after ownership acquisition")
    if handoff_path.read_bytes() != handoff_raw:
        raise RuntimeError(
            "registration handoff changed after Phase 4 ownership acquisition"
        )
    if candidate_path.read_bytes() != candidate_raw:
        raise RuntimeError(
            "Phase 4 candidate changed after ownership acquisition"
        )
    if probe_source.read_bytes() != probe_raw:
        raise RuntimeError(
            "Phase 4 target probe changed after ownership acquisition"
        )
    if _approval_path(plan_sha).read_bytes() != approval_raw:
        raise RuntimeError(
            "Phase 4 approval changed after ownership acquisition"
        )
    _require_controller_source_exact(plan.binding)
    _require_remote_binding_exact(plan.binding)
    _require_generation_snapshot_exact(handoff)

    started_at = datetime.now(timezone.utc).isoformat()
    completed = _completed(
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(candidate_path),
        cwd=_controller_repo_root(),
    )
    ended_at = datetime.now(timezone.utc).isoformat()
    if completed.returncode != 0:
        transcript = (
            f"started_at={started_at}\n"
            f"ended_at={ended_at}\n"
            f"phase4_plan_sha256={plan_sha}\n"
            f"registration_handoff_sha256={handoff_sha}\n"
            f"phase4_consumption_sha256={consumption_sha}\n"
            f"child_exit_code={completed.returncode}\n"
            "--- stdout ---\n"
            f"{completed.stdout}\n"
            "--- stderr ---\n"
            f"{completed.stderr}\n"
        ).encode("utf-8")
        _write_exclusive(transcript_path, transcript)
        raise RuntimeError(
            f"Phase 4 candidate failed with exit {completed.returncode}"
        )

    success_lines = {
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip()
    }
    if "PHASE4_TARGET_ENVIRONMENT_PASS" not in success_lines:
        raise RuntimeError("Phase 4 success marker missing")

    probe_result_path, probe_stdout_path, probe_stderr_path = _probe_paths(
        plan.binding
    )
    for path, description in (
        (probe_result_path, "Phase 4 target probe result"),
        (probe_stdout_path, "Phase 4 target probe stdout"),
        (probe_stderr_path, "Phase 4 target probe stderr"),
    ):
        _require_regular_nonreparse_file(path, description)
    probe_result_raw = probe_result_path.read_bytes()
    parse_target_probe_result_bytes(
        probe_result_raw,
        binding=plan.binding,
    )
    probe_stdout_raw = probe_stdout_path.read_bytes()
    probe_stderr_raw = probe_stderr_path.read_bytes()
    runner_root = Path(plan.binding.runner_root)
    post_generation_snapshot_sha = runner_generation_snapshot_sha256(
        generation_root=runner_root.parent,
        runner_root=runner_root,
        work_folder=plan.binding.work_folder,
    )

    evidence = Phase4ResultEvidence(
        schema=PHASE4_RESULT_SCHEMA,
        binding=plan.binding,
        phase4_plan_sha256=plan_sha,
        registration_handoff_sha256=handoff_sha,
        human_approval_sha256=approval_sha,
        phase4_consumption_sha256=consumption_sha,
        candidate_sha256=plan.candidate_sha256,
        target_probe_sha256=plan.target_probe_sha256,
        target_probe_result_sha256=sha256_bytes(probe_result_raw),
        target_probe_stdout_sha256=sha256_bytes(probe_stdout_raw),
        target_probe_stderr_sha256=sha256_bytes(probe_stderr_raw),
        runner_generation_snapshot_sha256=post_generation_snapshot_sha,
        status=PHASE4_RESULT_STATUS,
        completed_at=ended_at,
    )
    result_raw = phase4_result_bytes(evidence)
    _write_exclusive(result_path, result_raw)

    transcript = (
        f"started_at={started_at}\n"
        f"ended_at={ended_at}\n"
        f"phase4_plan_sha256={plan_sha}\n"
        f"registration_handoff_sha256={handoff_sha}\n"
        f"human_approval_sha256={approval_sha}\n"
        f"phase4_consumption_sha256={consumption_sha}\n"
        f"candidate_sha256={plan.candidate_sha256}\n"
        f"target_probe_sha256={plan.target_probe_sha256}\n"
        f"target_probe_result_sha256={evidence.target_probe_result_sha256}\n"
        f"runner_generation_snapshot_sha256={evidence.runner_generation_snapshot_sha256}\n"
        "status=PHASE4_TARGET_ENVIRONMENT_PASS\n"
        "--- stdout ---\n"
        f"{completed.stdout}\n"
        "--- stderr ---\n"
        f"{completed.stderr}\n"
    ).encode("utf-8")
    _write_exclusive(transcript_path, transcript)

    print("PHASE4_TARGET_ENVIRONMENT_PASS")
    print(f"result={result_path}")
    print(f"result_sha256={hashlib.sha256(result_raw).hexdigest()}")
    print(f"transcript={transcript_path}")
    print("NO_RUNNER_LISTENER_START_OR_WORKFLOW_DISPATCH_PERFORMED")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded #225 Phase 4 target-environment harness"
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
        raise RuntimeError("unsupported Phase 4 command")
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
