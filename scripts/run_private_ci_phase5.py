#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time
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
from agent_controller.private_ci_live_registration_runtime import authoritative_path
from agent_controller.private_ci_phase4_result import (
    parse_phase4_result_bytes,
    parse_target_probe_result_bytes,
)
from agent_controller.private_ci_phase5_authority import (
    parse_phase5_consumption_marker_bytes,
    phase5_approval_filename,
    phase5_consumption_marker_path,
)
from agent_controller.private_ci_phase5_contract import (
    GITHUB_API_VERSION,
    PHASE4_RESULT_PRODUCER_OPERATION_ID,
    PHASE4_RESULT_PRODUCER_STEP_ID,
    PHASE5_RUNNER_STDERR_FILENAME,
    PHASE5_RUNNER_STDOUT_FILENAME,
    PHASE5_SECURITY_PROBE_RESULT_FILENAME,
    PHASE5_SECURITY_PROBE_STDERR_FILENAME,
    PHASE5_SECURITY_PROBE_STDOUT_FILENAME,
    build_phase5_exactly_one_job_spec,
    render_phase5_exactly_one_job_candidate,
)
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_SCHEMA,
    PHASE5_RESULT_STATUS,
    Phase5ResultEvidence,
    validate_phase5_run_job_readback,
    phase5_result_bytes,
)
from agent_controller.private_ci_phase5_runtime import (
    build_reviewed_phase5_plan,
    parse_phase5_plan_bytes,
    phase5_plan_bytes,
    validate_frozen_phase5_plan,
)
from agent_controller.private_ci_runner_readback import read_all_runner_items
from agent_controller.private_ci_runner_tree_snapshot import (
    runner_generation_snapshot_sha256,
)


PHASE4_RESULT_FILENAME = "issue225-phase4-result.json"
PHASE5_CANDIDATE_FILENAME = "issue225-phase5-candidate.ps1"
PHASE5_PLAN_FILENAME = "issue225-phase5-plan.json"
PHASE5_RESULT_FILENAME = "issue225-phase5-result.json"
PHASE5_TRANSCRIPT_FILENAME = "issue225-phase5-exactly-one-job.log"
PHASE5_READBACK_MAX_ATTEMPTS = 8
PHASE5_READBACK_DELAY_SECONDS = 1.0
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
_RUN_ID_PATTERN = re.compile(r"^PHASE5_WORKFLOW_RUN_ID=([1-9][0-9]*)$", re.MULTILINE)
_RUNNER_PROCESS_ID_PATTERN = re.compile(
    r"^PHASE5_RUNNER_PROCESS_ID=([1-9][0-9]*)$",
    re.MULTILINE,
)
_RUNNER_PROCESS_OWNER_PATTERN = re.compile(
    r"^PHASE5_RUNNER_PROCESS_OWNER=([^\r\n]+)$",
    re.MULTILINE,
)


def _controller_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _completed(
    *command: str,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=None if cwd is None else str(cwd),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
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
    completed = _completed(
        "gh.exe",
        "api",
        "-H",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
        endpoint,
    )
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


def _require_repository_pr_workflow_exact(binding) -> None:
    repository = _gh_json(f"repos/{binding.repository}")
    if (
        type(repository) is not dict
        or repository.get("visibility") != "private"
        or repository.get("default_branch") != "main"
    ):
        raise RuntimeError("Phase 5 repository drift")

    pr = _gh_json(
        f"repos/{binding.repository}/pulls/{binding.pull_request_number}"
    )
    if type(pr) is not dict:
        raise RuntimeError("Phase 5 PR readback invalid")
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
        raise RuntimeError("Phase 5 PR binding drift")

    branch = _gh_json(f"repos/{binding.repository}/branches/main")
    if (
        type(branch) is not dict
        or type(branch.get("commit")) is not dict
        or branch["commit"].get("sha") != binding.workflow_sha
    ):
        raise RuntimeError("Phase 5 workflow SHA drift")
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
        raise RuntimeError("Phase 5 workflow path drift")


def _require_remote_binding_exact(binding) -> None:
    _require_repository_pr_workflow_exact(binding)
    eligible: list[dict[str, object]] = []
    for runner in _github_runner_items(binding.repository):
        labels = runner.get("labels")
        if type(labels) is not list:
            raise RuntimeError("Phase 5 runner label readback invalid")
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
        raise RuntimeError("Phase 5 eligible runner count unsafe")
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
        raise RuntimeError("Phase 5 runner binding drift")


def _require_local_runner_exact(binding) -> None:
    root = Path(binding.runner_root)
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("Phase 5 runner root invalid")
    run_cmd = root / "run.cmd"
    settings_path = root / ".runner"
    _require_regular_nonreparse_file(run_cmd, "Phase 5 run.cmd")
    _require_regular_nonreparse_file(settings_path, "Phase 5 .runner settings")
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Phase 5 .runner settings invalid") from error
    if type(settings) is not dict:
        raise RuntimeError("Phase 5 .runner settings shape invalid")
    if (
        settings.get("agentId") != binding.runner_id
        or settings.get("agentName") != binding.runner_name
        or settings.get("workFolder") != binding.work_folder
        or settings.get("ephemeral") is not True
        or settings.get("disableUpdate") is not True
    ):
        raise RuntimeError("Phase 5 local runner binding drift")


def _require_controller_source_exact(binding) -> None:
    repo = _controller_repo_root()
    if str(repo).casefold() != binding.controller_tree.casefold():
        raise RuntimeError("Phase 5 controller tree mismatch")
    head = _completed("git.exe", "-C", str(repo), "rev-parse", "HEAD")
    if head.returncode != 0 or head.stdout.strip() != binding.controller_main_sha:
        raise RuntimeError("Phase 5 controller HEAD drift")
    status = _completed(
        "git.exe",
        "-C",
        str(repo),
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status.returncode != 0 or status.stdout.strip():
        raise RuntimeError("Phase 5 controller tree not clean")
    remote = _completed(
        "git.exe",
        "ls-remote",
        "https://github.com/oimus1976/agent-controller.git",
        "refs/heads/main",
    )
    parts = remote.stdout.split()
    remote_sha = parts[0] if remote.returncode == 0 and parts else ""
    if remote_sha != binding.controller_main_sha:
        raise RuntimeError("Phase 5 controller main drift")


def _require_non_elevated_broker(binding) -> None:
    host = _completed("hostname.exe")
    identity = _completed("whoami.exe")
    if (
        host.returncode != 0
        or host.stdout.strip().casefold() != binding.host.casefold()
    ):
        raise RuntimeError("Phase 5 host mismatch")
    if (
        identity.returncode != 0
        or identity.stdout.strip().casefold()
        != binding.broker_identity.casefold()
    ):
        raise RuntimeError("Phase 5 broker identity mismatch")

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
        raise RuntimeError("Phase 5 broker elevation readback failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Phase 5 broker elevation readback invalid") from error
    if type(payload) is not dict or type(payload.get("elevated")) is not bool:
        raise RuntimeError("Phase 5 broker elevation readback invalid")
    if payload["elevated"]:
        raise RuntimeError("Phase 5 apply must run non-elevated")


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
        raise RuntimeError("Phase 5 PowerShell AST producer failed")
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Phase 5 AST producer output invalid") from error
    if type(raw) is not dict:
        raise RuntimeError("Phase 5 AST producer output invalid")
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


def _authenticate_phase4_result(
    *,
    phase4_result_bytes: bytes,
    binding,
    evidence_key: bytes,
):
    phase4_sha = hashlib.sha256(phase4_result_bytes).hexdigest()
    message = prior_evidence_auth_message(
        repository=binding.repository,
        pull_request_number=binding.pull_request_number,
        target_sha=binding.target_sha,
        producer_operation_id=PHASE4_RESULT_PRODUCER_OPERATION_ID,
        producer_step_id=PHASE4_RESULT_PRODUCER_STEP_ID,
        evidence_sha256=phase4_sha,
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
        producer_operation_id=PHASE4_RESULT_PRODUCER_OPERATION_ID,
        producer_step_id=PHASE4_RESULT_PRODUCER_STEP_ID,
        evidence_bytes=phase4_result_bytes,
        auth_tag=tag,
    )


def _approval_path(plan_sha: str) -> Path:
    return authoritative_path(phase5_approval_filename(plan_sha))


def _require_phase5_approval(plan_sha: str, binding) -> tuple[bytes, str]:
    path = _approval_path(plan_sha)
    _require_regular_nonreparse_file(path, "Phase 5 human approval")
    raw = path.read_bytes()
    approval = parse_approval_bytes(
        raw,
        expected_plan_sha256=plan_sha,
    )
    if approval.host != binding.host:
        raise RuntimeError("Phase 5 approval host mismatch")
    if approval.approver_identity != binding.broker_identity:
        raise RuntimeError("Phase 5 approval identity mismatch")
    validate_approval_acl_state(_acl_state(path))
    if path.read_bytes() != raw:
        raise RuntimeError("Phase 5 approval changed during validation")
    return raw, approval_sha256(raw)


def _acquire_phase5_ownership(
    *,
    plan_sha: str,
    phase4_result_sha: str,
    approval_sha: str,
) -> None:
    helper = (
        _controller_repo_root()
        / "scripts"
        / "Consume-PrivateCiPhase5Approval.ps1"
    )
    quoted = str(helper).replace("'", "''")
    command = (
        "$Child = Start-Process -FilePath 'powershell.exe' -Verb RunAs "
        "-Wait -PassThru -ArgumentList @("
        "'-NoProfile','-ExecutionPolicy','Bypass','-File',"
        f"'{quoted}','-PlanSha256','{plan_sha}',"
        f"'-Phase4ResultSha256','{phase4_result_sha}',"
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
        raise RuntimeError("Phase 5 protected ownership acquisition failed")


def _validate_phase5_consumption(
    *,
    phase4_result_sha: str,
    plan_sha: str,
    approval_sha: str,
) -> tuple[bytes, str]:
    path = phase5_consumption_marker_path(phase4_result_sha)
    _require_regular_nonreparse_file(
        path,
        "Phase 5 protected consumption marker",
    )
    if not CONSUMPTION_ROOT.is_dir() or CONSUMPTION_ROOT.is_symlink():
        raise RuntimeError("Phase 5 authority root invalid")
    raw = path.read_bytes()
    parse_phase5_consumption_marker_bytes(
        raw,
        expected_plan_sha256=plan_sha,
        expected_phase4_result_sha256=phase4_result_sha,
        expected_human_approval_sha256=approval_sha,
    )
    validate_consumption_container_acl_state(_acl_state(CONSUMPTION_ROOT))
    validate_consumption_acl_state(_acl_state(path))
    if path.read_bytes() != raw:
        raise RuntimeError("Phase 5 consumption marker changed")
    return raw, hashlib.sha256(raw).hexdigest()


def _extract_runner_process_identity(stdout: str) -> tuple[int, str]:
    if type(stdout) is not str:
        raise RuntimeError("Phase 5 candidate stdout invalid")
    ids = _RUNNER_PROCESS_ID_PATTERN.findall(stdout)
    owners = _RUNNER_PROCESS_OWNER_PATTERN.findall(stdout)
    if len(ids) != 1 or len(owners) != 1:
        raise RuntimeError(
            "Phase 5 runner process identity evidence missing or ambiguous; "
            "dispatch must not be retried"
        )
    process_id = int(ids[0])
    owner = owners[0].strip()
    if process_id <= 0 or not owner:
        raise RuntimeError(
            "Phase 5 runner process identity evidence invalid; "
            "dispatch must not be retried"
        )
    return process_id, owner


def _extract_workflow_run_id(stdout: str) -> int:
    if type(stdout) is not str:
        raise RuntimeError("Phase 5 candidate stdout invalid")
    matches = _RUN_ID_PATTERN.findall(stdout)
    if len(matches) != 1:
        raise RuntimeError(
            "Phase 5 dispatch response did not yield exactly one workflow run id; "
            "dispatch must not be retried"
        )
    run_id = int(matches[0])
    if run_id <= 0:
        raise RuntimeError(
            "Phase 5 workflow run id invalid; dispatch must not be retried"
        )
    return run_id


def _read_exact_phase5_run_job(
    *,
    binding,
    expected_workflow_run_id: int,
):
    workflow_run_id = expected_workflow_run_id
    last_error: Exception | None = None
    for attempt in range(1, PHASE5_READBACK_MAX_ATTEMPTS + 1):
        try:
            run = _gh_json(
                f"repos/{binding.repository}/actions/runs/{workflow_run_id}"
            )
            jobs = _gh_json(
                f"repos/{binding.repository}/actions/runs/{workflow_run_id}/jobs?filter=latest&per_page=100"
            )
            if type(run) is not dict:
                raise RuntimeError("Phase 5 workflow run readback shape invalid")
            if run.get("id") != workflow_run_id:
                raise RuntimeError("Phase 5 workflow run id readback mismatch")
            if run.get("run_attempt") not in (None, 1):
                raise RuntimeError("Phase 5 workflow run was rerun")
            if run.get("status") == "completed":
                if run.get("conclusion") != "success":
                    raise RuntimeError("Phase 5 workflow run failed")
                if type(jobs) is not dict:
                    raise RuntimeError("Phase 5 jobs readback shape invalid")
                job_items = jobs.get("jobs")
                total = jobs.get("total_count")
                if total not in (0, 1) or type(job_items) is not list:
                    raise RuntimeError("Phase 5 job cardinality unsafe")
                if total == 1 and len(job_items) == 1:
                    job = job_items[0]
                    if (
                        type(job) is dict
                        and job.get("status") == "completed"
                    ):
                        return validate_phase5_run_job_readback(
                            run_payload=run,
                            jobs_payload=jobs,
                            binding=binding,
                            expected_workflow_run_id=workflow_run_id,
                        )
            last_error = RuntimeError(
                "Phase 5 exact run/job not terminally visible yet"
            )
        except RuntimeError as error:
            last_error = error
            if any(
                phrase in str(error)
                for phrase in (
                    "was rerun",
                    "workflow run failed",
                    "cardinality unsafe",
                    "id readback mismatch",
                )
            ):
                raise
        if attempt < PHASE5_READBACK_MAX_ATTEMPTS:
            time.sleep(PHASE5_READBACK_DELAY_SECONDS)
    raise RuntimeError(
        "Phase 5 exact run/job readback exhausted; dispatch must not be retried"
    ) from last_error


def _runner_output_paths(binding) -> tuple[Path, Path]:
    root = Path(binding.runner_root)
    return (
        root / PHASE5_RUNNER_STDOUT_FILENAME,
        root / PHASE5_RUNNER_STDERR_FILENAME,
    )


def _security_probe_paths(binding) -> tuple[Path, Path, Path]:
    root = Path(binding.runner_root)
    return (
        root / PHASE5_SECURITY_PROBE_RESULT_FILENAME,
        root / PHASE5_SECURITY_PROBE_STDOUT_FILENAME,
        root / PHASE5_SECURITY_PROBE_STDERR_FILENAME,
    )


def _write_attempt_transcript(
    *,
    path: Path,
    started_at: str,
    ended_at: str,
    plan_sha: str,
    phase4_result_sha: str,
    approval_sha: str,
    consumption_sha: str,
    child_exit_code: int | None,
    workflow_run_id: int | None,
    runner_process_id: int | None = None,
    runner_process_owner: str = "",
    stdout: str,
    stderr: str,
    status: str,
    error: str = "",
) -> None:
    lines = [
        f"started_at={started_at}",
        f"ended_at={ended_at}",
        f"phase5_plan_sha256={plan_sha}",
        f"phase4_result_sha256={phase4_result_sha}",
        f"human_approval_sha256={approval_sha}",
        f"phase5_consumption_sha256={consumption_sha}",
        f"child_exit_code={'' if child_exit_code is None else child_exit_code}",
        f"workflow_run_id={'' if workflow_run_id is None else workflow_run_id}",
        f"runner_process_id={'' if runner_process_id is None else runner_process_id}",
        f"runner_process_owner={runner_process_owner}",
        f"status={status}",
    ]
    if error:
        lines.append(f"error={error}")
    lines.extend(
        (
            "--- stdout ---",
            stdout,
            "--- stderr ---",
            stderr,
            "",
        )
    )
    _write_exclusive(path, "\n".join(lines).encode("utf-8"))



def _require_phase4_generation_snapshot_exact(phase4) -> str:
    runner_root = Path(phase4.binding.runner_root)
    observed = runner_generation_snapshot_sha256(
        generation_root=runner_root.parent,
        runner_root=runner_root,
        work_folder=phase4.binding.work_folder,
    )
    if observed != phase4.runner_generation_snapshot_sha256:
        raise RuntimeError("Phase 5 runner generation snapshot drift")
    return observed

def command_plan() -> int:
    phase4_path = authoritative_path(PHASE4_RESULT_FILENAME)
    candidate_path = authoritative_path(PHASE5_CANDIDATE_FILENAME)
    plan_path = authoritative_path(PHASE5_PLAN_FILENAME)
    _require_regular_nonreparse_file(phase4_path, "Phase 4 result")
    if candidate_path.exists() or plan_path.exists():
        raise RuntimeError(
            "Phase 5 plan artifacts already exist; do not overwrite automatically"
        )

    phase4_raw = phase4_path.read_bytes()
    phase4 = parse_phase4_result_bytes(phase4_raw)
    phase4_sha = hashlib.sha256(phase4_raw).hexdigest()
    _require_phase4_generation_snapshot_exact(phase4)
    _require_non_elevated_broker(phase4.binding)
    _require_controller_source_exact(phase4.binding)
    _require_local_runner_exact(phase4.binding)
    _require_remote_binding_exact(phase4.binding)

    candidate = render_phase5_exactly_one_job_candidate(
        phase4.binding,
        phase4_result_sha256=phase4_sha,
        target_probe_sha256=phase4.target_probe_sha256,
    )
    _write_exclusive(candidate_path, candidate.encode("utf-8"))
    spec = build_phase5_exactly_one_job_spec(
        phase4.binding,
        phase4_result_sha256=phase4_sha,
    )
    ast_key, _ = _configure_authority()
    ast = _powershell_attestation(
        candidate_path,
        operator_step_spec_sha256(spec),
        ast_key,
    )
    plan = build_reviewed_phase5_plan(
        phase4_result_bytes=phase4_raw,
        ast_attestation=ast,
    )
    raw_plan = phase5_plan_bytes(plan)
    _write_exclusive(plan_path, raw_plan)
    plan_sha = hashlib.sha256(raw_plan).hexdigest()

    print("PASS_TO_OPERATOR")
    print(f"phase5_plan={plan_path}")
    print(f"phase5_plan_sha256={plan_sha}")
    print(f"candidate_sha256={plan.candidate_sha256}")
    print(f"phase4_result_sha256={phase4_sha}")
    print(
        "approval_issuer="
        + str(_controller_repo_root() / "scripts" / "Approve-PrivateCiPhase5.ps1")
    )
    print("NO_PHASE5_LIVE_EFFECT_PERFORMED")
    return 0


def command_apply(expected_plan_sha256: str) -> int:
    expected_plan_sha = _require_digest(
        expected_plan_sha256,
        "expected Phase 5 plan",
    )
    phase4_path = authoritative_path(PHASE4_RESULT_FILENAME)
    candidate_path = authoritative_path(PHASE5_CANDIDATE_FILENAME)
    plan_path = authoritative_path(PHASE5_PLAN_FILENAME)
    result_path = authoritative_path(PHASE5_RESULT_FILENAME)
    transcript_path = authoritative_path(PHASE5_TRANSCRIPT_FILENAME)

    for path, description in (
        (phase4_path, "Phase 4 result"),
        (candidate_path, "Phase 5 candidate"),
        (plan_path, "Phase 5 plan"),
    ):
        _require_regular_nonreparse_file(path, description)
    if result_path.exists() or transcript_path.exists():
        raise RuntimeError(
            "Phase 5 result/transcript already exists; do not retry dispatch"
        )

    phase4_raw = phase4_path.read_bytes()
    phase4_sha = hashlib.sha256(phase4_raw).hexdigest()
    phase4 = parse_phase4_result_bytes(phase4_raw)
    plan_raw = plan_path.read_bytes()
    plan_sha = hashlib.sha256(plan_raw).hexdigest()
    if plan_sha != expected_plan_sha:
        raise RuntimeError("human-authorized Phase 5 plan SHA-256 mismatch")
    plan = parse_phase5_plan_bytes(plan_raw)
    reasons = validate_frozen_phase5_plan(
        plan,
        phase4_result_bytes=phase4_raw,
    )
    if reasons:
        raise RuntimeError("Phase 5 plan drift: " + ",".join(reasons))
    candidate_raw = candidate_path.read_bytes()
    if candidate_raw != plan.candidate.encode("utf-8"):
        raise RuntimeError("Phase 5 candidate artifact drift")

    _require_non_elevated_broker(plan.binding)
    _require_controller_source_exact(plan.binding)
    _require_local_runner_exact(plan.binding)
    _require_remote_binding_exact(plan.binding)
    _require_phase4_generation_snapshot_exact(phase4)
    approval_raw, approval_sha = _require_phase5_approval(
        plan_sha,
        plan.binding,
    )

    ast_key, evidence_key = _configure_authority()
    spec = build_phase5_exactly_one_job_spec(
        plan.binding,
        phase4_result_sha256=phase4_sha,
    )
    ast = _powershell_attestation(
        candidate_path,
        operator_step_spec_sha256(spec),
        ast_key,
    )
    prior = _authenticate_phase4_result(
        phase4_result_bytes=phase4_raw,
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
        raise RuntimeError("Phase 5 live gate blocked: " + reasons_text)

    marker_path = phase5_consumption_marker_path(phase4_sha)
    if marker_path.exists():
        raise RuntimeError(
            "Phase 4 result already consumed by Phase 5; dispatch must not be retried"
        )

    _acquire_phase5_ownership(
        plan_sha=plan_sha,
        phase4_result_sha=phase4_sha,
        approval_sha=approval_sha,
    )
    consumption_raw, consumption_sha = _validate_phase5_consumption(
        phase4_result_sha=phase4_sha,
        plan_sha=plan_sha,
        approval_sha=approval_sha,
    )

    started_at = datetime.now(timezone.utc).isoformat()
    child_exit_code: int | None = None
    workflow_run_id: int | None = None
    child_stdout = ""
    child_stderr = ""
    runner_process_id: int | None = None
    runner_process_owner = ""
    try:
        if plan_path.read_bytes() != plan_raw:
            raise RuntimeError("Phase 5 plan changed after ownership acquisition")
        if phase4_path.read_bytes() != phase4_raw:
            raise RuntimeError(
                "Phase 4 result changed after Phase 5 ownership acquisition"
            )
        if candidate_path.read_bytes() != candidate_raw:
            raise RuntimeError(
                "Phase 5 candidate changed after ownership acquisition"
            )
        if _approval_path(plan_sha).read_bytes() != approval_raw:
            raise RuntimeError(
                "Phase 5 approval changed after ownership acquisition"
            )
        _require_controller_source_exact(plan.binding)
        _require_local_runner_exact(plan.binding)
        _require_remote_binding_exact(plan.binding)
        _require_phase4_generation_snapshot_exact(phase4)

        completed = _completed(
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(candidate_path),
            cwd=_controller_repo_root(),
        )
        child_exit_code = completed.returncode
        child_stdout = completed.stdout
        child_stderr = completed.stderr
        ended_at = datetime.now(timezone.utc).isoformat()

        try:
            workflow_run_id = _extract_workflow_run_id(child_stdout)
        except RuntimeError:
            workflow_run_id = None

        try:
            runner_process_id, runner_process_owner = (
                _extract_runner_process_identity(child_stdout)
            )
        except RuntimeError:
            runner_process_id = None
            runner_process_owner = ""

        if child_exit_code != 0:
            raise RuntimeError(
                f"Phase 5 candidate failed with exit {child_exit_code}; "
                "dispatch must not be retried"
            )
        if "PHASE5_EXACTLY_ONE_JOB_ATTEMPT_COMPLETE" not in {
            line.strip() for line in child_stdout.splitlines() if line.strip()
        }:
            raise RuntimeError(
                "Phase 5 success marker missing; dispatch must not be retried"
            )
        workflow_run_id = _extract_workflow_run_id(child_stdout)
        runner_process_id, runner_process_owner = (
            _extract_runner_process_identity(child_stdout)
        )
        expected_owner = (
            plan.binding.host + "\\" + plan.binding.target_identity
        )
        if runner_process_owner.casefold() != expected_owner.casefold():
            raise RuntimeError(
                "Phase 5 runner process owner mismatch; dispatch must not be retried"
            )

        readback = _read_exact_phase5_run_job(
            binding=plan.binding,
            expected_workflow_run_id=workflow_run_id,
        )
        _require_controller_source_exact(plan.binding)
        _require_repository_pr_workflow_exact(plan.binding)

        security_result_path, security_stdout_path, security_stderr_path = (
            _security_probe_paths(plan.binding)
        )
        for path, description in (
            (security_result_path, "Phase 5 security probe result"),
            (security_stdout_path, "Phase 5 security probe stdout"),
            (security_stderr_path, "Phase 5 security probe stderr"),
        ):
            _require_regular_nonreparse_file(path, description)
        security_result_raw = security_result_path.read_bytes()
        parse_target_probe_result_bytes(
            security_result_raw,
            binding=plan.binding,
        )
        security_stdout_raw = security_stdout_path.read_bytes()
        security_stderr_raw = security_stderr_path.read_bytes()

        runner_stdout_path, runner_stderr_path = _runner_output_paths(
            plan.binding
        )
        _require_regular_nonreparse_file(
            runner_stdout_path,
            "Phase 5 runner stdout",
        )
        _require_regular_nonreparse_file(
            runner_stderr_path,
            "Phase 5 runner stderr",
        )
        runner_stdout_raw = runner_stdout_path.read_bytes()
        runner_stderr_raw = runner_stderr_path.read_bytes()

        evidence = Phase5ResultEvidence(
            schema=PHASE5_RESULT_SCHEMA,
            binding=plan.binding,
            phase5_plan_sha256=plan_sha,
            phase4_result_sha256=phase4_sha,
            human_approval_sha256=approval_sha,
            phase5_consumption_sha256=consumption_sha,
            candidate_sha256=plan.candidate_sha256,
            workflow_run_id=readback.workflow_run_id,
            workflow_run_attempt=readback.run_attempt,
            job_id=readback.job_id,
            runner_id=readback.runner_id,
            runner_name=readback.runner_name,
            runner_label=readback.runner_label,
            runner_process_id=runner_process_id,
            runner_process_owner=runner_process_owner,
            runner_child_exit_code=child_exit_code,
            security_probe_sha256=phase4.target_probe_sha256,
            security_probe_result_sha256=hashlib.sha256(
                security_result_raw
            ).hexdigest(),
            security_probe_stdout_sha256=hashlib.sha256(
                security_stdout_raw
            ).hexdigest(),
            security_probe_stderr_sha256=hashlib.sha256(
                security_stderr_raw
            ).hexdigest(),
            runner_stdout_sha256=hashlib.sha256(
                runner_stdout_raw
            ).hexdigest(),
            runner_stderr_sha256=hashlib.sha256(
                runner_stderr_raw
            ).hexdigest(),
            status=PHASE5_RESULT_STATUS,
            completed_at=ended_at,
        )
        result_raw = phase5_result_bytes(evidence)

        _write_attempt_transcript(
            path=transcript_path,
            started_at=started_at,
            ended_at=ended_at,
            plan_sha=plan_sha,
            phase4_result_sha=phase4_sha,
            approval_sha=approval_sha,
            consumption_sha=consumption_sha,
            child_exit_code=child_exit_code,
            workflow_run_id=workflow_run_id,
            runner_process_id=runner_process_id,
            runner_process_owner=runner_process_owner,
            stdout=child_stdout,
            stderr=child_stderr,
            status=PHASE5_RESULT_STATUS,
        )
        _write_exclusive(result_path, result_raw)

        print(PHASE5_RESULT_STATUS)
        print(f"workflow_run_id={workflow_run_id}")
        print(f"job_id={readback.job_id}")
        print(f"result={result_path}")
        print(f"result_sha256={hashlib.sha256(result_raw).hexdigest()}")
        print(f"transcript={transcript_path}")
        return 0
    except Exception as error:
        ended_at = datetime.now(timezone.utc).isoformat()
        if not transcript_path.exists():
            _write_attempt_transcript(
                path=transcript_path,
                started_at=started_at,
                ended_at=ended_at,
                plan_sha=plan_sha,
                phase4_result_sha=phase4_sha,
                approval_sha=approval_sha,
                consumption_sha=consumption_sha,
                child_exit_code=child_exit_code,
                workflow_run_id=workflow_run_id,
                runner_process_id=runner_process_id,
                runner_process_owner=runner_process_owner,
                stdout=child_stdout,
                stderr=child_stderr,
                status="PHASE5_FAILED_OR_UNCERTAIN",
                error=str(error),
            )
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded #225 Phase 5 exactly-one-job harness"
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
        raise RuntimeError("unsupported Phase 5 command")
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
