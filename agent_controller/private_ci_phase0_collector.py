from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from agent_controller.private_ci_phase0_evidence import (
    PHASE0_EVIDENCE_SCHEMA,
    Phase0Evidence,
    phase0_freeze_mismatch_reason_codes,
    phase0_reason_codes,
)
from agent_controller.private_ci_pilot_identity import (
    PrivateCiPilotIdentityFreeze,
    pilot_identity_freeze_reason_codes,
)
from agent_controller.private_ci_runner_readback import read_all_runner_items

CONTROLLER_REPOSITORY_URL = "https://github.com/oimus1976/agent-controller.git"
PYTHON_EXECUTABLE = r"C:\Program Files\Python312\python.exe"

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
PathExists = Callable[[Path], bool]
Now = Callable[[], datetime]


def _default_command_runner(*command: str, cwd=None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=None if cwd is None else str(cwd),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _default_path_exists(path: Path) -> bool:
    return path.exists()


def _default_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_success(completed: subprocess.CompletedProcess[str], label: str) -> str:
    if completed.returncode != 0:
        raise ValueError(f"phase0 collection failed: {label}")
    return completed.stdout.strip()


def _json_output(completed: subprocess.CompletedProcess[str], label: str) -> object:
    text = _require_success(completed, label)
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"phase0 collection invalid JSON: {label}") from error


def _local_probe(
    command_runner: CommandRunner,
    target_identity: str,
) -> dict[str, object]:
    quoted_target = target_identity.replace("'", "''")
    script = rf"""
$ErrorActionPreference = 'Stop'
$TargetName = '{quoted_target}'
$Target = Get-LocalUser -Name $TargetName -ErrorAction SilentlyContinue
$TargetEnabled = $false
$TargetAdmin = $false
if ($null -ne $Target) {
    $TargetEnabled = [bool]$Target.Enabled
    $AdminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $AdminGroup = Get-LocalGroup -SID $AdminSid
    $Qualified = "$env:COMPUTERNAME\$TargetName"
    $Members = @(Get-LocalGroupMember -Group $AdminGroup.Name -ErrorAction Stop)
    $TargetAdmin = $null -ne ($Members | Where-Object {
        $_.Name -ieq $Qualified -or $_.Name -ieq $TargetName
    })
}
$RunnerProcesses = @(
    Get-CimInstance Win32_Process -ErrorAction Stop |
        Where-Object { $_.Name -match 'Runner|actions' }
)
$RunnerServices = @(
    Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object {
            $_.Name -match 'runner|actions' -or
            $_.DisplayName -match 'runner|actions'
        }
)
$RunnerTasks = @(
    Get-ScheduledTask -ErrorAction Stop |
        Where-Object {
            $_.TaskName -match 'runner|actions' -or
            $_.TaskPath -match 'runner|actions'
        }
)
[ordered]@{
    host = $env:COMPUTERNAME
    broker_identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    target_identity_enabled = $TargetEnabled
    target_identity_admin = $TargetAdmin
    runner_process_count = $RunnerProcesses.Count
    runner_service_count = $RunnerServices.Count
    runner_task_count = $RunnerTasks.Count
    powershell_version = $PSVersionTable.PSVersion.ToString()
} | ConvertTo-Json -Compress
""".strip()
    completed = command_runner(
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    )
    payload = _json_output(completed, "local-probe")
    if type(payload) is not dict:
        raise ValueError("phase0 collection invalid local probe shape")
    return payload


def _gh_json(command_runner: CommandRunner, endpoint: str) -> object:
    return _json_output(
        command_runner("gh.exe", "api", endpoint),
        f"github:{endpoint}",
    )


def _runner_items(
    command_runner: CommandRunner,
    repository: str,
) -> tuple[dict[str, object], ...]:
    base = f"repos/{repository}/actions/runners?per_page=100"

    def fetch_page(page: int) -> object:
        endpoint = base if page == 1 else f"{base}&page={page}"
        return _gh_json(command_runner, endpoint)

    return read_all_runner_items(fetch_page)


def _matching_runner_count(
    items: tuple[dict[str, object], ...],
    *,
    runner_name: str,
    runner_label: str,
) -> int:
    count = 0
    for item in items:
        if type(item.get("labels")) is not list:
            raise ValueError("phase0 collection invalid runner item")
        labels = {
            label.get("name")
            for label in item["labels"]
            if type(label) is dict and type(label.get("name")) is str
        }
        if item.get("name") == runner_name or runner_label in labels:
            count += 1
    return count


def collect_phase0_evidence(
    controller_tree: Path,
    *,
    pilot_freeze: PrivateCiPilotIdentityFreeze,
    command_runner: CommandRunner = _default_command_runner,
    path_exists: PathExists = _default_path_exists,
    now: Now = _default_now,
) -> Phase0Evidence:
    freeze_reasons = pilot_identity_freeze_reason_codes(pilot_freeze)
    if freeze_reasons:
        raise ValueError(
            "phase0 pilot freeze blocked: " + ",".join(freeze_reasons)
        )
    tree = str(controller_tree)
    if tree.casefold() != pilot_freeze.controller_tree.casefold():
        raise ValueError("phase0 controller tree differs from pilot freeze")
    local_head = _require_success(
        command_runner("git.exe", "-C", tree, "rev-parse", "HEAD"),
        "controller-head",
    )
    status = command_runner(
        "git.exe",
        "-C",
        tree,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status.returncode != 0:
        raise ValueError("phase0 collection failed: controller-status")
    remote_line = _require_success(
        command_runner(
            "git.exe",
            "ls-remote",
            CONTROLLER_REPOSITORY_URL,
            "refs/heads/main",
        ),
        "controller-main",
    )
    remote_parts = remote_line.split()
    remote_main = remote_parts[0] if remote_parts else ""
    if remote_main != pilot_freeze.controller_main_sha:
        raise ValueError("phase0 controller main differs from pilot freeze")
    if local_head != pilot_freeze.controller_main_sha:
        raise ValueError("phase0 controller tree HEAD differs from pilot freeze")

    local = _local_probe(command_runner, pilot_freeze.target_identity)

    python = command_runner(PYTHON_EXECUTABLE, "--version")
    if python.returncode != 0:
        raise ValueError("phase0 collection failed: python-version")
    python_text = (python.stdout or python.stderr).strip()
    python_version = python_text.removeprefix("Python ").strip()

    repository = _gh_json(command_runner, f"repos/{pilot_freeze.repository}")
    if type(repository) is not dict:
        raise ValueError("phase0 collection invalid repository readback")

    pr = _gh_json(command_runner, f"repos/{pilot_freeze.repository}/pulls/{pilot_freeze.pull_request_number}")
    if type(pr) is not dict or type(pr.get("head")) is not dict or type(pr.get("base")) is not dict:
        raise ValueError("phase0 collection invalid PR readback")
    head_repo = pr["head"].get("repo")
    if type(head_repo) is not dict:
        raise ValueError("phase0 collection invalid PR head repository")

    branch = _gh_json(command_runner, f"repos/{pilot_freeze.repository}/branches/main")
    if type(branch) is not dict or type(branch.get("commit")) is not dict:
        raise ValueError("phase0 collection invalid workflow branch readback")
    observed_workflow_sha = str(branch["commit"].get("sha", ""))
    workflow_file = _gh_json(
        command_runner,
        (
            f"repos/{pilot_freeze.repository}/contents/{pilot_freeze.workflow_path}"
            f"?ref={observed_workflow_sha}"
        ),
    )
    if (
        type(workflow_file) is not dict
        or workflow_file.get("type") != "file"
        or workflow_file.get("path") != pilot_freeze.workflow_path
    ):
        raise ValueError("phase0 collection invalid workflow path readback")

    runners = _runner_items(command_runner, pilot_freeze.repository)

    return Phase0Evidence(
        schema=PHASE0_EVIDENCE_SCHEMA,
        collected_at=now().isoformat(),
        status="PHASE0_PASS",
        controller_main_sha=remote_main,
        controller_tree=tree,
        controller_tree_head_sha=local_head,
        controller_tree_clean=not bool(status.stdout.strip()),
        host=str(local.get("host", "")),
        broker_identity=str(local.get("broker_identity", "")),
        target_identity=pilot_freeze.target_identity,
        target_identity_enabled=local.get("target_identity_enabled") is True,
        target_identity_admin=local.get("target_identity_admin") is True,
        repository=pilot_freeze.repository,
        repository_visibility=str(repository.get("visibility", "")),
        default_branch=str(repository.get("default_branch", "")),
        pull_request_number=pilot_freeze.pull_request_number,
        pull_request_state=str(pr.get("state", "")),
        pull_request_draft=pr.get("draft") is True,
        pull_request_head_repository=str(head_repo.get("full_name", "")),
        pull_request_head_sha=str(pr["head"].get("sha", "")),
        pull_request_base=str(pr["base"].get("ref", "")),
        workflow_sha=observed_workflow_sha,
        workflow_path=pilot_freeze.workflow_path,
        runner_name=pilot_freeze.runner_name,
        runner_label=pilot_freeze.runner_label,
        environment_generation=pilot_freeze.environment_generation,
        runner_root=pilot_freeze.runner_root,
        work_folder=pilot_freeze.work_folder,
        runner_root_exists=path_exists(Path(pilot_freeze.runner_root)),
        matching_pilot_runner_count=_matching_runner_count(
            runners,
            runner_name=pilot_freeze.runner_name,
            runner_label=pilot_freeze.runner_label,
        ),
        runner_process_count=int(local.get("runner_process_count", -1)),
        runner_service_count=int(local.get("runner_service_count", -1)),
        runner_task_count=int(local.get("runner_task_count", -1)),
        powershell_version=str(local.get("powershell_version", "")),
        python_version=python_version,
    )


def collect_validated_phase0_evidence(
    controller_tree: Path,
    *,
    pilot_freeze: PrivateCiPilotIdentityFreeze,
    command_runner: CommandRunner = _default_command_runner,
    path_exists: PathExists = _default_path_exists,
    now: Now = _default_now,
) -> Phase0Evidence:
    evidence = collect_phase0_evidence(
        controller_tree,
        pilot_freeze=pilot_freeze,
        command_runner=command_runner,
        path_exists=path_exists,
        now=now,
    )
    reasons = (
        phase0_reason_codes(evidence)
        + phase0_freeze_mismatch_reason_codes(evidence, pilot_freeze)
    )
    if reasons:
        raise ValueError("phase0 evidence blocked: " + ",".join(reasons))
    return evidence


def phase0_state_matches(frozen: Phase0Evidence, fresh: Phase0Evidence) -> bool:
    if type(frozen) is not Phase0Evidence or type(fresh) is not Phase0Evidence:
        return False
    frozen_payload = frozen.to_dict()
    fresh_payload = fresh.to_dict()
    frozen_payload.pop("collected_at", None)
    fresh_payload.pop("collected_at", None)
    return frozen_payload == fresh_payload
