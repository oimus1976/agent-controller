#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from agent_controller.private_ci_live_registration_runtime import (
    authoritative_path,
)
from agent_controller.private_ci_pilot_identity import (
    PRIVATE_CI_BROKER_IDENTITY,
    PRIVATE_CI_HOST,
    PRIVATE_CI_RUNNER_LABEL,
    PRIVATE_CI_TARGET_IDENTITY,
    build_fresh_pilot_identity_freeze,
    pilot_identity_freeze_bytes,
    validate_pilot_workflow_runner_exclusivity,
)
from agent_controller.private_ci_runner_readback import read_all_runner_items


PILOT_FREEZE_FILENAME = "issue216-pilot-identity-freeze.json"
CONTROLLER_REPOSITORY_URL = "https://github.com/oimus1976/agent-controller.git"


def _controller_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _completed(*command: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=None if cwd is None else str(cwd),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _require_success(completed: subprocess.CompletedProcess[str], label: str) -> str:
    if completed.returncode != 0:
        raise RuntimeError(f"fresh freeze readback failed: {label}")
    return completed.stdout.strip()


def _gh_json(endpoint: str) -> object:
    completed = _completed("gh.exe", "api", endpoint)
    text = _require_success(completed, f"github:{endpoint}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"fresh freeze GitHub JSON invalid: {endpoint}"
        ) from error


def _runner_items(repository: str) -> tuple[dict[str, object], ...]:
    base = f"repos/{repository}/actions/runners?per_page=100"

    def fetch_page(page: int) -> object:
        endpoint = base if page == 1 else f"{base}&page={page}"
        return _gh_json(endpoint)

    return read_all_runner_items(fetch_page)


def _local_zero_residual() -> None:
    script = r"""
$ErrorActionPreference = 'Stop'
$Target = Get-LocalUser -Name 'ac-runner' -ErrorAction SilentlyContinue
$TargetEnabled = $false
$TargetAdmin = $false
if ($null -ne $Target) {
    $TargetEnabled = [bool]$Target.Enabled
    $AdminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $AdminGroup = Get-LocalGroup -SID $AdminSid
    $Qualified = "$env:COMPUTERNAME\ac-runner"
    $Members = @(Get-LocalGroupMember -Group $AdminGroup.Name -ErrorAction Stop)
    $TargetAdmin = $null -ne ($Members | Where-Object {
        $_.Name -ieq $Qualified -or $_.Name -ieq 'ac-runner'
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
    target_enabled = $TargetEnabled
    target_admin = $TargetAdmin
    runner_process_count = $RunnerProcesses.Count
    runner_service_count = $RunnerServices.Count
    runner_task_count = $RunnerTasks.Count
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
    text = _require_success(completed, "local-zero-residual")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError("fresh freeze local readback invalid") from error
    if type(payload) is not dict:
        raise RuntimeError("fresh freeze local readback shape invalid")
    if str(payload.get("host", "")).casefold() != PRIVATE_CI_HOST.casefold():
        raise RuntimeError("fresh freeze host mismatch")
    if (
        str(payload.get("broker_identity", "")).casefold()
        != PRIVATE_CI_BROKER_IDENTITY.casefold()
    ):
        raise RuntimeError("fresh freeze broker identity mismatch")
    if payload.get("target_enabled") is not True:
        raise RuntimeError("fresh freeze target identity is not enabled")
    if payload.get("target_admin") is not False:
        raise RuntimeError("fresh freeze target identity is admin or uncertain")
    for field in (
        "runner_process_count",
        "runner_service_count",
        "runner_task_count",
    ):
        if payload.get(field) != 0:
            raise RuntimeError(f"fresh freeze residual state present: {field}")


def _require_controller_main_exact() -> tuple[str, str]:
    root = _controller_repo_root()
    local_head = _require_success(
        _completed("git.exe", "-C", str(root), "rev-parse", "HEAD"),
        "controller-head",
    )
    status = _completed(
        "git.exe",
        "-C",
        str(root),
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status.returncode != 0 or status.stdout.strip():
        raise RuntimeError("fresh freeze controller tree not clean")
    remote_line = _require_success(
        _completed(
            "git.exe",
            "ls-remote",
            CONTROLLER_REPOSITORY_URL,
            "refs/heads/main",
        ),
        "controller-main",
    )
    parts = remote_line.split()
    remote_main = parts[0] if parts else ""
    if local_head != remote_main:
        raise RuntimeError("fresh freeze controller HEAD is not current main")
    return remote_main, str(root)


def _require_target_exact(
    *,
    repository: str,
    pull_request_number: int,
    workflow_path: str,
) -> tuple[str, str]:
    repo = _gh_json(f"repos/{repository}")
    if (
        type(repo) is not dict
        or repo.get("visibility") != "private"
        or repo.get("default_branch") != "main"
    ):
        raise RuntimeError("fresh freeze repository boundary invalid")

    pr = _gh_json(f"repos/{repository}/pulls/{pull_request_number}")
    if type(pr) is not dict:
        raise RuntimeError("fresh freeze PR readback invalid")
    head = pr.get("head")
    base = pr.get("base")
    if (
        pr.get("state") != "open"
        or pr.get("draft") is not True
        or type(head) is not dict
        or type(base) is not dict
        or type(head.get("repo")) is not dict
        or head["repo"].get("full_name") != repository
        or base.get("ref") != "main"
    ):
        raise RuntimeError("fresh freeze PR boundary invalid")
    target_sha = head.get("sha")
    if type(target_sha) is not str:
        raise RuntimeError("fresh freeze target SHA invalid")

    branch = _gh_json(f"repos/{repository}/branches/main")
    if type(branch) is not dict or type(branch.get("commit")) is not dict:
        raise RuntimeError("fresh freeze main readback invalid")
    workflow_sha = branch["commit"].get("sha")
    if type(workflow_sha) is not str:
        raise RuntimeError("fresh freeze workflow SHA invalid")
    workflow = _gh_json(
        f"repos/{repository}/contents/{workflow_path}?ref={workflow_sha}"
    )
    if (
        type(workflow) is not dict
        or workflow.get("type") != "file"
        or workflow.get("path") != workflow_path
    ):
        raise RuntimeError("fresh freeze workflow path invalid")
    return target_sha, workflow_sha



def _require_workflow_runner_exclusivity(
    *,
    repository: str,
    workflow_sha: str,
    trusted_workflow_path: str,
) -> None:
    inventory = _gh_json(
        f"repos/{repository}/contents/.github/workflows?ref={workflow_sha}"
    )
    if type(inventory) is not list or not inventory:
        raise RuntimeError("fresh freeze workflow inventory invalid")

    sources: dict[str, str] = {}
    for item in inventory:
        if (
            type(item) is not dict
            or item.get("type") != "file"
            or type(item.get("path")) is not str
        ):
            raise RuntimeError("fresh freeze workflow inventory entry invalid")
        path = item["path"]
        if not path.endswith((".yml", ".yaml")):
            raise RuntimeError("fresh freeze unexpected workflow entry")
        payload = _gh_json(
            f"repos/{repository}/contents/{path}?ref={workflow_sha}"
        )
        if (
            type(payload) is not dict
            or payload.get("type") != "file"
            or payload.get("path") != path
            or payload.get("encoding") != "base64"
            or type(payload.get("content")) is not str
        ):
            raise RuntimeError(
                f"fresh freeze workflow content readback invalid: {path}"
            )
        encoded = payload["content"].replace("\n", "")
        try:
            raw = base64.b64decode(encoded, validate=True)
            source = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise RuntimeError(
                f"fresh freeze workflow content decode failed: {path}"
            ) from error
        sources[path] = source

    try:
        validate_pilot_workflow_runner_exclusivity(
            sources,
            trusted_workflow_path=trusted_workflow_path,
        )
    except ValueError as error:
        raise RuntimeError(
            "fresh freeze workflow runner exclusivity invalid"
        ) from error

def _require_no_pilot_runner(repository: str, runner_name: str) -> None:
    matches = []
    for item in _runner_items(repository):
        labels = item.get("labels")
        if type(labels) is not list:
            raise RuntimeError("fresh freeze runner labels invalid")
        label_names = {
            label.get("name")
            for label in labels
            if type(label) is dict and type(label.get("name")) is str
        }
        if item.get("name") == runner_name or PRIVATE_CI_RUNNER_LABEL in label_names:
            matches.append(item)
    if matches:
        raise RuntimeError("fresh freeze stale eligible pilot runner exists")


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create one fresh #216 private-CI pilot identity freeze from current readback"
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request-number", required=True, type=int)
    parser.add_argument("--workflow-path", required=True)
    options = parser.parse_args()

    try:
        output = authoritative_path(PILOT_FREEZE_FILENAME)
        if output.exists():
            raise RuntimeError(
                "authoritative pilot identity freeze already exists; do not overwrite automatically"
            )

        controller_main_sha, controller_tree = _require_controller_main_exact()
        _local_zero_residual()
        target_sha, workflow_sha = _require_target_exact(
            repository=options.repository,
            pull_request_number=options.pull_request_number,
            workflow_path=options.workflow_path,
        )
        _require_workflow_runner_exclusivity(
            repository=options.repository,
            workflow_sha=workflow_sha,
            trusted_workflow_path=options.workflow_path,
        )

        nonce = secrets.token_hex(8)
        freeze = build_fresh_pilot_identity_freeze(
            repository=options.repository,
            pull_request_number=options.pull_request_number,
            target_sha=target_sha,
            workflow_sha=workflow_sha,
            workflow_path=options.workflow_path,
            nonce=nonce,
            controller_main_sha=controller_main_sha,
            controller_tree=controller_tree,
        )

        generation_root = Path(freeze.runner_root).parent
        if generation_root.exists() or Path(freeze.runner_root).exists():
            raise RuntimeError("fresh freeze generated local identity already exists")
        _require_no_pilot_runner(freeze.repository, freeze.runner_name)

        raw = pilot_identity_freeze_bytes(freeze)
        _write_exclusive(output, raw)
        digest = hashlib.sha256(raw).hexdigest()

        print("PILOT_IDENTITY_FREEZE_CREATED")
        print(f"freeze={output}")
        print(f"freeze_sha256={digest}")
        print(f"runner_name={freeze.runner_name}")
        print(f"environment_generation={freeze.environment_generation}")
        print(f"target_sha={freeze.target_sha}")
        print(f"workflow_sha={freeze.workflow_sha}")
        print("NO_RUNNER_REGISTRATION_OR_WORKFLOW_DISPATCH_PERFORMED")
        return 0
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
