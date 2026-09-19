#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from agent_controller.private_ci_consumption_marker import (
    CONSUMPTION_ROOT,
    consumption_marker_path,
    validate_consumption_acl_state,
    validate_consumption_container_acl_state,
)
from agent_controller.private_ci_human_approval import (
    approval_filename,
    validate_approval_acl_state,
)
from agent_controller.private_ci_live_registration_runtime import (
    authoritative_path,
    parse_plan_bytes,
)
from agent_controller.private_ci_phase4_contract import (
    registration_handoff_bytes,
)
from agent_controller.private_ci_registration_handoff import (
    build_registration_handoff_evidence,
)
from agent_controller.private_ci_runner_readback import read_all_runner_items
from agent_controller.private_ci_runner_tree_snapshot import (
    runner_generation_snapshot_bytes,
)


PHASE0_FILENAME = "issue216-phase0-canonical.json"
REGISTRATION_PLAN_FILENAME = "issue217-live-registration-plan.json"
REGISTRATION_RESULT_FILENAME = "issue217-live-registration-result.json"
HANDOFF_PENDING_FILENAME = "issue225-registration-handoff.pending.json"
HANDOFF_FILENAME = "issue225-registration-handoff.json"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

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
    quoted_path = str(path).replace("'", "''")
    mutation_mask = " -bor\n    ".join(
        f"[Security.AccessControl.FileSystemRights]::{right}"
        for right in _ATOMIC_MUTATING_FILE_SYSTEM_RIGHTS
    )
    script = rf"""
$Acl = Get-Acl -LiteralPath '{quoted_path}'
$OwnerAccount = New-Object -TypeName Security.Principal.NTAccount -ArgumentList $Acl.Owner
$OwnerSid = $OwnerAccount.Translate([Security.Principal.SecurityIdentifier]).Value
$MutationMask = [int](
    {mutation_mask}
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
        raise RuntimeError(f"ACL readback failed: {path}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"ACL readback invalid: {path}") from error


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
    repository = _gh_json(f"repos/{binding.repository}")
    if (
        type(repository) is not dict
        or repository.get("visibility") != "private"
        or repository.get("default_branch") != "main"
    ):
        raise RuntimeError("registration handoff repository drift")

    pr = _gh_json(
        f"repos/{binding.repository}/pulls/{binding.pull_request_number}"
    )
    if type(pr) is not dict:
        raise RuntimeError("registration handoff PR readback invalid")
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
        raise RuntimeError("registration handoff PR binding drift")

    branch = _gh_json(f"repos/{binding.repository}/branches/main")
    if (
        type(branch) is not dict
        or type(branch.get("commit")) is not dict
        or branch["commit"].get("sha") != binding.workflow_sha
    ):
        raise RuntimeError("registration handoff workflow SHA drift")
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
        raise RuntimeError("registration handoff workflow path drift")

    items = _github_runner_items(binding.repository)
    eligible: list[dict[str, object]] = []
    for item in items:
        labels = item.get("labels")
        if type(labels) is not list:
            raise RuntimeError("registration handoff runner labels invalid")
        label_names = {
            label.get("name")
            for label in labels
            if type(label) is dict and type(label.get("name")) is str
        }
        if (
            item.get("id") == binding.runner_id
            or item.get("name") == binding.runner_name
            or binding.runner_label in label_names
        ):
            eligible.append(item)
    if len(eligible) != 1:
        raise RuntimeError("registration handoff eligible runner count unsafe")
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
        raise RuntimeError("registration handoff remote runner mismatch")


def _require_controller_source_exact(binding) -> None:
    repo = _controller_repo_root()
    if str(repo).casefold() != binding.controller_tree.casefold():
        raise RuntimeError("registration handoff controller tree mismatch")
    head = _completed("git.exe", "-C", str(repo), "rev-parse", "HEAD")
    if head.returncode != 0 or head.stdout.strip() != binding.controller_main_sha:
        raise RuntimeError("registration handoff controller HEAD drift")
    status = _completed(
        "git.exe",
        "-C",
        str(repo),
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status.returncode != 0 or status.stdout.strip():
        raise RuntimeError("registration handoff controller tree not clean")
    remote = _completed(
        "git.exe",
        "ls-remote",
        "https://github.com/oimus1976/agent-controller.git",
        "refs/heads/main",
    )
    parts = remote.stdout.split()
    remote_sha = parts[0] if remote.returncode == 0 and parts else ""
    if remote_sha != binding.controller_main_sha:
        raise RuntimeError("registration handoff controller main drift")


def _require_host_identity(binding) -> None:
    host = _completed("hostname.exe")
    identity = _completed("whoami.exe")
    if host.returncode != 0 or host.stdout.strip().casefold() != binding.host.casefold():
        raise RuntimeError("registration handoff host mismatch")
    if (
        identity.returncode != 0
        or identity.stdout.strip().casefold()
        != binding.broker_identity.casefold()
    ):
        raise RuntimeError("registration handoff broker identity mismatch")


def _publish_protected_handoff(
    *,
    expected_handoff_sha256: str,
) -> None:
    helper = (
        _controller_repo_root()
        / "scripts"
        / "Publish-PrivateCiRegistrationHandoff.ps1"
    )
    quoted = str(helper).replace("'", "''")
    command = (
        "$Child = Start-Process -FilePath 'powershell.exe' -Verb RunAs "
        "-Wait -PassThru -ArgumentList @("
        "'-NoProfile','-ExecutionPolicy','Bypass','-File',"
        f"'{quoted}','-ExpectedHandoffSha256','{expected_handoff_sha256}'"
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
        raise RuntimeError("protected registration handoff publication failed")


def main() -> int:
    try:
        phase0_path = authoritative_path(PHASE0_FILENAME)
        plan_path = authoritative_path(REGISTRATION_PLAN_FILENAME)
        result_path = authoritative_path(REGISTRATION_RESULT_FILENAME)
        pending_path = authoritative_path(HANDOFF_PENDING_FILENAME)
        handoff_path = authoritative_path(HANDOFF_FILENAME)

        for path, description in (
            (phase0_path, "Phase 0 evidence"),
            (plan_path, "registration plan"),
            (result_path, "registration result"),
        ):
            _require_regular_nonreparse_file(path, description)
        if pending_path.exists() or handoff_path.exists():
            raise RuntimeError(
                "registration handoff output already exists; do not overwrite automatically"
            )

        phase0_raw = phase0_path.read_bytes()
        plan_raw = plan_path.read_bytes()
        plan = parse_plan_bytes(plan_raw)
        plan_sha = hashlib.sha256(plan_raw).hexdigest()
        approval_path = authoritative_path(approval_filename(plan_sha))
        marker_path = consumption_marker_path(plan_sha)
        _require_regular_nonreparse_file(
            approval_path,
            "registration human approval",
        )
        _require_regular_nonreparse_file(
            marker_path,
            "registration protected consumption marker",
        )
        if not CONSUMPTION_ROOT.is_dir() or CONSUMPTION_ROOT.is_symlink():
            raise RuntimeError("registration authority root invalid")
        validate_approval_acl_state(_acl_state(approval_path))
        validate_consumption_container_acl_state(_acl_state(CONSUMPTION_ROOT))
        validate_consumption_acl_state(_acl_state(marker_path))

        result_raw = result_path.read_bytes()
        runner_settings_path = Path(plan.binding.runner_root) / ".runner"
        _require_regular_nonreparse_file(
            runner_settings_path,
            "local runner settings",
        )
        runner_settings_raw = runner_settings_path.read_bytes()
        runner_root = Path(plan.binding.runner_root)
        generation_root = runner_root.parent
        generation_snapshot_raw = runner_generation_snapshot_bytes(
            generation_root=generation_root,
            runner_root=runner_root,
            work_folder=plan.binding.work_folder,
        )

        evidence = build_registration_handoff_evidence(
            phase0_evidence_bytes=phase0_raw,
            registration_plan_bytes=plan_raw,
            human_approval_bytes=approval_path.read_bytes(),
            registration_consumption_bytes=marker_path.read_bytes(),
            registration_result_bytes=result_raw,
            local_runner_settings_bytes=runner_settings_raw,
            runner_generation_snapshot_bytes=generation_snapshot_raw,
        )
        _require_host_identity(evidence.binding)
        _require_controller_source_exact(evidence.binding)
        _require_remote_binding_exact(evidence.binding)

        handoff_raw = registration_handoff_bytes(evidence)
        handoff_sha = hashlib.sha256(handoff_raw).hexdigest()
        _write_exclusive(pending_path, handoff_raw)
        _publish_protected_handoff(
            expected_handoff_sha256=handoff_sha,
        )

        _require_regular_nonreparse_file(
            handoff_path,
            "protected registration handoff",
        )
        persisted = handoff_path.read_bytes()
        if persisted != handoff_raw:
            raise RuntimeError(
                "protected registration handoff changed during publication"
            )
        validate_approval_acl_state(_acl_state(handoff_path))
        try:
            pending_path.unlink()
        except OSError:
            pass

        print("REGISTRATION_HANDOFF_PASS")
        print(f"handoff={handoff_path}")
        print(f"handoff_sha256={handoff_sha}")
        print(f"runner_id={evidence.binding.runner_id}")
        print("NO_RUNNER_START_OR_WORKFLOW_DISPATCH_PERFORMED")
        return 0
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
