from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from agent_controller.private_ci_human_approval import validate_approval_acl_state


CONSUMPTION_SCHEMA = "agent-controller.private-ci-live-registration-consumed.v2"
CONSUMPTION_ROOT = Path(r"C:\ProgramData\agent-controller-private-ci-authority")
CONSUMPTION_FILENAME_PREFIX = "issue217-live-registration-"


@dataclass(frozen=True, slots=True)
class ProtectedConsumptionMarker:
    schema: str
    plan_sha256: str
    phase0_evidence_sha256: str
    human_approval_sha256: str
    consumed_at: str


def _require_sha256(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"consumption marker {field} invalid")
    return value


def consumption_marker_path(plan_sha256: str) -> Path:
    digest = _require_sha256(plan_sha256, "plan SHA-256")
    return CONSUMPTION_ROOT / f"{CONSUMPTION_FILENAME_PREFIX}{digest}.consumed.json"


def canonical_consumption_bytes(payload: dict[str, object]) -> bytes:
    ordered = {
        "schema": payload["schema"],
        "plan_sha256": payload["plan_sha256"],
        "phase0_evidence_sha256": payload["phase0_evidence_sha256"],
        "human_approval_sha256": payload["human_approval_sha256"],
        "consumed_at": payload["consumed_at"],
    }
    return (
        json.dumps(ordered, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def parse_consumption_marker_bytes(
    raw: bytes,
    *,
    expected_plan_sha256: str,
    expected_phase0_evidence_sha256: str,
    expected_human_approval_sha256: str,
) -> ProtectedConsumptionMarker:
    if type(raw) is not bytes:
        raise ValueError("consumption marker must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("consumption marker JSON invalid") from error

    required = {
        "schema",
        "plan_sha256",
        "phase0_evidence_sha256",
        "human_approval_sha256",
        "consumed_at",
    }
    if type(payload) is not dict or set(payload) != required:
        raise ValueError("consumption marker shape invalid")
    if raw != canonical_consumption_bytes(payload):
        raise ValueError("consumption marker is not canonical")
    if payload.get("schema") != CONSUMPTION_SCHEMA:
        raise ValueError("consumption marker schema invalid")

    plan_sha = _require_sha256(payload.get("plan_sha256"), "plan SHA-256")
    phase0_sha = _require_sha256(
        payload.get("phase0_evidence_sha256"),
        "Phase 0 SHA-256",
    )
    approval_sha = _require_sha256(
        payload.get("human_approval_sha256"),
        "human approval SHA-256",
    )
    if plan_sha != expected_plan_sha256:
        raise ValueError("consumption marker plan SHA-256 mismatch")
    if phase0_sha != expected_phase0_evidence_sha256:
        raise ValueError("consumption marker Phase 0 SHA-256 mismatch")
    if approval_sha != expected_human_approval_sha256:
        raise ValueError("consumption marker human approval SHA-256 mismatch")

    consumed_at = payload.get("consumed_at")
    if type(consumed_at) is not str or not consumed_at:
        raise ValueError("consumption marker consumed_at invalid")
    try:
        parsed = datetime.fromisoformat(consumed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("consumption marker consumed_at invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("consumption marker consumed_at must be timezone-aware")

    return ProtectedConsumptionMarker(
        schema=payload["schema"],
        plan_sha256=plan_sha,
        phase0_evidence_sha256=phase0_sha,
        human_approval_sha256=approval_sha,
        consumed_at=consumed_at,
    )


def validate_consumption_acl_state(payload: object) -> None:
    try:
        validate_approval_acl_state(payload)
    except ValueError as error:
        raise ValueError(f"consumption marker ACL invalid: {error}") from error


def validate_consumption_container_acl_state(payload: object) -> None:
    try:
        validate_approval_acl_state(payload)
    except ValueError as error:
        raise ValueError(f"consumption authority container ACL invalid: {error}") from error


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


def read_consumption_acl_state(path: Path) -> dict[str, object]:
    quoted_path = str(path).replace("'", "''")
    mutation_mask = " -bor\n    ".join(
        f"[Security.AccessControl.FileSystemRights]::{right}"
        for right in _ATOMIC_MUTATING_FILE_SYSTEM_RIGHTS
    )
    script = rf"""
$ErrorActionPreference = 'Stop'
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
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        raise ValueError(f"ACL readback unavailable for {path}") from error

    if completed.returncode != 0:
        raise ValueError(f"ACL readback failed for {path}: {completed.stderr.strip()}")
    try:
        payload = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"ACL readback invalid for {path}") from error
    if type(payload) is not dict:
        raise ValueError(f"ACL readback shape invalid for {path}")
    return payload


FILE_ATTRIBUTE_REPARSE_POINT = 0x400

_INSTALL_PROTECTED_MARKER_ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$LiteralPath = $env:TARGET_MARKER_PATH
if ([string]::IsNullOrWhiteSpace($LiteralPath)) {
    throw "TARGET_MARKER_PATH environment variable is required"
}
if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
    throw "Marker path is missing before ACL installation: $LiteralPath"
}
$Item = Get-Item -LiteralPath $LiteralPath -Force
if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Reparse point blocked at protected marker boundary: $LiteralPath"
}

$SystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$AdministratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$UsersSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')

$FileAcl = New-Object Security.AccessControl.FileSecurity
$FileAcl.SetAccessRuleProtection($true, $false)

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $FileAcl.SetOwner($AdministratorsSid)
}

$NoneInheritance = [Security.AccessControl.InheritanceFlags]::None
$NonePropagation = [Security.AccessControl.PropagationFlags]::None
$Allow = [Security.AccessControl.AccessControlType]::Allow

foreach ($Entry in @(
    @($SystemSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($AdministratorsSid, [Security.AccessControl.FileSystemRights]::FullControl),
    @($UsersSid, [Security.AccessControl.FileSystemRights]::ReadAndExecute)
)) {
    $FileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $Entry[0], $Entry[1], $NoneInheritance, $NonePropagation, $Allow
    )))
}

Set-Acl -LiteralPath $LiteralPath -AclObject $FileAcl

$ItemAfter = Get-Item -LiteralPath $LiteralPath -Force
if (($ItemAfter.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Reparse point blocked after protected marker ACL installation: $LiteralPath"
}
""".strip()


def install_protected_marker_acl(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"marker missing or not a regular file: {path}")
    try:
        stat_result = path.lstat()
    except OSError as error:
        raise ValueError(f"marker stat failed: {path}") from error
    if getattr(stat_result, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"marker ReparsePoint blocked: {path}")

    env = dict(os.environ, TARGET_MARKER_PATH=str(path))
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                _INSTALL_PROTECTED_MARKER_ACL_SCRIPT,
            ],
            env=env,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        raise ValueError(
            f"protected marker ACL installation unavailable for {path}"
        ) from error

    if completed.returncode != 0:
        raise ValueError(
            f"protected marker ACL installation failed for {path}: {completed.stderr.strip()}"
        )

    if not path.is_file() or path.is_symlink():
        raise ValueError(
            f"marker missing or not a regular file after ACL installation: {path}"
        )
    try:
        stat_result_after = path.lstat()
    except OSError as error:
        raise ValueError(f"marker stat failed after ACL installation: {path}") from error
    if getattr(stat_result_after, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"marker ReparsePoint blocked after ACL installation: {path}")

