#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import ctypes
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from agent_controller.private_ci_burned_evidence_archive import (
    ARCHIVE_RETIREMENT_PASS,
    REVIEWED_CONTROLLER_SOURCE_PATHS,
    ControllerSourceBinding,
    apply_archive_plan,
    archive_plan_bytes,
    build_archive_plan,
    parse_archive_plan_bytes,
)


AUTHORITATIVE_EVIDENCE_ROOT = r"C:\Users\Public\Documents\agent-controller-handoff"
CONTROLLER_REPOSITORY_URL = "https://github.com/oimus1976/agent-controller.git"
EXPECTED_HOST = "WOBBUFFET"
EXPECTED_IDENTITY = r"WOBBUFFET\c-admin"


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


def _require_success(
    completed: subprocess.CompletedProcess[str],
    description: str,
) -> str:
    if completed.returncode != 0:
        raise RuntimeError(
            f"{description} failed with exit={completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _python_binding() -> tuple[str, str]:
    path = Path(sys.executable).resolve(strict=True)
    stat_result = path.lstat()
    if path.is_symlink() or (
        getattr(stat_result, "st_file_attributes", 0) & 0x400
    ):
        raise RuntimeError("Python executable is symlink or reparse point")
    if not path.is_file():
        raise RuntimeError("Python executable is not regular file")
    return str(path), _file_sha256(path)


def _controller_source_bindings(
    root: Path,
) -> tuple[ControllerSourceBinding, ...]:
    bindings = []
    for relative_path in REVIEWED_CONTROLLER_SOURCE_PATHS:
        pure = PurePosixPath(relative_path)
        path = root.joinpath(*pure.parts)
        stat_result = path.lstat()
        if path.is_symlink() or (
            getattr(stat_result, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeError(
                f"reviewed controller source is symlink/reparse: {relative_path}"
            )
        if not path.is_file():
            raise RuntimeError(
                f"reviewed controller source is not file: {relative_path}"
            )
        bindings.append(
            ControllerSourceBinding(
                relative_path=relative_path,
                sha256=_file_sha256(path),
                size=stat_result.st_size,
            )
        )
    return tuple(bindings)


def _trusted_system_directory() -> Path:
    if os.name != "nt":
        raise RuntimeError("trusted system directory requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_system_directory.restype = ctypes.c_uint
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    count = get_system_directory(buffer, size)
    if count == 0 or count >= size:
        raise ctypes.WinError(ctypes.get_last_error())
    return Path(buffer.value)


def _trusted_windows_powershell_path() -> Path:
    path = (
        _trusted_system_directory()
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    stat_result = path.lstat()
    if path.is_symlink() or (
        getattr(stat_result, "st_file_attributes", 0) & 0x400
    ):
        raise RuntimeError("trusted Windows PowerShell is reparse point")
    if not path.is_file():
        raise RuntimeError("trusted Windows PowerShell missing")
    return path


def _decode_reviewed_plan(
    expected_plan_sha256: str,
    expected_plan_base64: str,
):
    expected = _require_digest(expected_plan_sha256)
    if type(expected_plan_base64) is not str or not expected_plan_base64:
        raise ValueError("expected archive plan base64 invalid")
    try:
        raw = base64.b64decode(
            expected_plan_base64.encode("ascii"),
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as error:
        raise ValueError("expected archive plan base64 invalid") from error
    if hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("reviewed archive plan bytes SHA-256 mismatch")
    return expected, parse_archive_plan_bytes(raw)


def _require_digest(value: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("expected archive plan SHA-256 invalid")
    return value


def _require_controller_source_exact() -> tuple[str, Path]:
    root = _controller_repo_root()
    local_head = _require_success(
        _completed("git.exe", "-C", str(root), "rev-parse", "HEAD"),
        "controller HEAD readback",
    )
    status = _completed(
        "git.exe",
        "-C",
        str(root),
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status.returncode != 0:
        raise RuntimeError("controller tree status readback failed")
    if status.stdout.strip():
        raise RuntimeError("controller execution tree is not clean")

    remote_line = _require_success(
        _completed(
            "git.exe",
            "ls-remote",
            CONTROLLER_REPOSITORY_URL,
            "refs/heads/main",
        ),
        "controller main readback",
    )
    fields = remote_line.split()
    remote_main = fields[0] if fields else ""
    if local_head != remote_main:
        raise RuntimeError("controller HEAD is not current canonical main")
    return local_head, root


def _windows_boundary_state() -> dict[str, object]:
    if os.name != "nt":
        raise RuntimeError("Windows boundary requires Windows")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    secur32 = ctypes.WinDLL("secur32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    computer = ctypes.create_unicode_buffer(256)
    computer_size = ctypes.c_uint(len(computer))
    if not kernel32.GetComputerNameW(
        computer,
        ctypes.byref(computer_size),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    NameSamCompatible = 2
    identity_size = ctypes.c_ulong(0)
    secur32.GetUserNameExW(
        NameSamCompatible,
        None,
        ctypes.byref(identity_size),
    )
    if identity_size.value <= 1:
        raise ctypes.WinError(ctypes.get_last_error())
    identity = ctypes.create_unicode_buffer(identity_size.value)
    if not secur32.GetUserNameExW(
        NameSamCompatible,
        identity,
        ctypes.byref(identity_size),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    shell32.IsUserAnAdmin.restype = ctypes.c_bool
    return {
        "host": computer.value,
        "identity": identity.value,
        "elevated": bool(shell32.IsUserAnAdmin()),
    }

def _require_windows_elevated_boundary() -> None:
    if os.name != "nt":
        raise RuntimeError("archive apply requires Windows")
    payload = _windows_boundary_state()
    if str(payload.get("host", "")).casefold() != EXPECTED_HOST.casefold():
        raise RuntimeError("archive apply host mismatch")
    if (
        str(payload.get("identity", "")).casefold()
        != EXPECTED_IDENTITY.casefold()
    ):
        raise RuntimeError("archive apply identity mismatch")
    if payload.get("elevated") is not True:
        raise RuntimeError(
            "archive apply must run elevated through the Windows UAC boundary"
        )


def command_plan() -> int:
    controller_main_sha, controller_tree = _require_controller_source_exact()
    evidence_root = Path(AUTHORITATIVE_EVIDENCE_ROOT)
    python_executable, python_sha256 = _python_binding()
    controller_sources = _controller_source_bindings(controller_tree)
    plan = build_archive_plan(
        evidence_root=evidence_root,
        controller_main_sha=controller_main_sha,
        controller_tree=str(controller_tree),
        python_executable=python_executable,
        python_sha256=python_sha256,
        controller_sources=controller_sources,
    )
    if plan is None:
        print("BURNED_CANONICAL_ARCHIVE_NOT_REQUIRED")
        print("canonical_restart_blocking_artifacts=0")
        print("NO_MUTATION_PERFORMED")
        return 0

    raw = archive_plan_bytes(plan)
    digest = hashlib.sha256(raw).hexdigest()
    plan_base64 = base64.b64encode(raw).decode("ascii")
    bootstrap_path = (
        controller_tree
        / "scripts"
        / "Archive-PrivateCiBurnedEvidence.ps1"
    )
    bootstrap_template = bootstrap_path.read_text(encoding="utf-8")
    sha_token = "__EXPECTED_PLAN_SHA256__"
    if bootstrap_template.count(sha_token) != 1:
        raise RuntimeError("archive UAC bootstrap template marker invalid")
    rendered_bootstrap = bootstrap_template.replace(
        sha_token,
        digest,
    )
    encoded_bootstrap = base64.b64encode(
        rendered_bootstrap.encode("utf-16-le")
    ).decode("ascii")
    powershell_path = _trusted_windows_powershell_path()
    quoted_powershell = str(powershell_path).replace("'", "''")
    uac_argument = (
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {encoded_bootstrap}"
    )

    print("BURNED_CANONICAL_ARCHIVE_PLAN_READY")
    print(f"archive_plan_sha256={digest}")
    print(f"archive_directory={plan.archive_directory}")
    print(f"python_executable={plan.python_executable}")
    print(f"python_sha256={plan.python_sha256}")
    print(f"artifact_count={len(plan.items)}")
    for item in plan.items:
        print(
            "artifact="
            f"{item.filename}|sha256={item.sha256}|size={item.size}"
        )
    print("archive_plan_json=" + raw.decode("utf-8").rstrip("\n"))
    print(
        "uac_apply_command="
        "$env:AGENT_CONTROLLER_ARCHIVE_PLAN_BASE64="
        f"'{plan_base64}'; "
        "try { "
        f"Start-Process '{quoted_powershell}' -Verb RunAs -Wait "
        "-ArgumentList "
        f"\"{uac_argument}\""
        " } finally { "
        "Remove-Item Env:AGENT_CONTROLLER_ARCHIVE_PLAN_BASE64 "
        "-ErrorAction SilentlyContinue"
        " }"
    )
    print("NO_MUTATION_PERFORMED")
    return 0


def command_apply_internal(
    expected_plan_sha256: str,
    expected_plan_base64: str,
) -> int:
    expected, plan = _decode_reviewed_plan(
        expected_plan_sha256,
        expected_plan_base64,
    )
    _require_windows_elevated_boundary()

    # The elevated process runs only from the reviewed, locked source
    # snapshot created by the UAC bootstrap. Do not import or execute the
    # mutable controller checkout after elevation.
    python_executable, python_sha256 = _python_binding()
    if python_executable.casefold() != plan.python_executable.casefold():
        raise RuntimeError("reviewed archive Python executable drift")
    if python_sha256 != plan.python_sha256:
        raise RuntimeError("reviewed archive Python SHA-256 drift")

    evidence_root = Path(AUTHORITATIVE_EVIDENCE_ROOT)
    result = apply_archive_plan(
        evidence_root=evidence_root,
        plan=plan,
        expected_plan_sha256=expected,
        completed_at=datetime.now(timezone.utc),
    )
    if result.status != ARCHIVE_RETIREMENT_PASS:
        raise RuntimeError("archive apply did not reach PASS")

    print(ARCHIVE_RETIREMENT_PASS)
    print(f"archive_plan_sha256={expected}")
    print(f"archive_directory={result.archive_directory}")
    print(f"artifact_count={len(result.items)}")
    print("APPROVAL_AND_CONSUMPTION_AUTHORITY_UNCHANGED")
    print("NO_RUNNER_OR_GITHUB_LIVE_EFFECT_PERFORMED")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or apply fail-closed archival of burned #216 canonical "
            "evidence without touching approval/consumption authority"
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan")
    apply_parser = subparsers.add_parser("apply-internal")
    apply_parser.add_argument("--expected-plan-sha256", required=True)
    apply_parser.add_argument("--expected-plan-base64", required=True)
    options = parser.parse_args()

    try:
        if options.command == "plan":
            return command_plan()
        if options.command == "apply-internal":
            return command_apply_internal(
                options.expected_plan_sha256,
                options.expected_plan_base64,
            )
        raise RuntimeError("unsupported command")
    except Exception as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
