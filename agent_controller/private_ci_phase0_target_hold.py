"""#316 owner-launched target-profile hold around the strict Phase 0 collector.

The human starts the one-shot CLI and types the target password into the
Windows credential dialog of the PowerShell hold child. This module never sees
a credential. It observes the target profile state with fresh read-only
PowerShell processes before, during and after the hold, and reports the hold as
restored only when the retained-handle exit AND the independent poststate both
prove it. Nothing here writes Phase 0 evidence.
"""
from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional, Protocol

POWERSHELL_EXECUTABLE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
HOLD_SCRIPT_NAME = "Issue316-TargetProfileHold.ps1"

FRAME_AWAITING_CREDENTIAL = "HOLD_AWAITING_CREDENTIAL"
FRAME_STARTING_TARGET = "HOLD_STARTING_TARGET"
FRAME_READY_PREFIX = "HOLD_READY "
FRAME_REPORT_PREFIX = "HOLD_REPORT "

STARTUP_TIMEOUT_SECONDS = 60.0
CREDENTIAL_TIMEOUT_SECONDS = 300.0
TARGET_READY_TIMEOUT_SECONDS = 60.0
REPORT_TIMEOUT_SECONDS = 40.0
EXIT_TIMEOUT_SECONDS = 10.0
POSTSTATE_TIMEOUT_SECONDS = 90.0
POSTSTATE_INTERVAL_SECONDS = 2.0

# Facts that one profile load/unload must leave unchanged. NTUSER.DAT content
# and profile timestamps are expected to change and are not compared.
STABLE_STATE_KEYS = (
    "sid",
    "enabled",
    "admin",
    "profile",
    "profile_status",
    "account_description",
    "profile_acl",
    "hive_acl",
)

# Read-only. Same observations as the reviewed #305 Read-Issue305State.
_STATE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'
$User = Get-LocalUser -Name '__TARGET_IDENTITY__'
$Sid = $User.SID.Value
$Profiles = @(Get-CimInstance Win32_UserProfile -Filter "SID='$Sid'" -OperationTimeoutSec 5)
if ($Profiles.Count -ne 1 -or $Profiles[0].Special) { throw 'PROFILE_BINDING' }
if ($User.Enabled -isnot [bool] -or $Profiles[0].Loaded -isnot [bool] -or $null -eq $Profiles[0].Status) { throw 'PROFILE_STATE_UNKNOWN' }
$ProfilePath = $Profiles[0].LocalPath
$Listed = Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
if ([Environment]::ExpandEnvironmentVariables($Listed.ProfileImagePath) -cne $ProfilePath) { throw 'PROFILE_BINDING' }
# Name enumeration, not OpenSubKey: a standard-user broker can be denied read
# access to another user's loaded hive, and that must not hide the mount.
$Mounted = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames()) -contains $Sid
$Admin = Get-LocalGroup -SID 'S-1-5-32-544'
$AdminSids = @(Get-LocalGroupMember -Group $Admin.Name | ForEach-Object { $_.SID.Value })
$Account = Get-CimInstance Win32_UserAccount -Filter "SID='$Sid'" -OperationTimeoutSec 5
if ($null -eq $Account) { throw 'ACCOUNT_UNKNOWN' }
$Sessions = @(Get-CimAssociatedInstance -InputObject $Account -Association Win32_LoggedOnUser -OperationTimeoutSec 5)
$Hive = Join-Path $ProfilePath 'NTUSER.DAT'
foreach ($Path in @($ProfilePath, $Hive)) {
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'REPARSE' }
}
[ordered]@{
    sid = $Sid; enabled = [bool]$User.Enabled; admin = ($AdminSids -contains $Sid)
    mounted = $Mounted; loaded = [bool]$Profiles[0].Loaded; sessions = $Sessions.Count
    profile = $ProfilePath; profile_status = [int]$Profiles[0].Status
    account_description = [string]$User.Description
    profile_acl = (Get-Acl -LiteralPath $ProfilePath).Sddl
    hive_acl = (Get-Acl -LiteralPath $Hive).Sddl
} | ConvertTo-Json -Compress
""".strip()

_STATE_TYPES = {
    "sid": str,
    "enabled": bool,
    "admin": bool,
    "mounted": bool,
    "loaded": bool,
    "sessions": int,
    "profile": str,
    "profile_status": int,
    "account_description": str,
    "profile_acl": str,
    "hive_acl": str,
}

CommandRunner = Callable[..., subprocess.CompletedProcess]


def read_target_profile_state(
    command_runner: CommandRunner, target_identity: str
) -> dict[str, object]:
    """One fresh read-only observation. Any doubt raises; nothing is inferred."""
    if (
        type(target_identity) is not str
        or not target_identity
        or not all(c.isalnum() or c in "-_" for c in target_identity)
    ):
        raise ValueError("target identity invalid")
    completed = command_runner(
        POWERSHELL_EXECUTABLE,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        _STATE_SCRIPT.replace("__TARGET_IDENTITY__", target_identity),
    )
    if completed.returncode != 0:
        raise ValueError("target profile state unreadable")
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError) as error:
        raise ValueError("target profile state invalid JSON") from error
    if type(payload) is not dict or set(payload) != set(_STATE_TYPES):
        raise ValueError("target profile state shape invalid")
    for key, expected in _STATE_TYPES.items():
        if type(payload[key]) is not expected:
            raise ValueError(f"target profile state field invalid: {key}")
    return payload


def target_state_idle(state: object) -> bool:
    return (
        type(state) is dict
        and state.get("enabled") is True
        and state.get("admin") is False
        and state.get("mounted") is False
        and state.get("loaded") is False
        and type(state.get("sessions")) is int
        and state.get("sessions") == 0
    )


def target_state_stable(before: object, after: object) -> bool:
    if type(before) is not dict or type(after) is not dict:
        return False
    return all(
        key in before and key in after and before[key] == after[key]
        for key in STABLE_STATE_KEYS
    )


class HoldProcess(Protocol):
    def read_line(self, timeout: float) -> Optional[str]:
        """Next stdout line; None on EOF; TimeoutError when the deadline passes."""

    def send_release(self) -> None: ...

    def wait(self, timeout: float) -> Optional[int]:
        """Exit code, or None when the process has not exited in time."""

    def kill(self) -> None: ...


class SubprocessHold:
    """The real hold child. stdout is framed lines; stdin carries RELEASE."""

    def __init__(self, command: list[str]) -> None:
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self._lines: "queue.Queue[Optional[str]]" = queue.Queue()
        self._errors: list[str] = []
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        threading.Thread(target=self._pump_errors, daemon=True).start()

    def _pump_errors(self) -> None:
        # Drained so the child cannot block; kept short for diagnostics only.
        for line in self._process.stderr:
            if len(self._errors) < 20:
                self._errors.append(line.strip()[:300])

    def stderr_tail(self) -> str:
        return " | ".join(self._errors)

    def _pump(self) -> None:
        try:
            for line in self._process.stdout:
                self._lines.put(line.rstrip("\r\n"))
        finally:
            self._lines.put(None)

    def read_line(self, timeout: float) -> Optional[str]:
        try:
            return self._lines.get(timeout=max(timeout, 0.0))
        except queue.Empty:
            raise TimeoutError("hold frame deadline") from None

    def send_release(self) -> None:
        try:
            self._process.stdin.write("RELEASE\n")
            self._process.stdin.flush()
        finally:
            self._process.stdin.close()

    def wait(self, timeout: float) -> Optional[int]:
        try:
            return self._process.wait(timeout=max(timeout, 0.0))
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        self._process.kill()

    def close(self) -> None:
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            try:
                stream.close()
            except Exception:
                pass


def hold_command(hold_script: Path, *, target_sid: str, host: str) -> list[str]:
    # Not -NonInteractive: the child must be able to show the credential dialog.
    return [
        POWERSHELL_EXECUTABLE,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(hold_script),
        "-TargetSid",
        target_sid,
        "-HostName",
        host,
    ]


def _report_from_frame(line: str) -> Optional[dict[str, object]]:
    try:
        report = json.loads(line[len(FRAME_REPORT_PREFIX):])
    except ValueError:
        return None
    return report if type(report) is dict else None


class TargetProfileHold:
    """preflight -> acquire -> (caller collects) -> release_and_verify.

    ``release_and_verify`` is the callback for ``deferred_phase0_commit``. It
    returns True only when no target profile state from this run can remain:
    the hold child exited, the target child either never started or exited on
    its retained handle, and a fresh observation is idle and matches the
    baseline. After a successful acquire it additionally requires the clean
    release report. Every other outcome is False, which the caller reports as
    STOP_PARTIAL_PROFILE_STATE. Nothing is retried, unloaded or repaired.
    """

    def __init__(
        self,
        *,
        hold_script: Path,
        host: str,
        state_reader: Callable[[], dict[str, object]],
        process_factory: Callable[[list[str]], HoldProcess] = SubprocessHold,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        progress: Callable[[str], None] = lambda _message: None,
    ) -> None:
        self._hold_script = hold_script
        self._host = host
        self._state_reader = state_reader
        self._process_factory = process_factory
        self._sleep = sleep
        self._monotonic = monotonic
        self._progress = progress
        self._baseline: Optional[dict[str, object]] = None
        self._process: Optional[HoldProcess] = None
        self._target_stage_entered = False
        self._acquired = False
        self._report: Optional[dict[str, object]] = None
        self._released = False
        self.outcome: dict[str, object] = {}

    def preflight(self) -> dict[str, object]:
        """Read-only. Raises unless the target is provably idle right now."""
        state = self._state_reader()
        if not target_state_idle(state):
            raise RuntimeError(
                "target profile is not idle (mounted/loaded/session/admin/disabled); no effect performed"
            )
        self._baseline = state
        return state

    def _expect(self, timeout: float, stage: str) -> str:
        assert self._process is not None
        try:
            line = self._process.read_line(timeout)
        except TimeoutError:
            raise RuntimeError(f"target hold deadline: {stage}") from None
        if line is None:
            raise RuntimeError(f"target hold ended early: {stage}")
        if line.startswith(FRAME_REPORT_PREFIX):
            self._report = _report_from_frame(line)
            raise RuntimeError(f"target hold reported failure: {stage}")
        return line

    def acquire(self) -> None:
        if self._baseline is None:
            raise RuntimeError("target hold preflight missing")
        if self._process is not None:
            raise RuntimeError("target hold already attempted; no retry")
        self._process = self._process_factory(
            hold_command(
                self._hold_script,
                target_sid=str(self._baseline["sid"]),
                host=self._host,
            )
        )
        if self._expect(STARTUP_TIMEOUT_SECONDS, "startup") != FRAME_AWAITING_CREDENTIAL:
            raise RuntimeError("target hold protocol violation: startup")
        self._progress("credential dialog open: type the ac-runner password, or cancel for no effect")
        frame = self._expect(CREDENTIAL_TIMEOUT_SECONDS, "credential")
        if frame != FRAME_STARTING_TARGET:
            raise RuntimeError("target hold stopped before logon (credential not supplied); no effect")
        # From here a native logon may be in flight; only a confirmed target
        # exit or a never-started report can clear that.
        self._target_stage_entered = True
        self._progress("target logon/profile load starting")
        frame = self._expect(TARGET_READY_TIMEOUT_SECONDS, "target-ready")
        if not frame.startswith(FRAME_READY_PREFIX):
            raise RuntimeError("target hold protocol violation: target-ready")
        state = self._state_reader()
        if (
            state.get("mounted") is not True
            or state.get("sid") != self._baseline["sid"]
        ):
            raise RuntimeError("target SID hive not observed mounted during hold")
        self._acquired = True
        self._progress("target profile held; hive observed mounted")

    def _finish_process(self) -> Optional[int]:
        assert self._process is not None
        try:
            self._process.send_release()
        except Exception:
            pass  # A dead pipe is itself the release signal (EOF) for the child.
        deadline = self._monotonic() + REPORT_TIMEOUT_SECONDS
        while self._report is None:
            try:
                line = self._process.read_line(deadline - self._monotonic())
            except TimeoutError:
                break
            if line is None:
                break
            if line.startswith(FRAME_REPORT_PREFIX):
                self._report = _report_from_frame(line)
                break
            if line == FRAME_STARTING_TARGET or line.startswith(FRAME_READY_PREFIX):
                # Seen only while draining (e.g. after a credential deadline):
                # the logon stage was entered all the same.
                self._target_stage_entered = True
        exit_code = self._process.wait(EXIT_TIMEOUT_SECONDS)
        if exit_code is None:
            # Our own child, our own handle. Its target sees EOF and exits by
            # itself; this never proves that, so the run cannot verify.
            try:
                self._process.kill()
            except Exception:
                pass
            self._process.wait(EXIT_TIMEOUT_SECONDS)
            return None
        return exit_code

    def _poststate(self) -> Optional[dict[str, object]]:
        deadline = self._monotonic() + POSTSTATE_TIMEOUT_SECONDS
        while True:
            try:
                state = self._state_reader()
            except Exception:
                state = None
            if target_state_idle(state):
                return state
            if self._monotonic() >= deadline:
                return state
            self._sleep(POSTSTATE_INTERVAL_SECONDS)

    def release_and_verify(self) -> bool:
        if self._released:
            raise RuntimeError("target hold already released; no retry")
        self._released = True
        if self._baseline is None:
            self.outcome = {"restored": False, "reason": "preflight missing"}
            return False

        exit_code: Optional[int] = None
        if self._process is not None:
            self._progress("releasing target hold")
            exit_code = self._finish_process()
        report = self._report
        after = self._poststate()
        idle = target_state_idle(after)
        stable = target_state_stable(self._baseline, after)

        if self._process is None:
            target_cleared = True
        elif exit_code is None:
            target_cleared = False
        elif report is not None:
            target_cleared = (
                report.get("target_started") is False
                or report.get("exit_confirmed") is True
            )
        else:
            # No report: clear only if the logon stage was never entered.
            target_cleared = not self._target_stage_entered

        clean_release = (
            exit_code == 0
            and report is not None
            and report.get("status") == "TARGET_HOLD_RELEASED"
            and report.get("ready") is True
            and report.get("release_confirmed") is True
            and report.get("exit_confirmed") is True
            and type(report.get("target_exit_code")) is int
            and report.get("target_exit_code") == 0
            and report.get("stderr_empty") is True
        )
        restored = target_cleared and idle and stable and (
            clean_release or not self._acquired
        )
        self.outcome = {
            "restored": restored,
            "hold_started": self._process is not None,
            "hold_exit_code": exit_code,
            "target_stage_entered": self._target_stage_entered,
            "acquired": self._acquired,
            "report_status": None if report is None else report.get("status"),
            "target_cleared": target_cleared,
            "clean_release": clean_release,
            "poststate_idle": idle,
            "poststate_stable": stable,
            "hold_stderr": getattr(self._process, "stderr_tail", lambda: "")(),
        }
        self._progress(
            "target profile restored and verified" if restored
            else "target profile restoration NOT verified"
        )
        return restored
