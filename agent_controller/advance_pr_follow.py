"""Bounded, local follow around the single-step Draft PR advancement."""
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from .advance_pr import _advance_conflict, _advance_pr_step, _advance_target
from .capacity_collect import DEFAULT_CODEX_TIMEOUT_SECONDS
from .operation_follow import _clock_value, _validate_bounds
from .reconciler import ReconcilerLock, pr_lock_path

DEFAULT_MAX_POLLS = 60
DEFAULT_MAX_ELAPSED = 3600
STEP_TIMEOUT = 120
NOTIFY_TIMEOUT = 10
_WAIT_STATES = {"WAIT_CI", "WAIT_CURRENT_HEAD_REVIEW"}


def _now():
    return datetime.now(timezone.utc).isoformat()


class _StepTimeout(TimeoutError):
    def __init__(self, observed_head):
        self.observed_head = observed_head


def _run_step(kwargs, timeout):
    # Isolate the whole step: per-socket timeouts cannot bound DNS, pagination,
    # a slow response body, or the sum of the reads and the write. On timeout
    # subprocess.run kills and waits for this worker before the PR lock is released.
    try:
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "agent_controller.advance_pr_follow"],
            input=json.dumps(dict(kwargs, step_deadline=time.monotonic() + timeout)),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            check=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.output or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        lines = output.splitlines()
        observed_head = None
        if lines and lines[0].startswith("HEAD "):
            candidate = lines[0].removeprefix("HEAD ")
            if re.fullmatch(r"[0-9a-f]{40}", candidate):
                observed_head = candidate
        raise _StepTimeout(observed_head) from None
    return json.loads(completed.stdout.splitlines()[-1])


def _write_result(path, result):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=".advance-pr-", delete=False,
    ) as handle:
        temp = Path(handle.name)
        try:
            json.dump(result, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            handle.close()
            temp.unlink(missing_ok=True)
            raise
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


_TOAST_SCRIPT = """
$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime]
$xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
$xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>Agent Controller</text><text/></binding></visual></toast>')
$xml.GetElementsByTagName('text').Item(1).InnerText = $env:AGENT_CONTROLLER_TOAST_TEXT
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(
    'Microsoft.Windows.PowerShell'
).Show($toast)
"""


def _notify(mode, command, path, result):
    env = None
    stderr = subprocess.DEVNULL
    windows_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    if mode == "bell":
        argv = [sys.executable, "-B", "-c", "import sys; sys.stderr.write(chr(7)); sys.stderr.flush()"]
        stderr = None
        windows_flags = 0
    elif mode == "windows-toast":
        if os.name != "nt":
            raise OSError("Windows is required")
        argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _TOAST_SCRIPT]
        env = dict(os.environ, AGENT_CONTROLLER_TOAST_TEXT=f"{result['repo']} #{result['pr']}: {result['state']}")
    else:
        argv = [command, str(path)]
        suffix = Path(command).suffix.lower()
        if suffix == ".py":
            argv = [sys.executable, "-B", *argv]
        elif os.name == "nt" and suffix in {".bat", ".cmd"}:
            raise ValueError("Choose a native executable or Python script")
    subprocess.run(
        argv, check=True, timeout=NOTIFY_TIMEOUT, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=stderr, env=env, creationflags=windows_flags,
    )


def _persist_and_notify(path, result, mode, command, notify):
    if not _persist(path, result):
        result["notification"] = {"status": "SKIPPED", "reason": "RESULT_WRITE_FAILED"}
        return result
    if mode == "none":
        return result
    try:
        notify(mode, command, path, result)
    except Exception as exc:
        error = "NOTIFICATION_TIMED_OUT" if isinstance(exc, subprocess.TimeoutExpired) else "NOTIFICATION_FAILED"
        result["notification"] = {"status": "FAILED", "error": error}
    else:
        result["notification"] = {"status": "SENT"}
    _persist(path, result)
    return result


def _persist(path, result):
    try:
        _write_result(path, result)
    except (OSError, ValueError):
        result["result_file_error"] = "RESULT_WRITE_FAILED"
        return False
    return True


def follow_pr(
    *, owner, repo, pr_number, policy_path=None, scope_policy=None, apply=False,
    task_observation=None, live_capacity=False, codex_command="codex", codex_timeout=DEFAULT_CODEX_TIMEOUT_SECONDS,
    expected_head=None, interval=60, max_polls=DEFAULT_MAX_POLLS,
    max_elapsed_seconds=DEFAULT_MAX_ELAPSED, result_file=None, notify_mode="none",
    notify_command=None, clock=time.monotonic, sleep_fn=time.sleep, run_step=_run_step, notify=_notify,
):
    """Keep ownership of the shared lock through terminal result publication."""
    lock = ReconcilerLock(pr_lock_path(owner, repo, pr_number))
    path = (Path(result_file) if result_file is not None
            else Path(lock.lock_file).with_suffix(".result.json")).resolve()
    result = _advance_target(owner, repo, pr_number)
    started_at = _now()
    count = 0
    elapsed = 0.0
    transitions = []
    initial_head = expected_head
    review_requested = False

    def finish(state=None, reason=None, action=None, *, conflict=False):
        if state is not None:
            result.update(state=state, reason=reason, next_action=action)
        notification = {"status": "SKIPPED" if conflict else "DISABLED" if notify_mode == "none" else "PENDING"}
        if conflict:
            notification["reason"] = "CONCURRENT_PR_ADVANCE"
        return dict(
            result, initial_head_sha=initial_head, result_file=str(path),
            observation_count=count, elapsed_seconds=elapsed, transitions=transitions,
            started_at=started_at, finished_at=_now(), notification=notification,
        )

    try:
        acquired = lock.acquire()
    except OSError:
        result["lock_path"] = lock.lock_file
        return finish("STOP_CONFLICT", "PR_LOCK_UNAVAILABLE", "Check the lock directory.", conflict=True)
    if not acquired:
        # Never replace the winning invocation's result or trigger its notifier.
        result.update(_advance_conflict(owner, repo, pr_number, lock.lock_file))
        return finish(conflict=True)

    def publish(state=None, reason=None, action=None):
        return _persist_and_notify(path, finish(state, reason, action), notify_mode, notify_command, notify)

    try:
        # A result file may not replace the shared lock or the policy it consumes.
        if (re.fullmatch(r"agent_controller_pr_[0-9a-f]{64}\.lock", path.name.lower())
                or (policy_path and path == Path(policy_path).resolve())):
            terminal = finish("STOP_POLICY", "UNSAFE_RESULT_PATH", "Choose a separate JSON result file.")
            terminal["notification"] = {"status": "SKIPPED", "reason": "UNSAFE_RESULT_PATH"}
            return terminal
        if (notify_mode not in {"none", "bell", "windows-toast", "command"}
                or ((notify_mode == "command") != bool(notify_command))):
            terminal = finish("STOP_POLICY", "INVALID_NOTIFICATION", "Provide a command only in command mode.")
            terminal["notification"] = {"status": "SKIPPED", "reason": "INVALID_NOTIFICATION"}
            _persist(path, terminal)
            return terminal
        try:
            _validate_bounds(max_elapsed_seconds=max_elapsed_seconds, max_observations=max_polls,
                             poll_interval_seconds=interval)
        except (ValueError, TypeError, OverflowError):
            return publish("STOP_POLICY", "INVALID_FOLLOW_BOUNDS", "Use finite positive polling bounds.")
        if expected_head is not None and (
            not isinstance(expected_head, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_head)
        ):
            initial_head = None
            return publish("STOP_POLICY", "INVALID_EXPECTED_HEAD", "Provide the full lowercase commit SHA.")

        try:
            started = previous = _clock_value(clock)
        except Exception:
            return publish("STOP_EVIDENCE", "CLOCK_MALFORMED", "Check the monotonic clock.")

        def tick():
            nonlocal previous, elapsed
            current = _clock_value(clock)
            if current < previous:
                raise ValueError("MONOTONIC_CLOCK_REVERSED")
            elapsed = current - started
            if not math.isfinite(elapsed):
                raise ValueError("CLOCK_MALFORMED")
            previous = current

        def elapsed_stop():
            return publish("STOP_WAIT_LIMIT", "MAX_ELAPSED",
                           "Review the recorded PR state before starting another follow.")

        while True:
            try:
                tick()
            except Exception as exc:
                reason = "MONOTONIC_CLOCK_REVERSED" if str(exc) == "MONOTONIC_CLOCK_REVERSED" else "CLOCK_MALFORMED"
                return publish("STOP_EVIDENCE", reason, "Check the monotonic clock.")
            remaining = max_elapsed_seconds - elapsed
            if remaining <= 0:
                return elapsed_stop()
            timeout = min(remaining, STEP_TIMEOUT)
            count += 1
            try:
                step = run_step(dict(
                    owner=owner, repo=repo, pr_number=pr_number, policy_path=policy_path, scope_policy=scope_policy,
                    apply=apply, task_observation=task_observation, live_capacity=live_capacity,
                    codex_command=codex_command, codex_timeout=codex_timeout,
                    expected_head=initial_head, review_requested=review_requested,
                ), timeout)
            except (subprocess.TimeoutExpired, TimeoutError) as exc:
                # A POST may have reached GitHub before the worker was stopped.
                # Keep the observed HEAD if the worker reached its first read.
                observed_head = getattr(exc, "observed_head", None)
                if observed_head is not None:
                    initial_head = initial_head or observed_head
                    result.update(head_sha=observed_head, actions_ci_status=None, review_verdict=None)
                elapsed += timeout
                if observed_head is not None and observed_head != initial_head:
                    return publish("STOP_HEAD_CHANGED", "STALE_HEAD_SHA", "Inspect the new HEAD and any posted request.")
                return publish("STOP_WAIT_LIMIT", "MAX_ELAPSED" if timeout == remaining else "STEP_TIMEOUT",
                               "Verify GitHub for a possible posted request before retrying.")
            except Exception:
                return publish("STOP_EVIDENCE", "FOLLOW_STEP_FAILED",
                               "Verify GitHub for a possible posted request before retrying.")

            if initial_head is None:
                initial_head = step.get("initial_head_sha") or step["head_sha"]
            result = step
            head, state, reason = step["head_sha"], step["state"], step["reason"]
            if isinstance(head, str) and re.fullmatch(r"[0-9a-f]{40}", head) and initial_head != head:
                state, reason = "STOP_HEAD_CHANGED", "STALE_HEAD_SHA"
                result.update(state=state, reason=reason, next_action="Inspect the new HEAD before another follow.")
            if state == "STOP_HEAD_CHANGED":
                result.update(actions_ci_status=None, review_verdict=None)
            if state in {"WAIT_REMEDIATION", "STOP_TASK_OBSERVATION_REQUIRED", "STOP_FOR_HUMAN_APPLY"}:
                result["next_action"] = "Check View Task → Update branch before taking further action (#200)."
            if state == "WAIT_CURRENT_HEAD_REVIEW" and reason in {"REQUEST_POSTED", "REVIEW_ALREADY_REQUESTED_FOR_HEAD"}:
                review_requested = True
            transition = dict(state=state, reason=reason, head_sha=head)
            if not transitions or any(transitions[-1][k] != v for k, v in transition.items()):
                transitions.append(dict(transition, observation=count))

            try:
                tick()
            except Exception as exc:
                reason = "MONOTONIC_CLOCK_REVERSED" if str(exc) == "MONOTONIC_CLOCK_REVERSED" else "CLOCK_MALFORMED"
                return publish("STOP_EVIDENCE", reason, "Check the monotonic clock and PR state.")
            if state not in _WAIT_STATES:
                return publish()
            if count >= max_polls:
                return publish("STOP_WAIT_LIMIT", "MAX_OBSERVATIONS", "Check the PR before starting another follow.")
            remaining = max_elapsed_seconds - elapsed
            if remaining <= 0:
                return elapsed_stop()
            try:
                sleep_fn(min(interval, remaining))
            except Exception:
                return publish("STOP_EVIDENCE", "FOLLOW_SLEEP_FAILED", "Check the PR before another follow.")
    finally:
        lock.release()


if __name__ == "__main__":
    # Internal subprocess protocol. The parent holds the shared PR lock.
    def report_head(head):
        print(f"HEAD {head}", flush=True)

    print(json.dumps(_advance_pr_step(**json.load(sys.stdin), report_head=report_head)))
