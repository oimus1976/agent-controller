"""Collect AI provider capacity quotas into a life-dashboard document.

This is the local collection runner for the AI usage dashboard. It runs on
the owner's machine, reads each provider's quota through the provider's own
documented machine-readable surface, converts the readings with
:mod:`agent_controller.capacity_dashboard_export`, and writes one
``ai-usage-observations`` JSON document that the owner imports into
life-dashboard manually. It never pushes, uploads, or transmits anything.

Sources (each optional; only the requested ones are collected):

- ``--claude-code-statusline <file>``: a Claude Code status-line JSON
  payload saved to a file. On the owner's machine this is produced by a
  statusLine wrapper: configure Claude Code's ``statusLine`` command to a
  small script that first saves its stdin to a fixed path (for example
  ``%USERPROFILE%\\.agent-controller\\claude-statusline.json``) and then
  prints whatever status line the owner wants displayed. This module does
  not change that configuration; it only reads the saved file. The parser
  uses only the ``rate_limits`` object — session content, prompts, and
  transcripts in the payload are never read into the export and never
  written out.
- ``--codex-app-server``: spawns ``codex app-server`` and speaks JSON-RPC
  over stdio (``initialize`` handshake, then ``account/rateLimits/read``).
  The server runs under the owner's existing Codex sign-in; this module
  never sees or records any credential — it only reads the rate-limit
  result object.
- ``--antigravity-statusline <file>``: an Antigravity CLI status-line JSON
  payload saved to a file, read the same way as the Claude Code file.

Saved status-line files preserve the file's modification time on disk as
``observed_at`` so re-reading an unchanged snapshot does not refresh its
verification timestamp.

Failure handling: a source that cannot be collected or yields zero capacity
pools is reported on stderr and skipped; it never produces a fabricated record,
and it never stops the other sources. The exit code is 0 when at least one
source succeeded and 1 when every requested source failed (or none was
requested). The output file is written only when at least one source succeeded,
so a failed or empty run cannot overwrite a good document with an empty one.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from typing import Optional, Sequence

from agent_controller.antigravity_capacity import parse_antigravity_statusline_capacity
from agent_controller.capacity_dashboard_export import (
    dashboard_document,
    pool_observations_to_dashboard_records,
)
from agent_controller.claude_code_capacity import parse_claude_code_statusline_capacity
from agent_controller.codex_capacity import parse_codex_rate_limits_capacity
from agent_controller.provider_capacity_pool import ProviderCapacityPoolObservation


# The parsers bind observations to a controller decision. Collection is a
# standing, task-less observation, so the binding uses fixed descriptive
# values; the dashboard export drops them again.
COLLECT_BINDING = {
    "controller_task_id": "ai-usage-dashboard-collect",
    "workstream_id": "ai-usage-dashboard",
    "operation_id": "capacity-collect",
    "operation_version": "1",
}

DEFAULT_CODEX_TIMEOUT_SECONDS = 30.0


def _format_dashboard_timestamp(moment: datetime) -> str:
    utc = moment.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _now_dashboard_timestamp() -> str:
    return _format_dashboard_timestamp(datetime.now(timezone.utc))


def _read_text_file_with_observed_at(path: str) -> tuple[str, str]:
    with Path(path).open("r", encoding="utf-8") as handle:
        stat_result = os.fstat(handle.fileno())
        payload = handle.read()
    observed_at = _format_dashboard_timestamp(
        datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc)
    )
    return payload, observed_at


def _send_message(process: subprocess.Popen, message: dict) -> None:
    if process.stdin is None:
        raise RuntimeError("codex app-server stdin is unavailable")
    try:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        raise RuntimeError("codex app-server closed its stdin") from exc


def _await_response(
    lines: "queue.Queue[Optional[str]]",
    request_id: int,
    deadline: float,
    process: subprocess.Popen,
) -> object:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for the codex app-server response")
        try:
            line = lines.get(timeout=remaining)
        except queue.Empty as exc:
            raise TimeoutError(
                "timed out waiting for the codex app-server response"
            ) from exc
        if line is None:
            raise RuntimeError("codex app-server exited before responding")
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("codex app-server sent a malformed JSON line") from exc
        if not isinstance(message, dict) or message.get("id") != request_id:
            # Notifications and other messages are not the response; the
            # rate-limit parser only ever sees the awaited result object.
            continue
        error = message.get("error")
        if error:
            raise RuntimeError(f"codex app-server returned an error: {error}")
        if "result" not in message:
            raise RuntimeError("codex app-server response has no result")
        return message["result"]


def _shutdown_process(process: subprocess.Popen) -> None:
    try:
        if process.stdin is not None:
            process.stdin.close()
    except OSError:
        pass
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _app_server_argv(command: str) -> list[str]:
    """Build the argv used to spawn ``codex app-server`` for COMMAND.

    Windows cannot CreateProcess a script directly: a ``.py`` command is
    run through the current interpreter, and a ``.cmd`` / ``.bat`` shim
    (how npm installs the codex CLI) is run through ``cmd /c``. Anything
    else is spawned as a native executable.
    """

    lowered = command.lower()
    if lowered.endswith(".py"):
        return [sys.executable, command, "app-server"]
    if sys.platform == "win32" and lowered.endswith((".cmd", ".bat")):
        return ["cmd", "/c", command, "app-server"]
    return [command, "app-server"]


def read_codex_rate_limits_result(command: str, timeout: float) -> str:
    """Run ``codex app-server`` and return the rate-limits result as JSON.

    Performs the documented stdio JSON-RPC handshake (``initialize`` /
    ``initialized``) and then calls ``account/rateLimits/read``. Only the
    result object is returned, serialized back to a JSON string for the
    pure parser; notifications interleaved by the server are ignored.
    """

    if timeout <= 0:
        raise ValueError("timeout must be positive")
    try:
        process = subprocess.Popen(
            _app_server_argv(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
    except OSError as exc:
        raise RuntimeError(f"could not start codex app-server: {exc}") from exc

    lines: "queue.Queue[Optional[str]]" = queue.Queue()

    def _pump() -> None:
        try:
            if process.stdout is not None:
                for line in process.stdout:
                    lines.put(line)
        except Exception:
            pass
        finally:
            lines.put(None)

    threading.Thread(target=_pump, daemon=True).start()
    deadline = time.monotonic() + timeout
    try:
        _send_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "agent-controller-capacity-collect",
                        "version": "1.0",
                    }
                },
            },
        )
        _await_response(lines, 1, deadline, process)
        _send_message(process, {"jsonrpc": "2.0", "method": "initialized"})
        _send_message(
            process,
            {"jsonrpc": "2.0", "id": 2, "method": "account/rateLimits/read"},
        )
        result = _await_response(lines, 2, deadline, process)
        return json.dumps(result)
    finally:
        _shutdown_process(process)


def _collect_file_source(
    path: str, parser, observed_at: Optional[str] = None
) -> list[dict]:
    payload, file_observed_at = _read_text_file_with_observed_at(path)
    pools: tuple[ProviderCapacityPoolObservation, ...] = parser(
        payload,
        **COLLECT_BINDING,
        observed_at=file_observed_at if observed_at is None else observed_at,
    )
    return pool_observations_to_dashboard_records(pools)


def _collect_codex(command: str, timeout: float, observed_at: str) -> list[dict]:
    payload = read_codex_rate_limits_result(command, timeout)
    pools = parse_codex_rate_limits_capacity(
        payload, **COLLECT_BINDING, observed_at=observed_at
    )
    return pool_observations_to_dashboard_records(pools)


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capacity_collect",
        description=(
            "Collect Claude Code / Codex / Antigravity capacity quotas into "
            "a life-dashboard ai-usage-observations JSON document."
        ),
    )
    parser.add_argument(
        "--claude-code-statusline",
        metavar="FILE",
        help="read a saved Claude Code status-line JSON payload from FILE",
    )
    parser.add_argument(
        "--codex-app-server",
        action="store_true",
        help="query a local `codex app-server` over stdio JSON-RPC",
    )
    parser.add_argument(
        "--codex-command",
        default="codex",
        metavar="COMMAND",
        help="codex executable to spawn for --codex-app-server (default: codex)",
    )
    parser.add_argument(
        "--codex-timeout",
        type=float,
        default=DEFAULT_CODEX_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help="overall timeout for the codex app-server exchange (default: 30)",
    )
    parser.add_argument(
        "--antigravity-statusline",
        metavar="FILE",
        help="read a saved Antigravity status-line JSON payload from FILE",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="write the dashboard document to FILE (default: stdout)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_argument_parser().parse_args(argv)

    sources = []
    if args.claude_code_statusline:
        sources.append("claude-code")
    if args.codex_app_server:
        sources.append("codex")
    if args.antigravity_statusline:
        sources.append("antigravity")
    if not sources:
        print(
            "capacity_collect: no source requested; specify at least one of "
            "--claude-code-statusline, --codex-app-server, "
            "--antigravity-statusline",
            file=sys.stderr,
        )
        return 1

    observed_at = _now_dashboard_timestamp()
    records: list[dict] = []
    successes = 0

    def _attempt(name: str, collect) -> None:
        nonlocal successes
        try:
            collected = collect()
            if not collected:
                raise ValueError("no capacity pools observed")
        except Exception as exc:  # per-source failure must not stop the run
            print(f"capacity_collect: {name}: failed: {exc}", file=sys.stderr)
            return
        successes += 1
        records.extend(collected)
        print(
            f"capacity_collect: {name}: ok ({len(collected)} pools)",
            file=sys.stderr,
        )

    if args.claude_code_statusline:
        _attempt(
            "claude-code",
            lambda: _collect_file_source(
                args.claude_code_statusline,
                parse_claude_code_statusline_capacity,
            ),
        )
    else:
        print("capacity_collect: claude-code: skipped (not requested)", file=sys.stderr)
    if args.codex_app_server:
        _attempt(
            "codex",
            lambda: _collect_codex(args.codex_command, args.codex_timeout, observed_at),
        )
    else:
        print("capacity_collect: codex: skipped (not requested)", file=sys.stderr)
    if args.antigravity_statusline:
        _attempt(
            "antigravity",
            lambda: _collect_file_source(
                args.antigravity_statusline,
                parse_antigravity_statusline_capacity,
            ),
        )
    else:
        print("capacity_collect: antigravity: skipped (not requested)", file=sys.stderr)

    if successes == 0:
        print(
            "capacity_collect: every requested source failed; no output written",
            file=sys.stderr,
        )
        return 1

    document = dashboard_document(records)
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(
            f"capacity_collect: wrote {len(records)} observations to {args.out}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
