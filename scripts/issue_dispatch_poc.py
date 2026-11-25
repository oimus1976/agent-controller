"""One-shot Issue intake -> local Claude Code -> result comment (Issue #338 PoC).

Each invocation is a single poll, intended to run every 60 seconds from the
Windows Task Scheduler. It accepts at most one Issue for the whole PoC:

* fixed private repository, exact dispatch label, allowed author ID,
  created after ``armed_at`` and before ``expires_at``;
* body must be exactly ``task: <task_type>``. The body is never passed to the
  CLI or a shell: the prompt and the fixture file are fixed by config;
* the one-shot slot is consumed on disk (O_EXCL) *before* the CLI starts, so
  overlap, restart, or failure can never trigger a second launch;
* unknown capacity, a non-subscription auth method, or a changed fixture
  blocks the launch without consuming the slot.

The receiver (this script), not the CLI, posts the result comment. The CLI
gets only the Read tool, no prompts, no user settings or hooks, and a child
environment without GitHub/Anthropic tokens. Without ``--live`` the script
never launches the CLI or posts a comment.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_controller.claude_code_capacity import parse_claude_code_statusline_capacity

FIXTURE_NAME = "fixture.md"
PROMPT = (
    "Read the file fixture.md in the current directory and summarize it in "
    "Japanese in at most five bullet points. Use no other file or tool. "
    "Do not include file paths, environment details, or credentials."
)
SCRUBBED_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")
MAX_SUMMARY_CHARS = 4000
SECRET_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{10,}"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\b[A-Za-z]:\\[^\s`'\"]*"),
)

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass(frozen=True)
class Config:
    repo: str
    label: str
    allowed_author_id: int
    task_type: str
    armed_at: datetime
    expires_at: datetime
    state_dir: Path
    claude_exe: Path
    fixture_dir: Path
    fixture_sha256: str
    statusline_path: Path
    statusline_max_age_minutes: int
    min_remaining_fraction: float
    allowed_auth_methods: tuple[str, ...]
    claude_timeout_seconds: int
    model: str


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_config(path: Path) -> Config:
    raw = json.loads(path.read_text(encoding="utf-8"))
    config = Config(
        repo=str(raw["repo"]),
        label=str(raw["label"]),
        allowed_author_id=int(raw["allowed_author_id"]),
        task_type=str(raw["task_type"]),
        armed_at=_utc(raw["armed_at"]),
        expires_at=_utc(raw["expires_at"]),
        state_dir=Path(raw["state_dir"]),
        claude_exe=Path(raw["claude_exe"]),
        fixture_dir=Path(raw["fixture_dir"]),
        fixture_sha256=str(raw["fixture_sha256"]).lower(),
        statusline_path=Path(raw["statusline_path"]),
        statusline_max_age_minutes=int(raw.get("statusline_max_age_minutes", 120)),
        min_remaining_fraction=float(raw.get("min_remaining_fraction", 0.2)),
        allowed_auth_methods=tuple(raw["allowed_auth_methods"]),
        claude_timeout_seconds=int(raw.get("claude_timeout_seconds", 300)),
        model=str(raw.get("model", "sonnet")),
    )
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", config.repo):
        raise ValueError("repo must be OWNER/REPO")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", config.task_type):
        raise ValueError("task_type must be a fixed slug")
    if config.expires_at <= config.armed_at or config.expires_at - config.armed_at > timedelta(hours=24):
        raise ValueError("the window must be positive and at most 24 hours")
    if not 0 < config.claude_timeout_seconds <= 900:
        raise ValueError("claude_timeout_seconds must be in (0, 900]")
    if not config.allowed_auth_methods:
        raise ValueError("allowed_auth_methods must be measured and listed")
    return config


def eligible_issues(issues: Sequence[Mapping], config: Config, now: datetime) -> list[Mapping]:
    """Return Issues that pass every intake rule. Pure; no effects."""
    accepted = []
    expected_body = f"task: {config.task_type}"
    for issue in issues:
        if "pull_request" in issue or issue.get("state") != "open" or issue.get("locked"):
            continue
        user = issue.get("user") or {}
        if user.get("id") != config.allowed_author_id or user.get("type") != "User":
            continue
        labels = [label.get("name") for label in issue.get("labels") or [] if isinstance(label, Mapping)]
        if config.label not in labels:
            continue
        try:
            created = _utc(str(issue.get("created_at")))
        except ValueError:
            continue
        if not config.armed_at < created <= now:
            continue
        if (issue.get("body") or "").strip() != expected_body:
            continue
        if issue.get("comments", 0) != 0:
            continue
        accepted.append(issue)
    return accepted


def capacity_ok(config: Config, now: datetime) -> tuple[bool, str]:
    path = config.statusline_path
    if not path.is_file():
        return False, "capacity_unknown"
    observed = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    if now - observed > timedelta(minutes=config.statusline_max_age_minutes):
        return False, "capacity_stale"
    try:
        pools = parse_claude_code_statusline_capacity(
            path.read_text(encoding="utf-8"),
            controller_task_id="issue-338", workstream_id="issue-338",
            operation_id="issue-338-preflight", operation_version="1",
            observed_at=observed.isoformat(),
        )
    except ValueError:
        return False, "capacity_unknown"
    if not pools:
        return False, "capacity_unknown"
    for pool in pools:
        remaining = pool.observation.remaining_capacity
        if remaining is None or remaining < config.min_remaining_fraction:
            return False, "capacity_low"
    return True, "capacity_ok"


def auth_ok(config: Config, run: Runner) -> tuple[bool, str]:
    if not config.claude_exe.is_file():
        return False, "cli_missing"
    try:
        result = run([str(config.claude_exe), "auth", "status", "--json"],
                     capture_output=True, text=True, encoding="utf-8", timeout=60,
                     env=child_env())
        status = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, "auth_unknown"
    if status.get("loggedIn") is not True or status.get("apiProvider") != "firstParty":
        return False, "auth_not_logged_in"
    if status.get("authMethod") not in config.allowed_auth_methods:
        return False, "auth_method_not_allowed"
    return True, "auth_ok"


def fixture_ok(config: Config) -> bool:
    path = config.fixture_dir / FIXTURE_NAME
    if not path.is_file():
        return False
    return hashlib.sha256(path.read_bytes()).hexdigest() == config.fixture_sha256


def child_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key.upper() not in SCRUBBED_ENV}
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    return env


def claude_argv(config: Config) -> list[str]:
    return [
        str(config.claude_exe), "-p", PROMPT,
        "--model", config.model,
        "--tools", "Read", "--allowedTools", "Read",
        "--permission-mode", "dontAsk", "--permission-prompts", "none",
        "--setting-sources", "project", "--settings", '{"disableAllHooks": true}',
        "--strict-mcp-config", "--no-session-persistence", "--output-format", "text",
    ]


def sanitize(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("<REDACTED>", text)
    text = text.strip()
    if len(text) > MAX_SUMMARY_CHARS:
        text = text[:MAX_SUMMARY_CHARS] + "\n…(truncated)"
    return text


def _consume(state_dir: Path, record: Mapping) -> bool:
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(state_dir / "consumed.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle)
        handle.flush()
        os.fsync(handle.fileno())
    return True


def _write_json(path: Path, record: Mapping) -> None:
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def list_issues(config: Config, run: Runner) -> list[Mapping]:
    result = run(
        ["gh", "api", "-X", "GET", f"repos/{config.repo}/issues",
         "-f", "state=open", "-f", f"labels={config.label}", "-f", "per_page=100"],
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=True,
    )
    issues = json.loads(result.stdout)
    if not isinstance(issues, list) or len(issues) >= 100:
        raise RuntimeError("unexpected or possibly truncated issue list")
    return issues


def post_comment(config: Config, number: int, body: str, run: Runner) -> None:
    run(["gh", "issue", "comment", str(number), "--repo", config.repo, "--body-file", "-"],
        input=body, capture_output=True, text=True, encoding="utf-8", timeout=60, check=True)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_once(config: Config, *, live: bool, run: Runner = subprocess.run,
             clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> dict:
    now = clock()
    if (config.state_dir / "consumed.json").exists():
        return {"outcome": "already_consumed"}
    if not config.armed_at <= now <= config.expires_at:
        return {"outcome": "outside_window"}
    candidates = eligible_issues(list_issues(config, run), config, now)
    if not candidates:
        return {"outcome": "no_candidate"}
    if len(candidates) > 1:
        return {"outcome": "ambiguous", "count": len(candidates)}
    issue = candidates[0]
    number = int(issue["number"])
    if not fixture_ok(config):
        return {"outcome": "blocked", "reason": "fixture_mismatch", "issue": number}
    for check in (lambda: auth_ok(config, run), lambda: capacity_ok(config, now)):
        ok, reason = check()
        if not ok:
            return {"outcome": "blocked", "reason": reason, "issue": number}
    if not live:
        return {"outcome": "would_launch", "issue": number, "argv": claude_argv(config)[3:]}

    created = _utc(issue["created_at"])
    if not _consume(config.state_dir, {"issue": number, "consumed_at": _iso(now)}):
        return {"outcome": "already_consumed"}

    started = clock()
    try:
        result = run(claude_argv(config), cwd=str(config.fixture_dir), env=child_env(),
                     capture_output=True, text=True, encoding="utf-8", errors="replace",
                     timeout=config.claude_timeout_seconds)
        exit_code, summary = result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        exit_code, summary = "timeout", ""
    except OSError:
        exit_code, summary = "launch_error", ""
    finished = clock()
    success = exit_code == 0 and summary.strip() != ""
    record = {
        "issue": number, "created_at": _iso(created), "consumed_at": _iso(now),
        "cli_started_at": _iso(started), "cli_finished_at": _iso(finished),
        "detection_latency_seconds": round((started - created).total_seconds(), 1),
        "exit_code": exit_code, "success": success, "launch_count": 1,
    }
    lines = [
        "## Issue #338 PoC 結果", "",
        f"- 結果: {'成功' if success else '失敗'}",
        f"- CLI終了コード: `{exit_code}`",
        f"- Issue作成: {record['created_at']} / CLI開始: {record['cli_started_at']} / CLI終了: {record['cli_finished_at']}",
        f"- 検知遅延: {record['detection_latency_seconds']} 秒", "- 起動回数: 1（受付は消費済み。再発火しません）",
    ]
    if success:
        lines += ["", "### 要約", "", sanitize(summary)]
    try:
        post_comment(config, number, "\n".join(lines) + "\n", run)
        record["comment_posted"] = True
    except (OSError, subprocess.SubprocessError):
        record["comment_posted"] = False
    _write_json(config.state_dir / "result.json", record)
    return {"outcome": "launched", **record}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--live", action="store_true",
                        help="actually launch the CLI and post the comment (needs owner approval)")
    parser.add_argument("--log-file", type=Path)
    args = parser.parse_args(argv)
    config = load_config(args.config)
    try:
        report = run_once(config, live=args.live)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
        report = {"outcome": "error", "kind": type(exc).__name__}
    line = json.dumps({"at": _iso(datetime.now(timezone.utc)), **report}, ensure_ascii=False)
    if args.log_file:
        with args.log_file.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    print(line)
    return 1 if report["outcome"] == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
