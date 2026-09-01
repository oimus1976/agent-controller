#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

# Direct script execution puts scripts/ on sys.path, not the repository root.
# Bootstrap the trusted repository root so the documented PowerShell command
# works without requiring an operator-managed PYTHONPATH override.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent_controller.github_draft_publication import GitHubRestDraftPublicationBackend
from agent_controller.jules_e2e_smoke import build_live_smoke, run_operator_assisted_smoke
from agent_controller.jules_live import JulesApiClient


STATE_FILE = Path(".jules_e2e_smoke_state.json")
EXPECTED_LOCAL_BRANCH = "main"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_once(path: Path, payload: dict[str, object]) -> None:
    path = path.resolve()
    if path.exists():
        raise RuntimeError(
            f"Smoke state already exists at {path}; do not retry a live Jules smoke blindly"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temp.replace(path)


def _replace_state(path: Path, payload: dict[str, object]) -> None:
    path = path.resolve()
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temp.replace(path)


def _git_text(
    args: Sequence[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    result = runner(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout.strip()


def _verify_local_checkout(
    *,
    expected_sha: str,
    cwd: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Require the trusted local runner checkout to be clean exact accepted main."""

    cwd = (cwd or Path.cwd()).resolve()
    root = Path(_git_text(("rev-parse", "--show-toplevel"), runner=runner)).resolve()
    if root != cwd:
        raise RuntimeError("LIVE_SMOKE_MUST_RUN_FROM_REPOSITORY_ROOT")
    branch = _git_text(("branch", "--show-current"), runner=runner)
    if branch != EXPECTED_LOCAL_BRANCH:
        raise RuntimeError("LIVE_SMOKE_LOCAL_BRANCH_NOT_MAIN")
    head = _git_text(("rev-parse", "HEAD"), runner=runner)
    if head.casefold() != expected_sha.casefold():
        raise RuntimeError("LIVE_SMOKE_LOCAL_HEAD_NOT_ACCEPTED_MAIN")
    if _git_text(("status", "--porcelain"), runner=runner):
        raise RuntimeError("LIVE_SMOKE_LOCAL_CHECKOUT_DIRTY")


def _wait_for_human(action: dict[str, object]) -> None:
    print("\nHUMAN PLAN ACTION REQUIRED")
    print(json.dumps(action, indent=2, sort_keys=True))
    print(
        "\nOpen the exact Jules session above and approve or reject its plan in Jules UI.\n"
        "Pressing Enter here does NOT approve anything; it only asks Agent Controller to re-read "
        "the same exact provider operation."
    )
    input("After you have acted in Jules UI, press Enter to re-read the same session: ")


def main() -> int:
    state_path = STATE_FILE

    if state_path.exists():
        print(
            f"Refusing live dispatch: fixed state file already exists at {state_path.resolve()}. "
            "Inspect the existing evidence instead of retrying blindly.",
            file=sys.stderr,
        )
        return 2

    try:
        api_client = JulesApiClient()
        # Validate Jules credential before arming the one-shot marker. Never print it.
        api_client.get_api_key()
        github = GitHubRestDraftPublicationBackend()
        task, workstream, branch, adapter, change_reader, github = build_live_smoke(
            github=github,
            api_client=api_client,
        )
        assert task.expected_start_sha is not None
        _verify_local_checkout(expected_sha=task.expected_start_sha)
    except Exception as exc:
        print(f"Live smoke preflight failed before session creation: {exc}", file=sys.stderr)
        return 2

    armed: dict[str, object] = {
        "schema_version": 1,
        "state": "ARMED_BEFORE_DISPATCH",
        "armed_at": _now(),
        "repo": task.repo,
        "expected_start_ref": task.expected_start_ref,
        "expected_start_sha": task.expected_start_sha,
        "controller_task_id": task.controller_task_id,
        "operation_id": task.operation_id,
        "workstream_id": workstream.workstream_id,
        "destination_branch": branch,
    }
    try:
        _write_once(state_path, armed)
    except Exception as exc:
        print(f"Could not arm one-shot smoke state; no session was dispatched: {exc}", file=sys.stderr)
        return 2

    def wait_and_persist_gate(action: dict[str, object]) -> None:
        gated = dict(armed)
        gated.update(
            {
                "state": "HUMAN_PLAN_ACTION_REQUIRED",
                "plan_gate_at": _now(),
                "provider_operation_id": action.get("provider_operation_id"),
                "provider_url": action.get("provider_url"),
            }
        )
        _replace_state(state_path, gated)
        _wait_for_human(action)

    try:
        result = run_operator_assisted_smoke(
            task=task,
            workstream=workstream,
            destination_branch=branch,
            adapter=adapter,
            change_reader=change_reader,
            github=github,
            wait_for_human=wait_and_persist_gate,
        )
    except (KeyboardInterrupt, EOFError):
        print(
            "\nSmoke interrupted. The fixed state file remains intentionally armed/gated. "
            "Do not rerun blindly; inspect the recorded Jules session and GitHub state first.",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        failed = dict(armed)
        failed.update({"state": "UNCAUGHT_UNCERTAINTY", "finished_at": _now(), "reason": str(exc)})
        _replace_state(state_path, failed)
        print(
            "Smoke stopped with uncertainty. The fixed one-shot state remains and blocks blind retry.",
            file=sys.stderr,
        )
        return 1

    evidence = dict(armed)
    evidence.update(
        {
            "state": result.status,
            "finished_at": _now(),
            "result": result.to_dict(),
        }
    )
    _replace_state(state_path, evidence)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    if result.status == "PASS":
        print(
            "\nLive smoke composition PASS. The published pull request is still Draft. "
            "Ready and merge remain human-final."
        )
        return 0

    print(
        "\nLive smoke did not PASS. Do not delete the fixed state file and rerun automatically; "
        "inspect the exact provider/GitHub evidence first.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
