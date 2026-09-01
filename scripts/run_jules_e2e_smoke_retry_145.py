#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import run_jules_e2e_smoke as first_run
from agent_controller.github_draft_publication import GitHubRestDraftPublicationBackend
from agent_controller.jules_e2e_smoke import build_live_smoke, run_operator_assisted_smoke
from agent_controller.jules_live import JulesApiClient

FIRST_STATE_FILE = Path(".jules_e2e_smoke_state.json")
RETRY_STATE_FILE = Path(".jules_e2e_smoke_retry_145_state.json")
EXPECTED_FIRST_SESSION_ID = "15578855358578323587"
EXPECTED_FIRST_START_SHA = "e5d7fc596edbf299ca9a2ee88fdce56ee9e2f7be"
EXPECTED_FIRST_REASON = "CHANGESET_FINALITY_AMBIGUOUS"


def _validate_first_run_state(path: Path = FIRST_STATE_FILE) -> dict[str, object]:
    resolved = path.resolve()
    if not resolved.exists():
        raise RuntimeError("AUTHORIZED_RETRY_REQUIRES_FIRST_RUN_STATE")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("FIRST_RUN_STATE_UNREADABLE") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("FIRST_RUN_STATE_MALFORMED")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("FIRST_RUN_RESULT_MISSING")
    if payload.get("expected_start_sha") != EXPECTED_FIRST_START_SHA:
        raise RuntimeError("FIRST_RUN_START_SHA_MISMATCH")
    if result.get("provider_operation_id") != EXPECTED_FIRST_SESSION_ID:
        raise RuntimeError("FIRST_RUN_SESSION_MISMATCH")
    if result.get("reason") != EXPECTED_FIRST_REASON:
        raise RuntimeError("FIRST_RUN_REASON_MISMATCH")
    if result.get("status") != "BLOCKED":
        raise RuntimeError("FIRST_RUN_STATUS_MISMATCH")
    publication = result.get("publication")
    if not isinstance(publication, dict):
        raise RuntimeError("FIRST_RUN_PUBLICATION_EVIDENCE_MISSING")
    if publication.get("status") != "BLOCKED" or publication.get("reason") != EXPECTED_FIRST_REASON:
        raise RuntimeError("FIRST_RUN_PUBLICATION_MISMATCH")
    if any(publication.get(key) is not None for key in ("branch", "commit_sha", "pr_number")):
        raise RuntimeError("FIRST_RUN_UNEXPECTED_GITHUB_MUTATION")
    return payload


def main() -> int:
    try:
        _validate_first_run_state()
    except Exception as exc:
        print(f"Authorized retry preflight failed before session creation: {exc}", file=sys.stderr)
        return 2

    if RETRY_STATE_FILE.exists():
        print(
            f"Refusing authorized retry dispatch: fixed retry state already exists at "
            f"{RETRY_STATE_FILE.resolve()}. Do not create a third Jules session.",
            file=sys.stderr,
        )
        return 2

    try:
        api_client = JulesApiClient()
        api_client.get_api_key()
        github = GitHubRestDraftPublicationBackend()
        task, workstream, branch, adapter, change_reader, github = build_live_smoke(
            github=github,
            api_client=api_client,
        )
        assert task.expected_start_sha is not None
        first_run._verify_local_checkout(expected_sha=task.expected_start_sha)
    except Exception as exc:
        print(f"Authorized retry preflight failed before session creation: {exc}", file=sys.stderr)
        return 2

    armed: dict[str, object] = {
        "schema_version": 1,
        "authorization_issue": 145,
        "state": "ARMED_BEFORE_DISPATCH",
        "armed_at": first_run._now(),
        "repo": task.repo,
        "expected_start_ref": task.expected_start_ref,
        "expected_start_sha": task.expected_start_sha,
        "controller_task_id": task.controller_task_id,
        "operation_id": task.operation_id,
        "workstream_id": workstream.workstream_id,
        "destination_branch": branch,
        "first_run_provider_operation_id": EXPECTED_FIRST_SESSION_ID,
        "first_run_start_sha": EXPECTED_FIRST_START_SHA,
        "first_run_reason": EXPECTED_FIRST_REASON,
    }
    try:
        first_run._write_once(RETRY_STATE_FILE, armed)
    except Exception as exc:
        print(f"Could not arm authorized retry state; no session was dispatched: {exc}", file=sys.stderr)
        return 2

    def wait_and_persist_gate(action: dict[str, object]) -> None:
        gated = dict(armed)
        gated.update(
            {
                "state": "HUMAN_PLAN_ACTION_REQUIRED",
                "plan_gate_at": first_run._now(),
                "provider_operation_id": action.get("provider_operation_id"),
                "provider_url": action.get("provider_url"),
            }
        )
        first_run._replace_state(RETRY_STATE_FILE, gated)
        first_run._wait_for_human(action)

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
            "\nAuthorized retry interrupted. The fixed retry state remains armed/gated. "
            "Do not rerun or create a third Jules session.",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        failed = dict(armed)
        failed.update(
            {
                "state": "UNCAUGHT_UNCERTAINTY",
                "finished_at": first_run._now(),
                "reason": str(exc),
            }
        )
        first_run._replace_state(RETRY_STATE_FILE, failed)
        print(
            "Authorized retry stopped with uncertainty. The fixed retry state remains; "
            "do not create a third Jules session.",
            file=sys.stderr,
        )
        return 1

    evidence = dict(armed)
    evidence.update(
        {
            "state": result.status,
            "finished_at": first_run._now(),
            "result": result.to_dict(),
        }
    )
    first_run._replace_state(RETRY_STATE_FILE, evidence)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    if result.status == "PASS":
        print(
            "\nAuthorized retry composition PASS. The published pull request is still Draft. "
            "Ready and merge remain human-final."
        )
        return 0

    print(
        "\nAuthorized retry did not PASS. Do not rerun or create a third Jules session; "
        "inspect the exact provider/GitHub evidence first.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
