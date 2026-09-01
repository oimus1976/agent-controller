#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent_controller.github_draft_publication import GitHubRestDraftPublicationBackend
from agent_controller.jules_draft_publication import publish_jules_changeset_to_draft_pr
from agent_controller.jules_e2e_smoke import run_operator_assisted_smoke
from agent_controller.jules_issue_task import JulesIssueTaskSpec, build_issue_task
from agent_controller.jules_live import JulesApiClient
from scripts import run_jules_e2e_smoke as smoke_runner


SPEC_FILE = Path(".jules_issue_task_spec.json")


def _load_spec(path: Path = SPEC_FILE) -> JulesIssueTaskSpec:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError("JULES_ISSUE_TASK_SPEC_MISSING") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("JULES_ISSUE_TASK_SPEC_INVALID_JSON") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("JULES_ISSUE_TASK_SPEC_NOT_OBJECT")
    return JulesIssueTaskSpec.from_mapping(raw)


def _spec_evidence(spec: JulesIssueTaskSpec) -> tuple[dict[str, object], str]:
    payload: dict[str, object] = {
        "schema_version": spec.schema_version,
        "issue_number": spec.issue_number,
        "repo": spec.repo,
        "expected_start_ref": spec.expected_start_ref,
        "expected_start_sha": spec.expected_start_sha,
        "controller_task_id": spec.controller_task_id,
        "operation_id": spec.operation_id,
        "workstream_id": spec.workstream_id,
        "destination_branch": spec.destination_branch,
        "prompt": spec.prompt,
        "allowed_paths": list(spec.allowed_paths),
        "denied_paths": list(spec.denied_paths),
        "requested_capability": spec.requested_capability,
        "allowed_effects": list(spec.allowed_effects),
        "forbidden_effects": list(spec.forbidden_effects),
        "approval_policy_id": spec.approval_policy_id,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload, digest


def _publication_with_issue_metadata(spec: JulesIssueTaskSpec):
    def publish_issue(**kwargs: Any):
        kwargs["pr_title"] = f"Issue #{spec.issue_number}: Jules implementation"
        kwargs["pr_body"] = (
            f"Implements #{spec.issue_number}.\n\n"
            "This Draft PR was published by the bounded Agent Controller Jules issue-task runner. "
            "The provider plan required explicit human approval. Ready and merge remain human-final."
        )
        return publish_jules_changeset_to_draft_pr(**kwargs)

    return publish_issue


def main() -> int:
    try:
        spec = _load_spec()
        spec_payload, spec_digest = _spec_evidence(spec)
    except Exception as exc:
        print(f"Issue-task spec validation failed before provider access: {exc}", file=sys.stderr)
        return 2

    state_path = Path(spec.state_filename)
    if state_path.exists():
        print(
            f"Refusing Jules dispatch: fixed task state already exists at {state_path.resolve()}. "
            "Inspect the existing evidence instead of retrying blindly.",
            file=sys.stderr,
        )
        return 2

    try:
        api_client = JulesApiClient()
        api_client.get_api_key()
        github = GitHubRestDraftPublicationBackend()
        task, workstream, branch, adapter, change_reader, github = build_issue_task(
            spec,
            github=github,
            api_client=api_client,
        )
        assert task.expected_start_sha is not None
        smoke_runner._verify_local_checkout(expected_sha=task.expected_start_sha)
    except Exception as exc:
        print(f"Issue-task preflight failed before session creation: {exc}", file=sys.stderr)
        return 2

    armed: dict[str, object] = {
        "schema_version": 1,
        "state": "ARMED_BEFORE_DISPATCH",
        "armed_at": smoke_runner._now(),
        "repo": task.repo,
        "issue_number": spec.issue_number,
        "expected_start_ref": task.expected_start_ref,
        "expected_start_sha": task.expected_start_sha,
        "controller_task_id": task.controller_task_id,
        "operation_id": task.operation_id,
        "workstream_id": workstream.workstream_id,
        "destination_branch": branch,
        "task_spec": spec_payload,
        "task_spec_sha256": spec_digest,
    }
    try:
        smoke_runner._write_once(state_path, armed)
    except Exception as exc:
        print(f"Could not arm one-shot issue-task state; no session was dispatched: {exc}", file=sys.stderr)
        return 2

    def wait_and_persist_gate(action: dict[str, object]) -> None:
        gated = dict(armed)
        gated.update(
            {
                "state": "HUMAN_PLAN_ACTION_REQUIRED",
                "plan_gate_at": smoke_runner._now(),
                "provider_operation_id": action.get("provider_operation_id"),
                "provider_url": action.get("provider_url"),
            }
        )
        smoke_runner._replace_state(state_path, gated)
        smoke_runner._wait_for_human(action)

    try:
        result = run_operator_assisted_smoke(
            task=task,
            workstream=workstream,
            destination_branch=branch,
            adapter=adapter,
            change_reader=change_reader,
            github=github,
            wait_for_human=wait_and_persist_gate,
            publish=_publication_with_issue_metadata(spec),
        )
    except (KeyboardInterrupt, EOFError):
        print(
            "\nIssue task interrupted. The fixed state file remains armed/gated. "
            "Do not rerun blindly; inspect the exact Jules session and GitHub state first.",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        failed = dict(armed)
        failed.update(
            {
                "state": "UNCAUGHT_UNCERTAINTY",
                "finished_at": smoke_runner._now(),
                "reason": str(exc),
            }
        )
        smoke_runner._replace_state(state_path, failed)
        print(
            "Issue task stopped with uncertainty. The one-shot state remains and blocks blind retry.",
            file=sys.stderr,
        )
        return 1

    evidence = dict(armed)
    evidence.update(
        {
            "state": result.status,
            "finished_at": smoke_runner._now(),
            "result": result.to_dict(),
        }
    )
    smoke_runner._replace_state(state_path, evidence)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    if result.status == "PASS":
        print(
            "\nBounded Jules issue task composition PASS. The published pull request is still Draft. "
            "Ready and merge remain human-final."
        )
        return 0

    print(
        "\nBounded Jules issue task did not PASS. Do not delete the fixed state file or redispatch. "
        "Inspect the exact provider/GitHub evidence first.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
