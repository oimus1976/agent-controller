import argparse
import json
import sys
from datetime import datetime, timezone

from .attention_queue import AttentionCategory
from .codex_live import CodexSnapshotReadClient
from .github_target_client import GitHubRestTargetReadClient
from .inspector import inspect_pr
from .watcher import watch_pr_once, watch_pr_loop
from .executor import plan_action, execute_action
from .reconciler import reconcile_pr_once
from .multi_watch import run_attention_watch
from .objective_target import (
    GitHubTargetExpectation,
    run_objective_target_handoff,
)
from .provider_adapters import CodexObservationAdapter
from .provider_contract import (
    ObjectiveScope,
    ProviderOperationRef,
    TaskBinding,
    VerificationResult,
)
from .review_request import (
    execute_codex_review_request,
    plan_codex_review_request,
)
from .remediation_request import (
    execute_codex_remediation_request,
    plan_codex_remediation_request,
)


def _require_single_pr_target(parser, args):
    if not args.repo or args.pr is None:
        parser.error(f"{args.command} requires --repo and --pr")
    owner_repo = args.repo.split('/')
    if len(owner_repo) != 2 or not all(owner_repo):
        parser.error("--repo must be in OWNER/REPO format")
    return owner_repo


def _require_repo(parser, repo):
    if not repo:
        parser.error("--repo is required")
    owner_repo = repo.split('/')
    if len(owner_repo) != 2 or not all(owner_repo):
        parser.error("--repo must be in OWNER/REPO format")
    return repo


def _observed_at_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description="Agent Controller: PR Inspector")
    parser.add_argument(
        "command",
        choices=[
            "inspect-pr",
            "watch-pr",
            "act-pr",
            "reconcile-pr",
            "attention-queue",
            "observe-codex",
            "verify-codex-target",
            "request-codex-review",
            "request-codex-remediation",
        ],
        help="Command to run",
    )
    parser.add_argument("--repo", help="Target repository in OWNER/REPO format")
    parser.add_argument("--pr", type=int, help="Target pull request number")
    parser.add_argument("--allowed-paths", nargs='*', help="List of allowed glob patterns for files (e.g. 'src/*' '*.py')")
    parser.add_argument("--denied-paths", nargs='*', help="List of denied glob patterns for files")
    parser.add_argument("--allow-docs-only", action='store_true', help="Allow PRs that only change documentation/config")

    parser.add_argument("--once", action='store_true', help="Run a single deterministic observation or reconciliation cycle")
    parser.add_argument("--state-file", default=".pr_state.json", help="Path to local state/evidence file")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds for loop mode")

    parser.add_argument("--policy", help="Path to explicit local policy JSON file")
    parser.add_argument("--receipts-file", default=".action_receipts.json", help="Path to action receipts file (reconcile-pr)")
    parser.add_argument("--apply", action='store_true', help="Actually perform authorized GitHub writes")

    parser.add_argument("--targets-file", help="JSON target list for attention-queue")

    parser.add_argument("--thread-id", help="Existing Codex thread id for observe-codex / verify-codex-target")
    parser.add_argument(
        "--source-codex-home",
        help="Absolute source Codex home containing the persisted thread; it is never passed directly to app-server",
    )
    parser.add_argument(
        "--codex-bin",
        help="Optional explicit path to the Codex executable; otherwise use the runtime bundled/resolved by openai-codex",
    )

    parser.add_argument(
        "--target-ref",
        help="Explicit Controller-owned GitHub branch ref to verify after provider completion",
    )
    parser.add_argument(
        "--expected-start-sha",
        help="Immutable GitHub start SHA that the verified target must descend from and differ from",
    )

    args = parser.parse_args()

    if args.command == "attention-queue":
        if not args.targets_file:
            parser.error("attention-queue requires --targets-file")
        try:
            with open(args.targets_file, 'r', encoding='utf-8') as handle:
                targets = json.load(handle)
            queue = run_attention_watch(targets)
            print(json.dumps(queue, indent=2))
        except Exception as e:
            print(f"Error building attention queue: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "observe-codex":
        if not args.thread_id:
            parser.error("observe-codex requires --thread-id")
        if not args.source_codex_home:
            parser.error("observe-codex requires --source-codex-home")
        try:
            operation = ProviderOperationRef(
                provider="codex",
                provider_operation_id=args.thread_id,
                provider_url=None,
                controller_task_id=f"live-codex:{args.thread_id}",
                operation_id=f"observe:{args.thread_id}",
            )
            adapter = CodexObservationAdapter(
                client=CodexSnapshotReadClient(
                    source_codex_home=args.source_codex_home,
                    codex_bin=args.codex_bin,
                ),
                observed_at=_observed_at_now,
            )
            observation = adapter.observe(operation)
            print(json.dumps(observation.to_dict(), indent=2))
        except Exception as e:
            print(f"Error observing Codex thread: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "verify-codex-target":
        if not args.thread_id:
            parser.error("verify-codex-target requires --thread-id")
        if not args.source_codex_home:
            parser.error("verify-codex-target requires --source-codex-home")
        repo = _require_repo(parser, args.repo)
        if not args.target_ref:
            parser.error("verify-codex-target requires --target-ref")
        if not args.expected_start_sha:
            parser.error("verify-codex-target requires --expected-start-sha")
        if not (args.allowed_paths or args.denied_paths):
            parser.error("verify-codex-target requires --allowed-paths and/or --denied-paths")

        try:
            controller_task_id = f"live-codex-target:{args.thread_id}"
            operation_id = f"verify-target:{args.thread_id}"
            task = TaskBinding(
                controller_task_id=controller_task_id,
                operation_id=operation_id,
                provider="codex",
                repo=repo,
                expected_start_ref=None,
                expected_start_sha=args.expected_start_sha,
                objective_scope=ObjectiveScope(
                    allowed_paths=args.allowed_paths,
                    denied_paths=args.denied_paths,
                ),
                requested_capability="verify_explicit_github_target_after_provider_completion",
                allowed_effects=(),
                forbidden_effects=(
                    "provider_mutation",
                    "github_write",
                    "level3_effect",
                ),
                approval_policy_id="adr-90-human-final",
                created_at=_observed_at_now(),
            )
            operation = ProviderOperationRef(
                provider="codex",
                provider_operation_id=args.thread_id,
                provider_url=None,
                controller_task_id=controller_task_id,
                operation_id=operation_id,
            )
            observer = CodexObservationAdapter(
                client=CodexSnapshotReadClient(
                    source_codex_home=args.source_codex_home,
                    codex_bin=args.codex_bin,
                ),
                observed_at=_observed_at_now,
            )
            result = run_objective_target_handoff(
                task=task,
                operation=operation,
                observer=observer,
                target=GitHubTargetExpectation(repo=repo, ref=args.target_ref),
                github=GitHubRestTargetReadClient(),
                github_observed_at=_observed_at_now,
            )
            print(json.dumps(result.to_dict(), indent=2))
            if result.verification_result is not VerificationResult.PASS:
                sys.exit(1)
        except Exception as e:
            print(f"Error verifying Codex GitHub target: {e}", file=sys.stderr)
            sys.exit(1)
        return

    owner, repo = _require_single_pr_target(parser, args)

    policy = {
        'allowed_paths': args.allowed_paths,
        'denied_paths': args.denied_paths,
        'allow_docs_only': args.allow_docs_only
    }

    if args.command == "inspect-pr":
        try:
            result = inspect_pr(owner, repo, args.pr, scope_policy=policy)
            print(f"PR State: {result['classification']}")
            print(f"Head SHA: {result['head_sha']}")
            print(f"Base Branch: {result['base_branch']}")
            print(f"Draft: {result['draft']}")
            print(f"Merged: {result['merged']}")
        except Exception as e:
            print(f"Error inspecting PR: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "watch-pr":
        try:
            if args.once:
                observation = watch_pr_once(owner, repo, args.pr, args.state_file, scope_policy=policy)
                print(json.dumps(observation, indent=2))
            else:
                print(f"Watching PR {owner}/{repo}#{args.pr} every {args.interval} seconds...", file=sys.stderr)
                watch_pr_loop(owner, repo, args.pr, args.state_file, args.interval, scope_policy=policy)
        except Exception as e:
            print(f"Error watching PR: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "act-pr":
        try:
            plan = plan_action(owner, repo, args.pr, "ENSURE_DRAFT", args.policy)
            print("PLAN:")
            print(json.dumps(plan, indent=2))
            result = execute_action(plan, owner, repo, args.pr, apply=args.apply)
            print("EXECUTION:")
            print(json.dumps(result, indent=2))
            if result.get("final_outcome") in ["BLOCKED", "FAILED"]:
                sys.exit(1)
        except Exception as e:
            print(f"Error acting on PR: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "request-codex-review":
        try:
            plan = plan_codex_review_request(
                owner=owner,
                repo=repo,
                pr_number=args.pr,
                policy_path=args.policy,
                scope_policy=policy,
            )
            print("PLAN:")
            print(json.dumps(plan, indent=2))
            result = execute_codex_review_request(
                plan=plan,
                owner=owner,
                repo=repo,
                pr_number=args.pr,
                policy_path=args.policy,
                apply=args.apply,
            )
            print("EXECUTION:")
            print(json.dumps(result, indent=2))
            if result.get("final_outcome") in ["BLOCKED", "FAILED"]:
                sys.exit(1)
        except Exception as e:
            print(f"Error requesting Codex review: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "request-codex-remediation":
        try:
            plan = plan_codex_remediation_request(
                owner=owner,
                repo=repo,
                pr_number=args.pr,
                policy_path=args.policy,
                scope_policy=policy,
            )
            print("PLAN:")
            print(json.dumps(plan, indent=2))
            result = execute_codex_remediation_request(
                plan=plan,
                owner=owner,
                repo=repo,
                pr_number=args.pr,
                policy_path=args.policy,
                apply=args.apply,
            )
            print("EXECUTION:")
            print(json.dumps(result, indent=2))
            if result.get("final_outcome") in ["BLOCKED", "FAILED"]:
                sys.exit(1)
        except Exception as e:
            print(f"Error requesting Codex remediation: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "reconcile-pr":
        try:
            if not args.once:
                print("Error: reconcile-pr currently requires --once flag", file=sys.stderr)
                sys.exit(1)
            result = reconcile_pr_once(
                owner, repo, args.pr,
                state_file=args.state_file,
                policy_file=args.policy,
                receipts_file=args.receipts_file,
                apply=args.apply
            )
            print(json.dumps(result, indent=2))
            plan = result.get("action_plan") or {}
            exec_res = result.get("execution_result") or {}
            if plan.get("decision") == "BLOCKED" or exec_res.get("final_outcome") in ["BLOCKED", "FAILED"]:
                sys.exit(1)
        except Exception as e:
            print(f"Error reconciling PR: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
