import argparse
import json
import sys
from .inspector import inspect_pr
from .watcher import watch_pr_once, watch_pr_loop
from .executor import plan_action, execute_action
from .reconciler import reconcile_pr_once
from .jules_transport import (
    jules_start,
    jules_status,
    jules_approve_plan,
    jules_send,
    jules_wait,
    verify_github_artifact
)

def main():
    parser = argparse.ArgumentParser(description="Agent Controller CLI")
    parser.add_argument("command", choices=[
        "inspect-pr", "watch-pr", "act-pr", "reconcile-pr",
        "jules-start", "jules-status", "jules-approve-plan", "jules-send", "jules-wait", "jules-verify-handoff"
    ], help="Command to run")

    parser.add_argument("--repo", help="Target repository in OWNER/REPO format")
    parser.add_argument("--pr", type=int, help="Target pull request number")
    parser.add_argument("--allowed-paths", nargs='*', help="List of allowed glob patterns for files (e.g. 'src/*' '*.py')")
    parser.add_argument("--denied-paths", nargs='*', help="List of denied glob patterns for files")
    parser.add_argument("--allow-docs-only", action='store_true', help="Allow PRs that only change documentation/config")

    # Arguments for watch-pr and reconcile-pr
    parser.add_argument("--once", action='store_true', help="Run a single deterministic observation or reconciliation cycle")
    parser.add_argument("--state-file", help="Path to local state/evidence file")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds for loop mode")

    # Arguments for act-pr and reconcile-pr
    parser.add_argument("--policy", help="Path to explicit local policy JSON file")
    parser.add_argument("--receipts-file", default=".action_receipts.json", help="Path to action receipts file (reconcile-pr)")
    parser.add_argument("--apply", action='store_true', help="Actually perform authorized GitHub writes")

    # Arguments for Jules commands
    parser.add_argument("--task-id", help="Controller task identity")
    parser.add_argument("--source", help="Jules source resource name")
    parser.add_argument("--starting-branch", help="Jules session starting branch")
    parser.add_argument("--expected-starting-sha", help="Expected GitHub head SHA at starting branch")
    parser.add_argument("--prompt", help="Initial task prompt for Jules session")
    parser.add_argument("--message", help="Remediation message to send to Jules session")
    parser.add_argument("--max-attempts", type=int, default=10, help="Maximum polling attempts for jules-wait")
    parser.add_argument("--no-require-plan-approval", action='store_true', help="Do not require explicit plan approval")

    args = parser.parse_args()

    # Determine default state file based on command
    if not args.state_file:
        if args.command.startswith("jules-"):
            args.state_file = ".jules_state.json"
        else:
            args.state_file = ".pr_state.json"

    owner, repo = None, None
    if args.repo:
        owner_repo = args.repo.split('/')
        if len(owner_repo) != 2:
            print("Error: --repo must be in OWNER/REPO format", file=sys.stderr)
            sys.exit(1)
        owner, repo = owner_repo

    policy = {
        'allowed_paths': args.allowed_paths,
        'denied_paths': args.denied_paths,
        'allow_docs_only': args.allow_docs_only
    }

    if args.command == "inspect-pr":
        if not owner or not args.pr:
            print("Error: --repo and --pr are required for inspect-pr", file=sys.stderr)
            sys.exit(1)
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
        if not owner or not args.pr:
            print("Error: --repo and --pr are required for watch-pr", file=sys.stderr)
            sys.exit(1)
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
        if not owner or not args.pr:
            print("Error: --repo and --pr are required for act-pr", file=sys.stderr)
            sys.exit(1)
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

    elif args.command == "reconcile-pr":
        if not owner or not args.pr:
            print("Error: --repo and --pr are required for reconcile-pr", file=sys.stderr)
            sys.exit(1)
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

    elif args.command == "jules-start":
        if not all([args.task_id, owner, repo, args.source, args.starting_branch, args.expected_starting_sha, args.prompt]):
            print("Error: --task-id, --repo, --source, --starting-branch, --expected-starting-sha, and --prompt are required for jules-start", file=sys.stderr)
            sys.exit(1)
        res = jules_start(
            task_id=args.task_id,
            owner=owner,
            repo=repo,
            source=args.source,
            starting_branch=args.starting_branch,
            expected_starting_sha=args.expected_starting_sha,
            prompt=args.prompt,
            state_file=args.state_file,
            require_plan_approval=not args.no_require_plan_approval
        )
        print(json.dumps(res, indent=2))
        if res.get("status") == "BLOCKED":
            sys.exit(1)

    elif args.command == "jules-status":
        res = jules_status(state_file=args.state_file)
        print(json.dumps(res, indent=2))
        if res.get("status") == "BLOCKED":
            sys.exit(1)

    elif args.command == "jules-approve-plan":
        res = jules_approve_plan(state_file=args.state_file)
        print(json.dumps(res, indent=2))
        if res.get("status") == "BLOCKED":
            sys.exit(1)

    elif args.command == "jules-send":
        if not args.message:
            print("Error: --message is required for jules-send", file=sys.stderr)
            sys.exit(1)
        res = jules_send(args.message, state_file=args.state_file)
        print(json.dumps(res, indent=2))
        if res.get("status") == "BLOCKED":
            sys.exit(1)

    elif args.command == "jules-wait":
        res = jules_wait(state_file=args.state_file, interval=args.interval, max_attempts=args.max_attempts)
        print(json.dumps(res, indent=2))
        if res.get("status") in ["BLOCKED", "TIMEOUT"]:
            sys.exit(1)

    elif args.command == "jules-verify-handoff":
        if not all([owner, repo, args.starting_branch, args.expected_starting_sha]):
            print("Error: --repo, --starting-branch, and --expected-starting-sha are required for jules-verify-handoff", file=sys.stderr)
            sys.exit(1)
        res = verify_github_artifact(
            owner=owner,
            repo=repo,
            target_branch=args.starting_branch,
            expected_starting_sha=args.expected_starting_sha,
            allowed_paths=args.allowed_paths,
            pr_number=args.pr
        )
        print(json.dumps(res, indent=2))
        if not res.get("verified"):
            sys.exit(1)

if __name__ == "__main__":
    main()
