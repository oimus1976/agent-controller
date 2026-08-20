import argparse
import sys
import json
from .inspector import inspect_pr
from .watcher import watch_pr_once, watch_pr_loop

def main():
    parser = argparse.ArgumentParser(description="Agent Controller: PR Inspector")
    parser.add_argument("command", choices=["inspect-pr", "watch-pr"], help="Command to run")
    parser.add_argument("--repo", required=True, help="Target repository in OWNER/REPO format")
    parser.add_argument("--pr", required=True, type=int, help="Target pull request number")
    parser.add_argument("--allowed-paths", nargs='*', help="List of allowed glob patterns for files (e.g. 'src/*' '*.py')")
    parser.add_argument("--denied-paths", nargs='*', help="List of denied glob patterns for files")
    parser.add_argument("--allow-docs-only", action='store_true', help="Allow PRs that only change documentation/config")

    # Arguments for watch-pr
    parser.add_argument("--once", action='store_true', help="Run a single deterministic observation (watch-pr)")
    parser.add_argument("--state-file", default=".pr_state.json", help="Path to local state/evidence file (watch-pr)")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds for loop mode (watch-pr)")

    args = parser.parse_args()

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
        try:
            result = inspect_pr(owner, repo, args.pr, scope_policy=policy)
            print(f"PR State: {result['classification']}")
            print(f"Head SHA: {result['head_sha']}")
            print(f"Base Branch: {result['base_branch']}")
            print(f"Draft: {result['draft']}")
            print(f"Merged: {result['merged']}")

            # Print more detailed objective evidence as needed
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

if __name__ == "__main__":
    main()
