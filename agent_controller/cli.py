import argparse
import sys
from .inspector import inspect_pr

def main():
    parser = argparse.ArgumentParser(description="Agent Controller: PR Inspector")
    parser.add_argument("command", choices=["inspect-pr"], help="Command to run")
    parser.add_argument("--repo", required=True, help="Target repository in OWNER/REPO format")
    parser.add_argument("--pr", required=True, type=int, help="Target pull request number")
    parser.add_argument("--allowed-paths", nargs='*', help="List of allowed glob patterns for files (e.g. 'src/*' '*.py')")
    parser.add_argument("--denied-paths", nargs='*', help="List of denied glob patterns for files")
    parser.add_argument("--allow-docs-only", action='store_true', help="Allow PRs that only change documentation/config")

    args = parser.parse_args()

    if args.command == "inspect-pr":
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

if __name__ == "__main__":
    main()
