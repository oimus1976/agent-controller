from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import quote

from agent_controller.inspector import _github_api_request


class GitHubRestTargetReadClient:
    """Thin read-only GitHub REST adapter for explicit branch verification.

    This reuses the repository's existing authenticated GET transport. The
    adapter intentionally supports branch refs only; tags and arbitrary rev
    expressions are outside this MVP target-binding contract.
    """

    @staticmethod
    def _repo_parts(repo: str) -> tuple[str, str]:
        parts = repo.split("/")
        if len(parts) != 2 or not all(parts):
            raise ValueError("repo must be in OWNER/REPO format")
        return parts[0], parts[1]

    @staticmethod
    def _head_ref_path(ref: str) -> str:
        if not isinstance(ref, str) or not ref:
            raise ValueError("target ref must be nonempty")
        if ref.startswith("refs/heads/"):
            branch = ref[len("refs/heads/") :]
        elif ref.startswith("heads/"):
            branch = ref[len("heads/") :]
        elif ref.startswith("refs/"):
            raise ValueError("only branch refs are supported")
        else:
            branch = ref
        if not branch or branch.startswith("/") or branch.endswith("/"):
            raise ValueError("target branch must be nonempty")
        if ".." in branch.split("/"):
            raise ValueError("target branch contains an invalid path segment")
        return f"heads/{branch}"

    def get_ref_sha(self, repo: str, ref: str) -> str | None:
        owner, name = self._repo_parts(repo)
        ref_path = self._head_ref_path(ref)
        url = (
            "https://api.github.com/repos/"
            f"{quote(owner, safe='')}/{quote(name, safe='')}/git/ref/{quote(ref_path, safe='/')}"
        )
        try:
            payload = _github_api_request(url)
        except Exception as e:
            if str(e).startswith("GitHub API Error: 404 "):
                return None
            raise

        if not isinstance(payload, Mapping):
            raise RuntimeError("GitHub ref response is malformed")
        obj = payload.get("object")
        if not isinstance(obj, Mapping):
            raise RuntimeError("GitHub ref object is malformed")
        if obj.get("type") != "commit":
            raise RuntimeError("GitHub branch ref did not resolve to a commit")
        sha = obj.get("sha")
        if not isinstance(sha, str) or not sha:
            raise RuntimeError("GitHub branch ref SHA is malformed")
        return sha

    def compare_commits(self, repo: str, base_sha: str, head_sha: str) -> Mapping[str, Any]:
        owner, name = self._repo_parts(repo)
        if not isinstance(base_sha, str) or not base_sha:
            raise ValueError("base_sha must be nonempty")
        if not isinstance(head_sha, str) or not head_sha:
            raise ValueError("head_sha must be nonempty")
        url = (
            "https://api.github.com/repos/"
            f"{quote(owner, safe='')}/{quote(name, safe='')}/compare/"
            f"{quote(base_sha, safe='')}...{quote(head_sha, safe='')}"
        )
        payload = _github_api_request(url)
        if not isinstance(payload, Mapping):
            raise RuntimeError("GitHub compare response is malformed")

        merge_base = payload.get("merge_base_commit")
        files = payload.get("files")
        if not isinstance(merge_base, Mapping):
            raise RuntimeError("GitHub compare merge base is malformed")
        merge_base_sha = merge_base.get("sha")
        if not isinstance(merge_base_sha, str) or not merge_base_sha:
            raise RuntimeError("GitHub compare merge-base SHA is malformed")
        if not isinstance(files, list):
            raise RuntimeError("GitHub compare changed-file list is malformed")
        # GitHub's compare response may cap the file list. Never scope-verify
        # against a potentially truncated set.
        if len(files) >= 300:
            raise RuntimeError("GitHub compare changed-file set may be truncated")

        return {
            "merge_base_sha": merge_base_sha,
            "files": files,
        }
