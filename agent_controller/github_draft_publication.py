from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping, Optional, Sequence

from agent_controller.jules_patch import ParsedTextPatch

_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")


class GitHubRestDraftPublicationBackend:
    """Narrow GitHub REST/Git Data backend for one Draft-PR publication path."""

    def __init__(self, token: Optional[str] = None, api_url: str = "https://api.github.com") -> None:
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._tree_cache: dict[tuple[str, str], dict[str, tuple[str, str]]] = {}

    def _token_value(self) -> str:
        token = self._token or os.environ.get("GITHUB_TOKEN")
        if not isinstance(token, str) or not token.strip():
            raise RuntimeError("GITHUB_TOKEN is required")
        return token.strip()

    @staticmethod
    def _repo(repo: str) -> tuple[str, str]:
        if not isinstance(repo, str) or repo.count("/") != 1:
            raise ValueError("repo must be OWNER/REPO")
        owner, name = repo.split("/", 1)
        if not owner or not name:
            raise ValueError("repo must be OWNER/REPO")
        return owner, name

    def _request(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None) -> Any:
        token = self._token_value()
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self._api_url}/{path.lstrip('/')}", data=data, method=method,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", **({"Content-Type": "application/json"} if data else {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
                return {} if not raw else json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace").replace(token, "[REDACTED]")
            raise RuntimeError(f"GitHub API request failed: {exc.code} {raw[:500]}") from None
        except Exception as exc:
            raise RuntimeError(f"GitHub API request failed: {str(exc).replace(token, '[REDACTED]')}") from None

    def get_default_branch(self, repo: str) -> str:
        owner, name = self._repo(repo)
        value = self._request("GET", f"repos/{owner}/{name}").get("default_branch")
        if not isinstance(value, str) or not value:
            raise RuntimeError("default_branch unavailable")
        return value

    def get_ref_sha(self, repo: str, ref: str) -> Optional[str]:
        owner, name = self._repo(repo)
        clean = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
        try:
            payload = self._request("GET", f"repos/{owner}/{name}/git/ref/heads/{urllib.parse.quote(clean, safe='/')}")
        except RuntimeError as exc:
            if " 404 " in str(exc):
                return None
            raise
        sha = payload.get("object", {}).get("sha")
        if not isinstance(sha, str) or not _SHA40.fullmatch(sha):
            raise RuntimeError("malformed ref SHA")
        return sha

    def _tree_entries(self, repo: str, commit_sha: str) -> dict[str, tuple[str, str]]:
        key = (repo, commit_sha)
        if key in self._tree_cache:
            return self._tree_cache[key]
        owner, name = self._repo(repo)
        commit = self._request("GET", f"repos/{owner}/{name}/git/commits/{commit_sha}")
        tree_sha = commit.get("tree", {}).get("sha") if isinstance(commit, Mapping) else None
        if not isinstance(tree_sha, str) or not _SHA40.fullmatch(tree_sha):
            raise RuntimeError("base tree unavailable")
        payload = self._request("GET", f"repos/{owner}/{name}/git/trees/{tree_sha}?recursive=1")
        if not isinstance(payload, Mapping) or payload.get("truncated") is True:
            raise RuntimeError("base tree listing unavailable or truncated")
        rows = payload.get("tree")
        if not isinstance(rows, list):
            raise RuntimeError("base tree listing malformed")
        entries: dict[str, tuple[str, str]] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                raise RuntimeError("base tree entry malformed")
            path, mode, kind = row.get("path"), row.get("mode"), row.get("type")
            if not all(isinstance(value, str) and value for value in (path, mode, kind)):
                raise RuntimeError("base tree entry malformed")
            entries[path] = (mode, kind)
        self._tree_cache[key] = entries
        return entries

    def get_file_text(self, repo: str, commit_sha: str, path: str) -> Optional[str]:
        entries = self._tree_entries(repo, commit_sha)
        entry = entries.get(path)
        if entry is None:
            return None
        if entry != ("100644", "blob"):
            raise RuntimeError("base path is not supported regular 100644 text")
        owner, name = self._repo(repo)
        payload = self._request("GET", f"repos/{owner}/{name}/contents/{urllib.parse.quote(path, safe='/')}?ref={commit_sha}")
        if payload.get("type") != "file" or payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
            raise RuntimeError("unsupported base file")
        try:
            return base64.b64decode(payload["content"]).decode("utf-8")
        except Exception:
            raise RuntimeError("base file is not UTF-8 text") from None

    def create_commit_from_text_changes(self, *, repo: str, base_sha: str, changes: Sequence[ParsedTextPatch], message: str) -> str:
        owner, name = self._repo(repo)
        commit = self._request("GET", f"repos/{owner}/{name}/git/commits/{base_sha}")
        base_tree = commit.get("tree", {}).get("sha")
        if not isinstance(base_tree, str) or not _SHA40.fullmatch(base_tree):
            raise RuntimeError("base tree unavailable")
        entries: list[dict[str, Any]] = []
        for change in changes:
            if change.old_path is not None and change.old_path != change.new_path:
                entries.append({"path": change.old_path, "mode": "100644", "type": "blob", "sha": None})
            if change.new_path is None:
                continue
            if change.new_text is None:
                raise RuntimeError("new text missing")
            blob = self._request("POST", f"repos/{owner}/{name}/git/blobs", {"content": change.new_text, "encoding": "utf-8"})
            blob_sha = blob.get("sha")
            if not isinstance(blob_sha, str) or not _SHA40.fullmatch(blob_sha):
                raise RuntimeError("blob SHA malformed")
            entries.append({"path": change.new_path, "mode": "100644", "type": "blob", "sha": blob_sha})
        tree = self._request("POST", f"repos/{owner}/{name}/git/trees", {"base_tree": base_tree, "tree": entries})
        tree_sha = tree.get("sha")
        if not isinstance(tree_sha, str) or not _SHA40.fullmatch(tree_sha):
            raise RuntimeError("tree SHA malformed")
        created = self._request("POST", f"repos/{owner}/{name}/git/commits", {"message": message, "tree": tree_sha, "parents": [base_sha]})
        sha = created.get("sha")
        if not isinstance(sha, str) or not _SHA40.fullmatch(sha):
            raise RuntimeError("commit SHA malformed")
        return sha

    def create_branch(self, repo: str, branch: str, sha: str) -> None:
        owner, name = self._repo(repo)
        self._request("POST", f"repos/{owner}/{name}/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})

    def list_open_prs_for_branch(self, repo: str, branch: str) -> Sequence[Mapping[str, Any]]:
        owner, name = self._repo(repo)
        head = urllib.parse.quote(f"{owner}:{branch}", safe=":")
        payload = self._request("GET", f"repos/{owner}/{name}/pulls?state=open&head={head}&per_page=100")
        if not isinstance(payload, list) or any(not isinstance(item, Mapping) for item in payload):
            raise RuntimeError("malformed PR list")
        return tuple(payload)

    def create_draft_pr(self, *, repo: str, head: str, base: str, title: str, body: str) -> Mapping[str, Any]:
        owner, name = self._repo(repo)
        payload = self._request("POST", f"repos/{owner}/{name}/pulls", {"title": title, "head": head, "base": base, "body": body, "draft": True})
        if not isinstance(payload, Mapping):
            raise RuntimeError("malformed PR creation response")
        return payload

    def get_pr(self, repo: str, pr_number: int) -> Mapping[str, Any]:
        owner, name = self._repo(repo)
        payload = self._request("GET", f"repos/{owner}/{name}/pulls/{pr_number}")
        if not isinstance(payload, Mapping):
            raise RuntimeError("malformed PR response")
        return payload

    def compare_files(self, repo: str, base_sha: str, head_sha: str) -> Sequence[Mapping[str, Any]]:
        owner, name = self._repo(repo)
        payload = self._request("GET", f"repos/{owner}/{name}/compare/{base_sha}...{head_sha}")
        files = payload.get("files") if isinstance(payload, Mapping) else None
        if not isinstance(files, list) or any(not isinstance(item, Mapping) for item in files) or len(files) >= 300:
            raise RuntimeError("compare files unavailable or truncated")
        return tuple(files)
