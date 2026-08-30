from __future__ import annotations

import json
import os
from typing import Any, Callable, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agent_controller.provider_contract import ProviderOperationRef, TaskBinding


TransportCallable = Callable[[Request], tuple[int, Mapping[str, str], bytes]]


def _branch_from_ref(ref: str) -> str:
    if not ref:
        raise ValueError("starting ref must be non-empty")
    if ref.startswith("refs/heads/"):
        branch = ref[len("refs/heads/") :]
    elif ref.startswith("heads/"):
        branch = ref[len("heads/") :]
    else:
        branch = ref
    if not branch or branch.startswith("/") or branch.endswith("/"):
        raise ValueError(f"invalid branch name derived from ref: {ref!r}")
    return branch


class JulesApiClient:
    """Thin network client for the official Jules REST API (v1alpha).

    API keys are supplied exclusively via runtime configuration or the JULES_API_KEY
    environment variable and sent only via the X-Goog-Api-Key HTTP header.
    Missing credentials fail before any network call, and error handling strictly
    prevents credential leakage.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://jules.googleapis.com",
        transport: Optional[TransportCallable] = None,
    ):
        self._explicit_api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._transport = transport

    def get_api_key(self) -> str:
        key = self._explicit_api_key or os.environ.get("JULES_API_KEY")
        if not key or not key.strip():
            raise ValueError("JULES_API_KEY is required for live Jules API operations")
        return key.strip()

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        api_key = self.get_api_key()
        clean_path = path.lstrip("/")
        url = f"{self.base_url}/v1alpha/{clean_path}"

        headers = {
            "X-Goog-Api-Key": api_key,
            "Accept": "application/json",
        }
        data: Optional[bytes] = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        req = Request(url, data=data, headers=headers, method=method)

        try:
            if self._transport is not None:
                status, resp_headers, resp_data = self._transport(req)
            else:
                with urlopen(req) as resp:
                    status = resp.status
                    resp_headers = dict(resp.headers)
                    resp_data = resp.read()

            if status < 200 or status >= 300:
                raise RuntimeError(f"Jules API request failed with status {status}")

            if not resp_data:
                return {}

            return json.loads(resp_data.decode("utf-8"))

        except (HTTPError, URLError, OSError, json.JSONDecodeError, RuntimeError) as exc:
            # Sanitize error message to ensure API key is never leaked
            err_msg = str(exc)
            if api_key in err_msg:
                err_msg = err_msg.replace(api_key, "[REDACTED]")
            raise RuntimeError(f"Jules API network call failed: {err_msg}") from None

    def list_sources(self) -> list[dict[str, Any]]:
        res = self._request("GET", "sources")
        sources = res.get("sources", [])
        return sources if isinstance(sources, list) else []

    def resolve_source(self, repo: str) -> str:
        if not repo or not isinstance(repo, str):
            raise ValueError("repo must be a non-empty string")
        if repo.startswith("sources/"):
            return repo

        # Standard canonical Jules source identifier for GitHub repos
        return f"sources/github.com/{repo}"

    def create_session(
        self,
        prompt: str,
        source: str,
        starting_branch: str,
        title: Optional[str] = None,
        require_plan_approval: bool = True,
    ) -> dict[str, Any]:
        if not prompt or not isinstance(prompt, str):
            raise ValueError("prompt must be a non-empty string")
        if not source or not isinstance(source, str):
            raise ValueError("source must be a non-empty string")
        if not starting_branch or not isinstance(starting_branch, str):
            raise ValueError("starting_branch must be a non-empty string")

        payload: dict[str, Any] = {
            "prompt": prompt,
            "sourceContext": {
                "source": source,
                "githubRepoContext": {
                    "startingBranch": starting_branch,
                },
            },
            "requirePlanApproval": require_plan_approval,
            "automationMode": "AUTOMATION_MODE_UNSPECIFIED",
        }
        if title:
            payload["title"] = title

        return self._request("POST", "sessions", body=payload)

    def get_session(self, session_id: str) -> dict[str, Any]:
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string")

        clean_id = session_id
        if clean_id.startswith("sessions/"):
            clean_id = clean_id[len("sessions/") :]

        return self._request("GET", f"sessions/{clean_id}")


class JulesDispatchClient:
    """Dispatch seam implementation for live official Jules API."""

    def __init__(self, api_client: JulesApiClient, default_prompt: Optional[str] = None):
        self.api_client = api_client
        self.default_prompt = default_prompt

    def dispatch(self, task: TaskBinding, prompt: Optional[str] = None) -> ProviderOperationRef:
        if task.provider != "jules":
            raise ValueError("JulesDispatchClient requires task.provider='jules'")
        if not task.repo:
            raise ValueError("TaskBinding.repo is required for Jules dispatch")
        if not task.expected_start_ref:
            raise ValueError("TaskBinding.expected_start_ref is required for Jules dispatch")
        if not task.expected_start_sha:
            raise ValueError("TaskBinding.expected_start_sha is required for Jules dispatch")

        starting_branch = _branch_from_ref(task.expected_start_ref)
        source = self.api_client.resolve_source(task.repo)

        effective_prompt = prompt or self.default_prompt or f"Task {task.controller_task_id}: {task.requested_capability}"

        session = self.api_client.create_session(
            prompt=effective_prompt,
            source=source,
            starting_branch=starting_branch,
            title=f"Task {task.controller_task_id}",
            require_plan_approval=True,
        )

        session_id = session.get("id")
        session_name = session.get("name")
        if not session_id and session_name and isinstance(session_name, str):
            session_id = session_name.split("/")[-1]

        if not session_id or not isinstance(session_id, str):
            raise RuntimeError("Jules API create_session response missing valid session ID")

        session_url = session.get("url") if isinstance(session.get("url"), str) else None

        return ProviderOperationRef(
            provider="jules",
            provider_operation_id=session_id,
            provider_url=session_url,
            controller_task_id=task.controller_task_id,
            operation_id=task.operation_id,
        )


class JulesReadClient:
    """Read seam implementation for live official Jules API observation."""

    def __init__(self, api_client: JulesApiClient):
        self.api_client = api_client

    def get_operation_raw(self, operation: ProviderOperationRef) -> Any:
        if operation.provider != "jules":
            raise ValueError("JulesReadClient requires operation.provider='jules'")
        if not operation.provider_operation_id:
            raise ValueError("operation.provider_operation_id must be non-empty")

        return self.api_client.get_session(operation.provider_operation_id)
