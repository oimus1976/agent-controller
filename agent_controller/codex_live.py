from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from agent_controller.provider_contract import ProviderOperationRef


class CodexSdkClient(Protocol):
    """Narrow read-only seam over the official openai-codex Python SDK client."""

    def start(self) -> None:
        ...

    def initialize(self) -> Any:
        ...

    def thread_read(self, thread_id: str, include_turns: bool = False) -> Any:
        ...

    def close(self) -> None:
        ...


CodexSdkFactory = Callable[[], CodexSdkClient]


def _default_sdk_factory() -> CodexSdkClient:
    try:
        # Official SDK transport. Kept lazy so deterministic CI does not require
        # the optional live-provider dependency.
        from openai_codex.client import CodexClient
    except ImportError as exc:  # pragma: no cover - exercised only in live use
        raise RuntimeError(
            "Live Codex observation requires the official 'openai-codex' Python SDK"
        ) from exc
    return CodexClient()


def _plain(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _tag(value: Any) -> str | None:
    value = _plain(value)
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("type", "status"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
    return None


def project_codex_thread_read(thread_id: str, response: Any) -> dict[str, Any]:
    """Project official thread/read evidence into the existing safe mapper vocabulary.

    No provider prose or item contents are retained. Ambiguous idle/not-loaded
    threads without a terminal latest turn intentionally remain unknown.
    """

    payload = _plain(response)
    if not isinstance(payload, Mapping):
        return {"status": "unknown", "task_id": thread_id}

    thread = payload.get("thread")
    if not isinstance(thread, Mapping):
        return {"status": "unknown", "task_id": thread_id}

    returned_id = thread.get("id")
    if returned_id != thread_id:
        return {"status": "unknown", "task_id": thread_id}

    thread_status = _tag(thread.get("status"))
    turns = thread.get("turns")
    latest_turn = turns[-1] if isinstance(turns, list) and turns else None
    turn_status = _tag(latest_turn.get("status")) if isinstance(latest_turn, Mapping) else None

    result: dict[str, Any] = {"task_id": thread_id}

    if thread_status == "systemError":
        result.update(status="failed", result="failure")
        return result

    if thread_status == "active" or turn_status in {"inProgress", "in_progress"}:
        result["status"] = "running"
        return result

    if turn_status == "completed":
        result.update(status="done", result="success")
        return result

    if turn_status in {"failed", "interrupted"}:
        result.update(status="failed", result="failure")
        return result

    # idle/notLoaded alone does not prove that the latest requested work
    # succeeded, failed, or even exists. Preserve that ambiguity.
    result["status"] = "unknown"
    return result


@dataclass(frozen=True)
class CodexOfficialSdkReadClient:
    """Concrete ProviderReadClient backed only by official Codex SDK reads."""

    sdk_factory: CodexSdkFactory = _default_sdk_factory

    def get_operation_raw(self, operation: ProviderOperationRef) -> Any:
        if operation.provider != "codex":
            raise ValueError("CodexOfficialSdkReadClient requires provider='codex'")
        if not operation.provider_operation_id:
            raise ValueError("provider_operation_id must be nonempty")

        client = self.sdk_factory()
        try:
            client.start()
            client.initialize()
            response = client.thread_read(
                operation.provider_operation_id,
                include_turns=True,
            )
        finally:
            client.close()

        return project_codex_thread_read(operation.provider_operation_id, response)
