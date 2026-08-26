from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from agent_controller.provider_contract import ProviderOperationRef


class CodexSdkClient(Protocol):
    """Narrow read-only seam over the official openai-codex app-server client."""

    def start(self) -> None:
        ...

    def initialize(self) -> Any:
        ...

    def thread_read(self, thread_id: str, include_turns: bool = False) -> Any:
        ...

    def close(self) -> None:
        ...


CodexSdkFactory = Callable[[str], CodexSdkClient]


def _default_sdk_factory(codex_bin: str) -> CodexSdkClient:
    try:
        # Official openai-codex package. The high-level public Codex API does
        # not currently expose a pure read-only thread discovery/read method,
        # so this slice deliberately uses the package's official app-server
        # client rather than resuming/starting a thread through the high-level
        # API. Treat API drift as unavailable evidence rather than falling back
        # to a mutating path.
        from openai_codex.client import CodexClient
    except ImportError as exc:  # pragma: no cover - exercised only in live use
        raise RuntimeError(
            "Live Codex observation requires the official 'openai-codex' Python package"
        ) from exc

    try:
        return CodexClient(codex_bin=codex_bin)
    except TypeError as exc:  # pragma: no cover - version-drift protection
        raise RuntimeError(
            "Installed openai-codex package is incompatible with the read-only client contract"
        ) from exc


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
    """Concrete ProviderReadClient backed only by official Codex app-server reads."""

    sdk_factory: CodexSdkFactory = _default_sdk_factory
    codex_bin: str = "codex"
    timeout_seconds: float = 15.0

    def __post_init__(self):
        if not isinstance(self.codex_bin, str) or not self.codex_bin:
            raise ValueError("codex_bin must be a nonempty string")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    def _read_once(self, operation: ProviderOperationRef) -> Any:
        client = self.sdk_factory(self.codex_bin)
        try:
            for required in ("start", "initialize", "thread_read", "close"):
                if not callable(getattr(client, required, None)):
                    raise RuntimeError(
                        "Installed openai-codex package is incompatible with the read-only client contract"
                    )
            client.start()
            client.initialize()
            response = client.thread_read(
                operation.provider_operation_id,
                include_turns=True,
            )
        finally:
            client.close()

        return response

    def get_operation_raw(self, operation: ProviderOperationRef) -> Any:
        if operation.provider != "codex":
            raise ValueError("CodexOfficialSdkReadClient requires provider='codex'")
        if not operation.provider_operation_id:
            raise ValueError("provider_operation_id must be nonempty")

        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="codex-read")
        future = executor.submit(self._read_once, operation)
        try:
            response = future.result(timeout=self.timeout_seconds)
        except FutureTimeoutError as exc:
            future.cancel()
            raise TimeoutError(
                f"Codex thread/read exceeded {self.timeout_seconds:g}s timeout"
            ) from exc
        finally:
            # Do not wait forever for a wedged SDK/app-server thread during
            # fail-closed timeout handling. The worker's finally block still
            # closes the provider client if/when the call returns.
            executor.shutdown(wait=False, cancel_futures=True)

        return project_codex_thread_read(operation.provider_operation_id, response)
