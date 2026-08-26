from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from agent_controller.provider_contract import ProviderOperationRef


SUPPORTED_CODEX_SDK_VERSION = "0.147.0"
_KNOWN_THREAD_STATUSES = frozenset({"notLoaded", "idle", "systemError", "active"})


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


CodexSdkFactory = Callable[[str | None], CodexSdkClient]


def _reject_server_request(method: str, _params: Any) -> dict[str, Any]:
    """Fail closed if app-server unexpectedly asks this observer to authorize anything."""

    raise RuntimeError(
        f"Unexpected Codex server request during read-only observation: {method}"
    )


def _default_sdk_factory(codex_bin: str | None) -> CodexSdkClient:
    try:
        # CodexConfig/version are public Python SDK surfaces. CodexClient is
        # official package code for the app-server JSON-RPC protocol, but it is
        # intentionally lower-level than the curated high-level Codex API.
        # We use it because the public high-level API currently exposes thread
        # listing but no pure thread/read equivalent; thread_resume would be a
        # lifecycle operation and is outside this read-only slice.
        import openai_codex
        from openai_codex import CodexConfig
        from openai_codex.client import CodexClient
    except ImportError as exc:  # pragma: no cover - exercised only in live use
        raise RuntimeError(
            "Live Codex observation requires 'openai-codex==0.147.0'; "
            "install requirements-codex.txt"
        ) from exc

    installed_version = getattr(openai_codex, "__version__", None)
    if installed_version != SUPPORTED_CODEX_SDK_VERSION:  # pragma: no cover - live only
        raise RuntimeError(
            "Unsupported openai-codex version for read-only observation: "
            f"expected {SUPPORTED_CODEX_SDK_VERSION}, found {installed_version!r}"
        )

    try:
        config = CodexConfig(codex_bin=codex_bin)
        return CodexClient(config=config, approval_handler=_reject_server_request)
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
    if thread_status not in _KNOWN_THREAD_STATUSES:
        return {"status": "unknown", "task_id": thread_id}

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
    codex_bin: str | None = None
    timeout_seconds: float = 15.0

    def __post_init__(self):
        if self.codex_bin is not None and (
            not isinstance(self.codex_bin, str) or not self.codex_bin
        ):
            raise ValueError("codex_bin must be None or a nonempty string")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    @staticmethod
    def _read_once(client: CodexSdkClient, operation: ProviderOperationRef) -> Any:
        client.start()
        client.initialize()
        return client.thread_read(
            operation.provider_operation_id,
            include_turns=True,
        )

    def get_operation_raw(self, operation: ProviderOperationRef) -> Any:
        if operation.provider != "codex":
            raise ValueError("CodexOfficialSdkReadClient requires provider='codex'")
        if not operation.provider_operation_id:
            raise ValueError("provider_operation_id must be nonempty")

        client = self.sdk_factory(self.codex_bin)
        for required in ("start", "initialize", "thread_read", "close"):
            if not callable(getattr(client, required, None)):
                try:
                    client.close()
                finally:
                    raise RuntimeError(
                        "Installed openai-codex package is incompatible with the read-only client contract"
                    )

        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="codex-read")
        future = executor.submit(self._read_once, client, operation)
        try:
            response = future.result(timeout=self.timeout_seconds)
        except FutureTimeoutError as exc:
            # The upstream low-level request waiter has no timeout. Closing the
            # official client terminates app-server and causes pending readers
            # to fail rather than leaving the observer wedged indefinitely.
            client.close()
            future.cancel()
            raise TimeoutError(
                f"Codex thread/read exceeded {self.timeout_seconds:g}s timeout"
            ) from exc
        finally:
            try:
                client.close()
            finally:
                executor.shutdown(wait=False, cancel_futures=True)

        return project_codex_thread_read(operation.provider_operation_id, response)
