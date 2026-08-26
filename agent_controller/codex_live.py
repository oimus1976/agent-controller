from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
import hashlib
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable, Mapping, Protocol
import uuid

from agent_controller.provider_contract import ProviderOperationRef


SUPPORTED_CODEX_SDK_VERSION = "0.147.0"
_KNOWN_THREAD_STATUSES = frozenset({"notLoaded", "idle", "systemError", "active"})
_ROLLOUT_ROOTS = ("sessions", "archived_sessions")
_ROLLOUT_SUFFIXES = (".jsonl", ".jsonl.zst")


class CodexSdkClient(Protocol):
    """Narrow read-only RPC seam over the official openai-codex app-server client."""

    def start(self) -> None:
        ...

    def initialize(self) -> Any:
        ...

    def thread_read(self, thread_id: str, include_turns: bool = False) -> Any:
        ...

    def close(self) -> None:
        ...


CodexSdkFactory = Callable[[str | None, str], CodexSdkClient]


def _reject_server_request(method: str, _params: Any) -> dict[str, Any]:
    """Fail closed if app-server unexpectedly asks this observer to authorize anything."""

    raise RuntimeError(
        f"Unexpected Codex server request during read-only observation: {method}"
    )


def _default_sdk_factory(codex_bin: str | None, codex_home: str) -> CodexSdkClient:
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
        # Important: app-server startup writes local runtime state even when the
        # only RPC is thread/read. Callers must therefore pass an explicitly
        # disposable Codex home; never rely on inherited/default CODEX_HOME.
        config = CodexConfig(
            codex_bin=codex_bin,
            env={"CODEX_HOME": codex_home},
        )
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


def _canonical_thread_id(thread_id: str) -> str:
    try:
        canonical = str(uuid.UUID(thread_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("snapshot Codex thread id must be a UUID") from exc
    if thread_id != canonical:
        raise ValueError("snapshot Codex thread id must use canonical lowercase UUID form")
    return canonical


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _find_rollout(source_home: Path, thread_id: str) -> Path:
    matches: list[Path] = []
    for root_name in _ROLLOUT_ROOTS:
        root = source_home / root_name
        if not root.is_dir():
            continue
        for candidate in root.rglob(f"*{thread_id}*"):
            if not candidate.is_file():
                continue
            if not candidate.name.endswith(_ROLLOUT_SUFFIXES):
                continue
            if candidate.is_symlink():
                raise RuntimeError("Codex rollout evidence must not be a symlink")
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(source_home):
                raise RuntimeError("Codex rollout evidence escapes the declared source home")
            matches.append(resolved)

    unique = sorted(set(matches))
    if not unique:
        raise FileNotFoundError(
            f"No persisted Codex rollout found for thread {thread_id} under {source_home}"
        )
    if len(unique) != 1:
        raise RuntimeError(
            f"Ambiguous Codex rollout evidence for thread {thread_id}: found {len(unique)} files"
        )
    return unique[0]


def _resolve_snapshot_parent(source_home: Path, snapshot_parent: str | None) -> Path:
    """Resolve the temp parent before creating anything and keep it outside source home."""

    configured_parent = (
        Path(snapshot_parent) if snapshot_parent is not None else Path(tempfile.gettempdir())
    )
    try:
        resolved_parent = configured_parent.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("snapshot_parent must resolve to an existing directory") from exc
    if not resolved_parent.is_dir():
        raise ValueError("snapshot_parent must resolve to an existing directory")
    if resolved_parent == source_home or resolved_parent.is_relative_to(source_home):
        raise RuntimeError(
            "snapshot_parent must resolve outside source_codex_home before snapshot creation"
        )
    return resolved_parent


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
    """Low-level official app-server reader confined to an explicit writable Codex home.

    The RPC surface is read-only, but app-server startup itself writes runtime
    state. This class therefore requires an explicit absolute codex_home and is
    intended to be used only with Controller-owned disposable state.
    """

    codex_home: str
    sdk_factory: CodexSdkFactory = _default_sdk_factory
    codex_bin: str | None = None
    timeout_seconds: float = 15.0

    def __post_init__(self):
        if not isinstance(self.codex_home, str) or not self.codex_home:
            raise ValueError("codex_home must be a nonempty absolute path")
        if not Path(self.codex_home).is_absolute():
            raise ValueError("codex_home must be an absolute path")
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

        client = self.sdk_factory(self.codex_bin, self.codex_home)
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


@dataclass(frozen=True)
class CodexSnapshotReadClient:
    """Observe one persisted Codex thread without exposing its source home to app-server.

    Only the target rollout is copied into a disposable Codex home. Source
    hashes are checked before/after the copy and again after observation, so an
    actively changing or inconsistent source fails closed.
    """

    source_codex_home: str
    sdk_factory: CodexSdkFactory = _default_sdk_factory
    codex_bin: str | None = None
    timeout_seconds: float = 15.0
    snapshot_parent: str | None = None

    def __post_init__(self):
        if not isinstance(self.source_codex_home, str) or not self.source_codex_home:
            raise ValueError("source_codex_home must be a nonempty absolute path")
        if not Path(self.source_codex_home).is_absolute():
            raise ValueError("source_codex_home must be an absolute path")
        if self.snapshot_parent is not None and not Path(self.snapshot_parent).is_absolute():
            raise ValueError("snapshot_parent must be None or an absolute path")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    def get_operation_raw(self, operation: ProviderOperationRef) -> Any:
        if operation.provider != "codex":
            raise ValueError("CodexSnapshotReadClient requires provider='codex'")
        thread_id = _canonical_thread_id(operation.provider_operation_id)

        source_home = Path(self.source_codex_home).resolve(strict=True)
        if not source_home.is_dir():
            raise ValueError("source_codex_home must resolve to a directory")
        snapshot_parent = _resolve_snapshot_parent(source_home, self.snapshot_parent)
        source_rollout = _find_rollout(source_home, thread_id)
        relative_rollout = source_rollout.relative_to(source_home)
        source_hash_before = _sha256_file(source_rollout)

        with tempfile.TemporaryDirectory(
            prefix="agent-controller-codex-snapshot-",
            dir=str(snapshot_parent),
        ) as temporary_home:
            snapshot_home = Path(temporary_home).resolve(strict=True)
            if snapshot_home.is_relative_to(source_home) or source_home.is_relative_to(
                snapshot_home
            ):
                raise RuntimeError(
                    "snapshot CODEX_HOME overlaps source_codex_home; refusing observation"
                )
            snapshot_rollout = snapshot_home / relative_rollout
            snapshot_rollout.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_rollout, snapshot_rollout)

            source_hash_after_copy = _sha256_file(source_rollout)
            snapshot_hash = _sha256_file(snapshot_rollout)
            if not (
                source_hash_before == source_hash_after_copy == snapshot_hash
            ):
                raise RuntimeError(
                    "Codex rollout changed during snapshot copy or snapshot hash mismatched"
                )

            reader = CodexOfficialSdkReadClient(
                codex_home=str(snapshot_home),
                sdk_factory=self.sdk_factory,
                codex_bin=self.codex_bin,
                timeout_seconds=self.timeout_seconds,
            )
            try:
                raw = reader.get_operation_raw(operation)
            finally:
                source_hash_after_observation = _sha256_file(source_rollout)
                if source_hash_after_observation != source_hash_before:
                    raise RuntimeError(
                        "Codex source rollout changed during observation; evidence is stale"
                    )

            return raw
