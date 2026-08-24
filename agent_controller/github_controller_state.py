from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from agent_controller.repository_write_guard import (
    RepositoryWriteGuard,
    RepositoryWritePurpose,
)
from agent_controller.repository_writer import (
    GuardedRepositoryWriter,
    RepositoryWriteBackend,
    RepositoryWriteResult,
)


CONTROLLER_STATE_REF = "controller-state"


@dataclass(frozen=True)
class GitHubContentsResponse:
    status_code: int
    content: Optional[str] = None
    revision: Optional[str] = None


@runtime_checkable
class GitHubContentsTransport(Protocol):
    def read_file(self, *, repo: str, ref: str, path: str) -> GitHubContentsResponse: ...

    def create_file(
        self, *, repo: str, ref: str, path: str, content: str, message: str
    ) -> GitHubContentsResponse: ...

    def update_file(
        self,
        *,
        repo: str,
        ref: str,
        path: str,
        content: str,
        message: str,
        expected_revision: str,
    ) -> GitHubContentsResponse: ...

    def delete_file(
        self,
        *,
        repo: str,
        ref: str,
        path: str,
        message: str,
        expected_revision: str,
    ) -> GitHubContentsResponse: ...

    def move_ref(
        self,
        *,
        repo: str,
        ref: str,
        target_sha: str,
        expected_old_sha: Optional[str],
    ) -> GitHubContentsResponse: ...


@dataclass(frozen=True)
class ControllerStateSnapshot:
    content: str
    revision: str


@dataclass(frozen=True)
class ControllerStateWriteResult:
    written: bool
    conflict: bool = False
    uncertain: bool = False
    revision: Optional[str] = None
    reason: Optional[str] = None


def _valid_response(response: object) -> bool:
    return isinstance(response, GitHubContentsResponse) and isinstance(response.status_code, int)


def _map_write_response(response: object) -> RepositoryWriteResult:
    if not _valid_response(response):
        return RepositoryWriteResult(False, uncertain=True, reason="GITHUB_RESPONSE_INVALID")
    if response.status_code in {200, 201}:
        if not isinstance(response.revision, str) or not response.revision:
            return RepositoryWriteResult(False, uncertain=True, reason="GITHUB_REVISION_MISSING")
        return RepositoryWriteResult(True, revision=response.revision)
    if response.status_code in {409, 422}:
        return RepositoryWriteResult(False, blocked=True, reason="GITHUB_WRITE_CONFLICT")
    return RepositoryWriteResult(
        False, uncertain=True, reason=f"GITHUB_WRITE_STATUS_{response.status_code}"
    )


class GitHubRepositoryWriteBackend(RepositoryWriteBackend):
    """Raw GitHub transport backend used only behind GuardedRepositoryWriter."""

    __slots__ = ("_transport",)

    def __init__(self, *, transport: GitHubContentsTransport) -> None:
        if not isinstance(transport, GitHubContentsTransport):
            raise TypeError("transport must satisfy GitHubContentsTransport")
        self._transport = transport

    def create_file(self, **kwargs) -> RepositoryWriteResult:
        try:
            return _map_write_response(self._transport.create_file(**kwargs))
        except Exception:
            return RepositoryWriteResult(
                False, uncertain=True, reason="GITHUB_TRANSPORT_UNCERTAIN"
            )

    def update_file(self, **kwargs) -> RepositoryWriteResult:
        try:
            return _map_write_response(self._transport.update_file(**kwargs))
        except Exception:
            return RepositoryWriteResult(
                False, uncertain=True, reason="GITHUB_TRANSPORT_UNCERTAIN"
            )

    def delete_file(self, **kwargs) -> RepositoryWriteResult:
        try:
            return _map_write_response(self._transport.delete_file(**kwargs))
        except Exception:
            return RepositoryWriteResult(
                False, uncertain=True, reason="GITHUB_TRANSPORT_UNCERTAIN"
            )

    def move_ref(self, **kwargs) -> RepositoryWriteResult:
        try:
            return _map_write_response(self._transport.move_ref(**kwargs))
        except Exception:
            return RepositoryWriteResult(
                False, uncertain=True, reason="GITHUB_TRANSPORT_UNCERTAIN"
            )


class GitHubControllerStateAdapter:
    """Fixed-ref controller-state storage with create-if-absent and blob-SHA CAS."""

    __slots__ = ("_repo", "_transport", "_writer")

    def __init__(
        self,
        *,
        repo: str,
        default_branch: str,
        transport: GitHubContentsTransport,
    ) -> None:
        if not isinstance(repo, str) or not repo:
            raise ValueError("repo must be non-empty")
        if not isinstance(default_branch, str) or not default_branch:
            raise ValueError("default_branch must be non-empty")
        if not isinstance(transport, GitHubContentsTransport):
            raise TypeError("transport must satisfy GitHubContentsTransport")
        backend = GitHubRepositoryWriteBackend(transport=transport)
        writer = GuardedRepositoryWriter(
            guard=RepositoryWriteGuard(repo=repo, default_branch=default_branch),
            backend=backend,
        )
        self._repo = repo
        self._transport = transport
        self._writer = writer

    @property
    def state_ref(self) -> str:
        return CONTROLLER_STATE_REF

    def read(self, *, path: str) -> Optional[ControllerStateSnapshot]:
        if not isinstance(path, str) or not path:
            raise ValueError("path must be non-empty")
        try:
            response = self._transport.read_file(
                repo=self._repo, ref=CONTROLLER_STATE_REF, path=path
            )
        except Exception as exc:
            raise RuntimeError("GITHUB_STATE_READ_UNCERTAIN") from exc
        if not _valid_response(response):
            raise RuntimeError("GITHUB_STATE_RESPONSE_INVALID")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise RuntimeError(f"GITHUB_STATE_READ_STATUS_{response.status_code}")
        if not isinstance(response.content, str):
            raise RuntimeError("GITHUB_STATE_CONTENT_INVALID")
        if not isinstance(response.revision, str) or not response.revision:
            raise RuntimeError("GITHUB_STATE_REVISION_INVALID")
        return ControllerStateSnapshot(response.content, response.revision)

    def create_if_absent(
        self, *, path: str, content: str, message: str
    ) -> ControllerStateWriteResult:
        result = self._writer.create_file(
            explicit_ref=CONTROLLER_STATE_REF,
            purpose=RepositoryWritePurpose.CONTROLLER_STATE,
            path=path,
            content=content,
            message=message,
        )
        if result.written:
            return ControllerStateWriteResult(True, revision=result.revision)
        if result.reason == "GITHUB_WRITE_CONFLICT":
            return ControllerStateWriteResult(False, conflict=True, reason=result.reason)
        if result.blocked:
            return ControllerStateWriteResult(
                False, conflict=False, uncertain=False, reason=result.reason
            )
        return ControllerStateWriteResult(False, uncertain=True, reason=result.reason)

    def compare_and_swap(
        self,
        *,
        path: str,
        expected_revision: str,
        content: str,
        message: str,
    ) -> ControllerStateWriteResult:
        result = self._writer.update_file(
            explicit_ref=CONTROLLER_STATE_REF,
            purpose=RepositoryWritePurpose.CONTROLLER_STATE,
            path=path,
            content=content,
            message=message,
            expected_revision=expected_revision,
        )
        if result.written:
            return ControllerStateWriteResult(True, revision=result.revision)
        if result.reason == "GITHUB_WRITE_CONFLICT":
            return ControllerStateWriteResult(False, conflict=True, reason=result.reason)
        if result.blocked:
            return ControllerStateWriteResult(
                False, conflict=False, uncertain=False, reason=result.reason
            )
        return ControllerStateWriteResult(False, uncertain=True, reason=result.reason)
