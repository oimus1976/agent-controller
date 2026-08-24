from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from agent_controller.repository_write_guard import (
    RepositoryWriteDecision,
    RepositoryWriteGuard,
    RepositoryWritePurpose,
    RepositoryWriteTarget,
)


@dataclass(frozen=True)
class RepositoryWriteResult:
    written: bool
    blocked: bool = False
    uncertain: bool = False
    reason: Optional[str] = None
    revision: Optional[str] = None


@runtime_checkable
class RepositoryWriteBackend(Protocol):
    def create_file(
        self, *, repo: str, ref: str, path: str, content: str, message: str
    ) -> RepositoryWriteResult: ...

    def update_file(
        self,
        *,
        repo: str,
        ref: str,
        path: str,
        content: str,
        message: str,
        expected_revision: str,
    ) -> RepositoryWriteResult: ...

    def delete_file(
        self,
        *,
        repo: str,
        ref: str,
        path: str,
        message: str,
        expected_revision: str,
    ) -> RepositoryWriteResult: ...

    def move_ref(
        self,
        *,
        repo: str,
        ref: str,
        target_sha: str,
        expected_old_sha: Optional[str],
    ) -> RepositoryWriteResult: ...


class GuardedRepositoryWriter:
    """Single Controller gateway for repository content/ref mutations.

    The backend never receives a write until the Controller-composed guard
    validates an explicit target ref. The generic gateway has no operation for
    implicit/default-branch fallback and no direct-default-branch admin mode.
    """

    __slots__ = ("_guard", "_backend")

    def __init__(
        self, *, guard: RepositoryWriteGuard, backend: RepositoryWriteBackend
    ) -> None:
        if not isinstance(guard, RepositoryWriteGuard):
            raise TypeError("guard must be RepositoryWriteGuard")
        if not isinstance(backend, RepositoryWriteBackend):
            raise TypeError("backend must satisfy RepositoryWriteBackend")
        self._guard = guard
        self._backend = backend

    def _validated_ref(
        self, *, explicit_ref: Optional[str], purpose: RepositoryWritePurpose
    ) -> tuple[Optional[str], Optional[RepositoryWriteResult]]:
        validation = self._guard.validate(
            target=RepositoryWriteTarget(
                repo=self._guard.repo,
                explicit_ref=explicit_ref,
                purpose=purpose,
            )
        )
        if validation.decision is not RepositoryWriteDecision.PASS:
            return None, RepositoryWriteResult(
                written=False,
                blocked=validation.decision is RepositoryWriteDecision.BLOCKED,
                uncertain=validation.decision is RepositoryWriteDecision.UNCERTAIN,
                reason=validation.reason,
            )
        return validation.normalized_ref, None

    @staticmethod
    def _inputs_valid(*values: object) -> bool:
        return all(isinstance(value, str) and bool(value) for value in values)

    def create_file(
        self,
        *,
        explicit_ref: Optional[str],
        purpose: RepositoryWritePurpose,
        path: str,
        content: str,
        message: str,
    ) -> RepositoryWriteResult:
        ref, failure = self._validated_ref(explicit_ref=explicit_ref, purpose=purpose)
        if failure is not None:
            return failure
        if not self._inputs_valid(path, content, message):
            return RepositoryWriteResult(False, blocked=True, reason="WRITE_INPUT_INVALID")
        try:
            return self._backend.create_file(
                repo=self._guard.repo, ref=ref, path=path, content=content, message=message
            )
        except Exception:
            return RepositoryWriteResult(False, uncertain=True, reason="WRITE_BACKEND_UNCERTAIN")

    def update_file(
        self,
        *,
        explicit_ref: Optional[str],
        purpose: RepositoryWritePurpose,
        path: str,
        content: str,
        message: str,
        expected_revision: str,
    ) -> RepositoryWriteResult:
        ref, failure = self._validated_ref(explicit_ref=explicit_ref, purpose=purpose)
        if failure is not None:
            return failure
        if not self._inputs_valid(path, content, message, expected_revision):
            return RepositoryWriteResult(False, blocked=True, reason="WRITE_INPUT_INVALID")
        try:
            return self._backend.update_file(
                repo=self._guard.repo,
                ref=ref,
                path=path,
                content=content,
                message=message,
                expected_revision=expected_revision,
            )
        except Exception:
            return RepositoryWriteResult(False, uncertain=True, reason="WRITE_BACKEND_UNCERTAIN")

    def delete_file(
        self,
        *,
        explicit_ref: Optional[str],
        purpose: RepositoryWritePurpose,
        path: str,
        message: str,
        expected_revision: str,
    ) -> RepositoryWriteResult:
        ref, failure = self._validated_ref(explicit_ref=explicit_ref, purpose=purpose)
        if failure is not None:
            return failure
        if not self._inputs_valid(path, message, expected_revision):
            return RepositoryWriteResult(False, blocked=True, reason="WRITE_INPUT_INVALID")
        try:
            return self._backend.delete_file(
                repo=self._guard.repo,
                ref=ref,
                path=path,
                message=message,
                expected_revision=expected_revision,
            )
        except Exception:
            return RepositoryWriteResult(False, uncertain=True, reason="WRITE_BACKEND_UNCERTAIN")

    def move_ref(
        self,
        *,
        explicit_ref: Optional[str],
        purpose: RepositoryWritePurpose,
        target_sha: str,
        expected_old_sha: Optional[str],
    ) -> RepositoryWriteResult:
        ref, failure = self._validated_ref(explicit_ref=explicit_ref, purpose=purpose)
        if failure is not None:
            return failure
        if not self._inputs_valid(target_sha):
            return RepositoryWriteResult(False, blocked=True, reason="WRITE_INPUT_INVALID")
        if expected_old_sha is not None and not self._inputs_valid(expected_old_sha):
            return RepositoryWriteResult(False, blocked=True, reason="WRITE_INPUT_INVALID")
        try:
            return self._backend.move_ref(
                repo=self._guard.repo,
                ref=ref,
                target_sha=target_sha,
                expected_old_sha=expected_old_sha,
            )
        except Exception:
            return RepositoryWriteResult(False, uncertain=True, reason="WRITE_BACKEND_UNCERTAIN")
