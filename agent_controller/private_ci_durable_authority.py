from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agent_controller.private_ci_contract import PrivateCiTargetOs


_SCHEMA_VERSION = 1
_STATE_RESERVED = "RESERVED"
_STATE_CONSUMED = "CONSUMED"


class DurablePrivateCiAuthorityError(RuntimeError):
    """Base error for fail-closed durable-authority failures."""


class DurablePrivateCiAuthoritySchemaError(DurablePrivateCiAuthorityError):
    """Raised when the database schema is absent, incompatible, or malformed."""


class DurablePrivateCiAuthorityStateError(DurablePrivateCiAuthorityError):
    """Raised when persisted authority state is invalid or cannot be trusted."""


@dataclass(frozen=True, slots=True)
class DurablePrivateCiBinding:
    repository: str
    pull_request_number: int
    expected_head_sha: str
    workflow_identity: str
    target_os: PrivateCiTargetOs
    runner_scope_repository: str
    runner_nonce: str
    runner_label: str
    environment_generation: str


@dataclass(frozen=True, slots=True)
class DurablePrivateCiReservation:
    """Opaque durable operation capability.

    The token is a random lookup capability only. Trusted repository/PR/SHA and
    lifecycle bindings remain authority-owned in SQLite and are never rebuilt
    from caller input.
    """

    token: str


class DurablePrivateCiAuthority:
    """Restart-safe SQLite authority for private-CI nonce and binding state.

    Each method opens its own SQLite connection. SQLite transactions therefore
    arbitrate independent authority instances and independent processes that
    share the same database file.
    """

    def __init__(self, database_path: Path | str) -> None:
        self._database_path = Path(database_path)
        if not self._database_path.parent.exists():
            raise DurablePrivateCiAuthoritySchemaError("authority database parent does not exist")
        self._initialize_or_validate_schema()

    def reserve(self, binding: DurablePrivateCiBinding) -> Optional[DurablePrivateCiReservation]:
        self._validate_binding(binding)
        token = secrets.token_hex(32)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_schema(connection)
            try:
                connection.execute(
                    """
                    INSERT INTO private_ci_authority (
                        token, repository, pull_request_number, expected_head_sha,
                        workflow_identity, target_os, runner_scope_repository,
                        runner_nonce, runner_label, environment_generation, state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        token,
                        binding.repository,
                        binding.pull_request_number,
                        binding.expected_head_sha,
                        binding.workflow_identity,
                        binding.target_os.value,
                        binding.runner_scope_repository,
                        binding.runner_nonce,
                        binding.runner_label,
                        binding.environment_generation,
                        _STATE_RESERVED,
                    ),
                )
            except sqlite3.IntegrityError:
                connection.rollback()
                return None
            connection.commit()
            return DurablePrivateCiReservation(token=token)
        except DurablePrivateCiAuthorityError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise DurablePrivateCiAuthorityStateError("authority reservation failed closed") from exc
        finally:
            connection.close()

    def binding_for(self, reservation: DurablePrivateCiReservation) -> Optional[DurablePrivateCiBinding]:
        token = self._validated_token(reservation)
        connection = self._connect()
        try:
            self._validate_schema(connection)
            row = connection.execute(
                """
                SELECT repository, pull_request_number, expected_head_sha,
                       workflow_identity, target_os, runner_scope_repository,
                       runner_nonce, runner_label, environment_generation, state
                  FROM private_ci_authority
                 WHERE token = ?
                """,
                (token,),
            ).fetchone()
            if row is None:
                return None
            binding, state = self._binding_from_row(row)
            return binding if state == _STATE_RESERVED else None
        except DurablePrivateCiAuthorityError:
            raise
        except sqlite3.DatabaseError as exc:
            raise DurablePrivateCiAuthorityStateError("authority lookup failed closed") from exc
        finally:
            connection.close()

    def consume(self, reservation: DurablePrivateCiReservation, expected_binding: DurablePrivateCiBinding) -> bool:
        token = self._validated_token(reservation)
        self._validate_binding(expected_binding)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_schema(connection)
            row = connection.execute(
                """
                SELECT repository, pull_request_number, expected_head_sha,
                       workflow_identity, target_os, runner_scope_repository,
                       runner_nonce, runner_label, environment_generation, state
                  FROM private_ci_authority
                 WHERE token = ?
                """,
                (token,),
            ).fetchone()
            if row is None:
                connection.rollback()
                return False
            binding, state = self._binding_from_row(row)
            if state != _STATE_RESERVED or binding != expected_binding:
                connection.rollback()
                return False
            cursor = connection.execute(
                "UPDATE private_ci_authority SET state = ? WHERE token = ? AND state = ?",
                (_STATE_CONSUMED, token, _STATE_RESERVED),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                return False
            connection.commit()
            return True
        except DurablePrivateCiAuthorityError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise DurablePrivateCiAuthorityStateError("authority consume failed closed") from exc
        finally:
            connection.close()

    def is_nonce_used(self, nonce: str) -> bool:
        self._validate_nonce(nonce)
        connection = self._connect()
        try:
            self._validate_schema(connection)
            return connection.execute(
                "SELECT 1 FROM private_ci_authority WHERE runner_nonce = ? LIMIT 1",
                (nonce,),
            ).fetchone() is not None
        except DurablePrivateCiAuthorityError:
            raise
        except sqlite3.DatabaseError as exc:
            raise DurablePrivateCiAuthorityStateError("authority nonce lookup failed closed") from exc
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(str(self._database_path), timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            return connection
        except sqlite3.DatabaseError as exc:
            raise DurablePrivateCiAuthorityStateError("authority database open failed closed") from exc

    def _initialize_or_validate_schema(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS authority_meta (schema_version INTEGER NOT NULL)")
            meta_count = connection.execute("SELECT COUNT(*) FROM authority_meta").fetchone()[0]
            if meta_count == 0:
                connection.execute("INSERT INTO authority_meta(schema_version) VALUES (?)", (_SCHEMA_VERSION,))
            elif meta_count != 1:
                raise DurablePrivateCiAuthoritySchemaError("authority schema metadata is ambiguous")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS private_ci_authority (
                    token TEXT PRIMARY KEY NOT NULL,
                    repository TEXT NOT NULL,
                    pull_request_number INTEGER NOT NULL,
                    expected_head_sha TEXT NOT NULL,
                    workflow_identity TEXT NOT NULL,
                    target_os TEXT NOT NULL,
                    runner_scope_repository TEXT NOT NULL,
                    runner_nonce TEXT NOT NULL UNIQUE,
                    runner_label TEXT NOT NULL,
                    environment_generation TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('RESERVED', 'CONSUMED'))
                )
                """
            )
            self._validate_schema(connection)
            connection.commit()
        except DurablePrivateCiAuthorityError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise DurablePrivateCiAuthoritySchemaError("authority schema initialization failed closed") from exc
        finally:
            connection.close()

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        try:
            rows = connection.execute("SELECT schema_version FROM authority_meta").fetchall()
        except sqlite3.DatabaseError as exc:
            raise DurablePrivateCiAuthoritySchemaError("authority schema metadata is missing") from exc
        if rows != [(_SCHEMA_VERSION,)]:
            raise DurablePrivateCiAuthoritySchemaError("authority schema version is incompatible")

        expected_columns = (
            ("token", "TEXT", 1, 1),
            ("repository", "TEXT", 1, 0),
            ("pull_request_number", "INTEGER", 1, 0),
            ("expected_head_sha", "TEXT", 1, 0),
            ("workflow_identity", "TEXT", 1, 0),
            ("target_os", "TEXT", 1, 0),
            ("runner_scope_repository", "TEXT", 1, 0),
            ("runner_nonce", "TEXT", 1, 0),
            ("runner_label", "TEXT", 1, 0),
            ("environment_generation", "TEXT", 1, 0),
            ("state", "TEXT", 1, 0),
        )
        table_info = connection.execute("PRAGMA table_info(private_ci_authority)").fetchall()
        observed_columns = tuple((row[1], row[2].upper(), row[3], row[5]) for row in table_info)
        if observed_columns != expected_columns:
            raise DurablePrivateCiAuthoritySchemaError("authority table shape is incompatible")

        unique_column_sets = set()
        for index_row in connection.execute("PRAGMA index_list(private_ci_authority)").fetchall():
            if index_row[2] != 1:
                continue
            index_name = index_row[1]
            columns = tuple(
                row[2]
                for row in connection.execute(f"PRAGMA index_info('{index_name}')").fetchall()
            )
            unique_column_sets.add(columns)
        if ("runner_nonce",) not in unique_column_sets:
            raise DurablePrivateCiAuthoritySchemaError("authority nonce uniqueness constraint is missing")

    @staticmethod
    def _validated_token(reservation: DurablePrivateCiReservation) -> str:
        if type(reservation) is not DurablePrivateCiReservation:
            raise DurablePrivateCiAuthorityStateError("reservation token type is invalid")
        if type(reservation.token) is not str or len(reservation.token) != 64:
            raise DurablePrivateCiAuthorityStateError("reservation token is invalid")
        if any(character not in "0123456789abcdef" for character in reservation.token):
            raise DurablePrivateCiAuthorityStateError("reservation token is invalid")
        return reservation.token

    @staticmethod
    def _validate_nonce(nonce: object) -> None:
        if (
            type(nonce) is not str
            or not (1 <= len(nonce) <= 64)
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in nonce)
        ):
            raise DurablePrivateCiAuthorityStateError("nonce is invalid")

    @classmethod
    def _validate_binding(cls, binding: DurablePrivateCiBinding) -> None:
        if type(binding) is not DurablePrivateCiBinding:
            raise DurablePrivateCiAuthorityStateError("binding type is invalid")
        string_fields = (
            binding.repository,
            binding.expected_head_sha,
            binding.workflow_identity,
            binding.runner_scope_repository,
            binding.runner_label,
            binding.environment_generation,
        )
        if any(type(value) is not str or not value.strip() for value in string_fields):
            raise DurablePrivateCiAuthorityStateError("binding contains invalid strings")
        if type(binding.pull_request_number) is not int or binding.pull_request_number <= 0:
            raise DurablePrivateCiAuthorityStateError("binding pull request number is invalid")
        if len(binding.expected_head_sha) != 40 or any(
            character not in "0123456789abcdef" for character in binding.expected_head_sha
        ):
            raise DurablePrivateCiAuthorityStateError("binding head SHA is invalid")
        if type(binding.target_os) is not PrivateCiTargetOs:
            raise DurablePrivateCiAuthorityStateError("binding target OS is invalid")
        cls._validate_nonce(binding.runner_nonce)
        if binding.runner_scope_repository != binding.repository:
            raise DurablePrivateCiAuthorityStateError("binding runner scope does not match repository")
        if binding.runner_label != f"ac-private-ci-{binding.runner_nonce}":
            raise DurablePrivateCiAuthorityStateError("binding runner label is not canonical")

    @classmethod
    def _binding_from_row(cls, row: tuple[object, ...]) -> tuple[DurablePrivateCiBinding, str]:
        if len(row) != 10:
            raise DurablePrivateCiAuthorityStateError("authority row shape is invalid")
        target_os_raw = row[4]
        state = row[9]
        if type(target_os_raw) is not str or type(state) is not str:
            raise DurablePrivateCiAuthorityStateError("authority row type is invalid")
        try:
            target_os = PrivateCiTargetOs(target_os_raw)
        except ValueError as exc:
            raise DurablePrivateCiAuthorityStateError("authority target OS is invalid") from exc
        if state not in (_STATE_RESERVED, _STATE_CONSUMED):
            raise DurablePrivateCiAuthorityStateError("authority lifecycle state is invalid")
        binding = DurablePrivateCiBinding(
            repository=row[0],
            pull_request_number=row[1],
            expected_head_sha=row[2],
            workflow_identity=row[3],
            target_os=target_os,
            runner_scope_repository=row[5],
            runner_nonce=row[6],
            runner_label=row[7],
            environment_generation=row[8],
        )
        cls._validate_binding(binding)
        return binding, state
