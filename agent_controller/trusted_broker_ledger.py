from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from agent_controller.signed_approval import (
    ApprovalChallenge,
    ProvenanceAssurance,
    canonicalize_approval_challenge,
    verify_signed_approval,
)


LEDGER_SCHEMA_VERSION = "agent-controller-trusted-broker-ledger-v1"


class BrokerAttemptState(str, Enum):
    CLAIMED = "CLAIMED"
    EFFECT_VERIFIED = "EFFECT_VERIFIED"
    FAILED_AFTER_CLAIM = "FAILED_AFTER_CLAIM"


class BrokerLedgerDecision(str, Enum):
    PASS = "PASS"
    REPLAYED = "REPLAYED"
    BLOCKED = "BLOCKED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class BrokerAttemptRecord:
    authorization_digest: str
    challenge_schema_version: str
    approval_id: str
    approval_policy_id: str
    controller_task_id: str
    operation_id: str
    operation_version: str
    provider: str
    requested_capability: str
    effect: str
    repo: str
    target_kind: str
    target_id: str
    expected_head_sha: str
    challenge_nonce: str
    signer_key_id: str
    signature_digest: str
    attempt_id: str
    state: BrokerAttemptState
    failure_code: Optional[str] = None


@dataclass(frozen=True)
class BrokerLedgerResult:
    decision: BrokerLedgerDecision
    record: Optional[BrokerAttemptRecord] = None
    reason: Optional[str] = None


_EXPECTED_COLUMNS = (
    ("authorization_digest", "TEXT", 1, 1),
    ("challenge_schema_version", "TEXT", 1, 0),
    ("approval_id", "TEXT", 1, 0),
    ("approval_policy_id", "TEXT", 1, 0),
    ("controller_task_id", "TEXT", 1, 0),
    ("operation_id", "TEXT", 1, 0),
    ("operation_version", "TEXT", 1, 0),
    ("provider", "TEXT", 1, 0),
    ("requested_capability", "TEXT", 1, 0),
    ("effect", "TEXT", 1, 0),
    ("repo", "TEXT", 1, 0),
    ("target_kind", "TEXT", 1, 0),
    ("target_id", "TEXT", 1, 0),
    ("expected_head_sha", "TEXT", 1, 0),
    ("challenge_nonce", "TEXT", 1, 0),
    ("signer_key_id", "TEXT", 1, 0),
    ("signature_digest", "TEXT", 1, 0),
    ("attempt_id", "TEXT", 1, 0),
    ("state", "TEXT", 1, 0),
    ("failure_code", "TEXT", 0, 0),
)


class TrustedBrokerAttemptLedger:
    """Broker-local at-most-once ledger.

    This class only becomes a security authority when its database and code run
    under the separately reviewed trusted broker OS/service identity. It does
    not itself create that OS isolation boundary.
    """

    __slots__ = ("_db_path", "_timeout_seconds")

    def __init__(self, *, db_path: str | Path, timeout_seconds: float = 5.0) -> None:
        path = Path(db_path)
        if str(path) in {"", "."}:
            raise ValueError("db_path must identify a database file")
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must be non-negative")
        self._db_path = str(path)
        self._timeout_seconds = float(timeout_seconds)
        self._initialize()

    @property
    def db_path(self) -> str:
        return self._db_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS broker_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) STRICT
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS effect_attempts (
                    authorization_digest TEXT PRIMARY KEY NOT NULL
                        CHECK(length(authorization_digest) = 64),
                    challenge_schema_version TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    approval_policy_id TEXT NOT NULL,
                    controller_task_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    operation_version TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    requested_capability TEXT NOT NULL,
                    effect TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    expected_head_sha TEXT NOT NULL,
                    challenge_nonce TEXT NOT NULL,
                    signer_key_id TEXT NOT NULL,
                    signature_digest TEXT NOT NULL
                        CHECK(length(signature_digest) = 64),
                    attempt_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL
                        CHECK(state IN ('CLAIMED','EFFECT_VERIFIED','FAILED_AFTER_CLAIM')),
                    failure_code TEXT
                ) STRICT
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO broker_meta(key, value) VALUES('schema_version', ?)",
                (LEDGER_SCHEMA_VERSION,),
            )
            row = connection.execute(
                "SELECT value FROM broker_meta WHERE key='schema_version'"
            ).fetchone()
            if row != (LEDGER_SCHEMA_VERSION,):
                raise RuntimeError("BROKER_LEDGER_SCHEMA_VERSION_MISMATCH")
            self._validate_schema(connection)
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA table_info(effect_attempts)").fetchall()
        observed = tuple((row[1], row[2], row[3], row[5]) for row in rows)
        if observed != _EXPECTED_COLUMNS:
            raise RuntimeError("BROKER_LEDGER_SCHEMA_INVALID")
        indexes = connection.execute("PRAGMA index_list(effect_attempts)").fetchall()
        unique_attempt = False
        for index in indexes:
            if not index[2]:
                continue
            columns = connection.execute(
                f"PRAGMA index_info('{index[1]}')"
            ).fetchall()
            if tuple(row[2] for row in columns) == ("attempt_id",):
                unique_attempt = True
                break
        if not unique_attempt:
            raise RuntimeError("BROKER_LEDGER_ATTEMPT_UNIQUENESS_MISSING")

    def integrity_check(self) -> BrokerLedgerResult:
        try:
            connection = self._connect()
            try:
                row = connection.execute("PRAGMA integrity_check").fetchone()
                self._validate_schema(connection)
                version = connection.execute(
                    "SELECT value FROM broker_meta WHERE key='schema_version'"
                ).fetchone()
            finally:
                connection.close()
        except Exception:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="BROKER_LEDGER_INTEGRITY_UNCERTAIN"
            )
        if row != ("ok",) or version != (LEDGER_SCHEMA_VERSION,):
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="BROKER_LEDGER_INTEGRITY_FAILED"
            )
        return BrokerLedgerResult(BrokerLedgerDecision.PASS, reason="BROKER_LEDGER_OK")

    @staticmethod
    def _authorization_evidence(
        challenge: ApprovalChallenge, signature_b64: str
    ) -> tuple[str, str]:
        verification = verify_signed_approval(
            challenge=challenge, signature_b64=signature_b64
        )
        if (
            not verification.valid
            or verification.assurance is not ProvenanceAssurance.VERIFIED_EVENT_PROVENANCE
            or verification.signer_key_id != challenge.signer_key_id
        ):
            raise ValueError(verification.reason or "SIGNATURE_NOT_VERIFIED")
        canonical = canonicalize_approval_challenge(challenge)
        signature_bytes = base64.b64decode(signature_b64, validate=True)
        return hashlib.sha256(canonical).hexdigest(), hashlib.sha256(signature_bytes).hexdigest()

    @staticmethod
    def _audit_tuple(
        challenge: ApprovalChallenge,
        authorization_digest: str,
        signature_digest: str,
    ) -> tuple[str, ...]:
        return (
            authorization_digest,
            challenge.schema_version,
            challenge.approval_id,
            challenge.approval_policy_id,
            challenge.controller_task_id,
            challenge.operation_id,
            challenge.operation_version,
            challenge.provider,
            challenge.requested_capability,
            challenge.effect,
            challenge.repo,
            challenge.target_kind,
            challenge.target_id,
            challenge.expected_head_sha,
            challenge.challenge_nonce,
            challenge.signer_key_id,
            signature_digest,
        )

    @staticmethod
    def _row_to_record(row: tuple[object, ...]) -> BrokerAttemptRecord:
        if len(row) != 20:
            raise ValueError("BROKER_LEDGER_ROW_INVALID")
        try:
            state = BrokerAttemptState(row[18])
        except (TypeError, ValueError) as exc:
            raise ValueError("BROKER_LEDGER_STATE_INVALID") from exc
        required = row[:19]
        if any(not isinstance(value, str) or not value for value in required):
            raise ValueError("BROKER_LEDGER_ROW_FIELD_INVALID")
        if row[19] is not None and (not isinstance(row[19], str) or not row[19]):
            raise ValueError("BROKER_LEDGER_FAILURE_CODE_INVALID")
        return BrokerAttemptRecord(*row[:18], state, row[19])

    def _read_connection(
        self, connection: sqlite3.Connection, authorization_digest: str
    ) -> Optional[BrokerAttemptRecord]:
        row = connection.execute(
            "SELECT authorization_digest, challenge_schema_version, approval_id, "
            "approval_policy_id, controller_task_id, operation_id, operation_version, "
            "provider, requested_capability, effect, repo, target_kind, target_id, "
            "expected_head_sha, challenge_nonce, signer_key_id, signature_digest, "
            "attempt_id, state, failure_code FROM effect_attempts "
            "WHERE authorization_digest=?",
            (authorization_digest,),
        ).fetchone()
        return None if row is None else self._row_to_record(row)

    def read_attempt(self, *, authorization_digest: str) -> BrokerLedgerResult:
        if not isinstance(authorization_digest, str) or len(authorization_digest) != 64:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="AUTHORIZATION_DIGEST_INVALID"
            )
        try:
            connection = self._connect()
            try:
                record = self._read_connection(connection, authorization_digest)
            finally:
                connection.close()
        except Exception:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="BROKER_LEDGER_READ_FAILED"
            )
        if record is None:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="BROKER_ATTEMPT_MISSING"
            )
        return BrokerLedgerResult(BrokerLedgerDecision.PASS, record)

    def claim_effect_attempt(
        self, *, challenge: ApprovalChallenge, signature_b64: str
    ) -> BrokerLedgerResult:
        if not isinstance(challenge, ApprovalChallenge):
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="CHALLENGE_INPUT_INVALID"
            )
        if not isinstance(signature_b64, str) or not signature_b64:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="SIGNATURE_INPUT_INVALID"
            )
        try:
            authorization_digest, signature_digest = self._authorization_evidence(
                challenge, signature_b64
            )
        except Exception as exc:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason=str(exc) or "SIGNATURE_NOT_VERIFIED"
            )
        audit = self._audit_tuple(challenge, authorization_digest, signature_digest)
        attempt_id = "attempt_" + secrets.token_urlsafe(24)

        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._read_connection(connection, authorization_digest)
                if existing is not None:
                    if self._record_matches_audit(existing, audit):
                        connection.execute("ROLLBACK")
                        return BrokerLedgerResult(
                            BrokerLedgerDecision.REPLAYED,
                            existing,
                            "AUTHORIZATION_ALREADY_CONSUMED",
                        )
                    connection.execute("ROLLBACK")
                    return BrokerLedgerResult(
                        BrokerLedgerDecision.BLOCKED,
                        existing,
                        "AUTHORIZATION_DIGEST_BINDING_CONFLICT",
                    )
                try:
                    connection.execute(
                        "INSERT INTO effect_attempts VALUES "
                        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                        (*audit, attempt_id, BrokerAttemptState.CLAIMED.value),
                    )
                except sqlite3.IntegrityError:
                    connection.execute("ROLLBACK")
                    return BrokerLedgerResult(
                        BrokerLedgerDecision.BLOCKED,
                        reason="BROKER_LEDGER_UNIQUENESS_CONFLICT",
                    )
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                connection.close()
        except sqlite3.Error:
            reread = self.read_attempt(authorization_digest=authorization_digest)
            if (
                reread.decision is BrokerLedgerDecision.PASS
                and reread.record is not None
                and reread.record.attempt_id == attempt_id
                and self._record_matches_audit(reread.record, audit)
            ):
                return BrokerLedgerResult(
                    BrokerLedgerDecision.PASS,
                    reread.record,
                    "CLAIM_CONFIRMED_AFTER_PERSISTENCE_UNCERTAINTY",
                )
            return BrokerLedgerResult(
                BrokerLedgerDecision.UNCERTAIN, reason="BROKER_LEDGER_CLAIM_UNCERTAIN"
            )

        reread = self.read_attempt(authorization_digest=authorization_digest)
        if (
            reread.decision is not BrokerLedgerDecision.PASS
            or reread.record is None
            or reread.record.attempt_id != attempt_id
            or not self._record_matches_audit(reread.record, audit)
            or reread.record.state is not BrokerAttemptState.CLAIMED
        ):
            return BrokerLedgerResult(
                BrokerLedgerDecision.UNCERTAIN,
                reread.record,
                "BROKER_LEDGER_POSTCLAIM_VERIFY_FAILED",
            )
        return BrokerLedgerResult(BrokerLedgerDecision.PASS, reread.record)

    @staticmethod
    def _record_matches_audit(
        record: BrokerAttemptRecord, audit: tuple[str, ...]
    ) -> bool:
        return (
            record.authorization_digest,
            record.challenge_schema_version,
            record.approval_id,
            record.approval_policy_id,
            record.controller_task_id,
            record.operation_id,
            record.operation_version,
            record.provider,
            record.requested_capability,
            record.effect,
            record.repo,
            record.target_kind,
            record.target_id,
            record.expected_head_sha,
            record.challenge_nonce,
            record.signer_key_id,
            record.signature_digest,
        ) == audit

    def mark_effect_verified(
        self, *, authorization_digest: str, attempt_id: str
    ) -> BrokerLedgerResult:
        return self._mark_terminal(
            authorization_digest=authorization_digest,
            attempt_id=attempt_id,
            terminal=BrokerAttemptState.EFFECT_VERIFIED,
            failure_code=None,
        )

    def mark_failed_after_claim(
        self, *, authorization_digest: str, attempt_id: str, failure_code: str
    ) -> BrokerLedgerResult:
        if not isinstance(failure_code, str) or not failure_code:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED, reason="FAILURE_CODE_INVALID"
            )
        return self._mark_terminal(
            authorization_digest=authorization_digest,
            attempt_id=attempt_id,
            terminal=BrokerAttemptState.FAILED_AFTER_CLAIM,
            failure_code=failure_code,
        )

    def _mark_terminal(
        self,
        *,
        authorization_digest: str,
        attempt_id: str,
        terminal: BrokerAttemptState,
        failure_code: Optional[str],
    ) -> BrokerLedgerResult:
        if not isinstance(authorization_digest, str) or len(authorization_digest) != 64:
            return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason="AUTHORIZATION_DIGEST_INVALID")
        if not isinstance(attempt_id, str) or not attempt_id:
            return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason="ATTEMPT_ID_INVALID")
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = self._read_connection(connection, authorization_digest)
                if current is None:
                    connection.execute("ROLLBACK")
                    return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason="BROKER_ATTEMPT_MISSING")
                if current.attempt_id != attempt_id:
                    connection.execute("ROLLBACK")
                    return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, current, "ATTEMPT_ID_MISMATCH")
                if current.state is terminal:
                    expected_failure = failure_code if terminal is BrokerAttemptState.FAILED_AFTER_CLAIM else None
                    connection.execute("ROLLBACK")
                    if current.failure_code == expected_failure:
                        return BrokerLedgerResult(BrokerLedgerDecision.REPLAYED, current, "TERMINAL_STATE_ALREADY_RECORDED")
                    return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, current, "TERMINAL_STATE_CONFLICT")
                if current.state is not BrokerAttemptState.CLAIMED:
                    connection.execute("ROLLBACK")
                    return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, current, "TERMINAL_STATE_IMMUTABLE")
                connection.execute(
                    "UPDATE effect_attempts SET state=?, failure_code=? "
                    "WHERE authorization_digest=? AND attempt_id=? AND state='CLAIMED'",
                    (terminal.value, failure_code, authorization_digest, attempt_id),
                )
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                connection.close()
        except sqlite3.Error:
            return BrokerLedgerResult(BrokerLedgerDecision.UNCERTAIN, reason="BROKER_LEDGER_TERMINAL_WRITE_UNCERTAIN")
        reread = self.read_attempt(authorization_digest=authorization_digest)
        if (
            reread.decision is BrokerLedgerDecision.PASS
            and reread.record is not None
            and reread.record.attempt_id == attempt_id
            and reread.record.state is terminal
            and reread.record.failure_code == failure_code
        ):
            return BrokerLedgerResult(BrokerLedgerDecision.PASS, reread.record)
        return BrokerLedgerResult(
            BrokerLedgerDecision.UNCERTAIN,
            reread.record,
            "BROKER_LEDGER_TERMINAL_VERIFY_FAILED",
        )
