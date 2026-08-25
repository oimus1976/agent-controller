from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agent_controller.broker_epoch import EpochBoundApprovalGate
from agent_controller.signed_approval import (
    ApprovalChallengeV3,
    ProvenanceAssurance,
    SCHEMA_VERSION_V3,
    canonicalize_approval_challenge,
    verify_signed_approval,
)
from agent_controller.trusted_broker_ledger import (
    BrokerAttemptState,
    BrokerLedgerCorruptError,
    BrokerLedgerDecision,
    BrokerLedgerResult,
)


LEDGER_SCHEMA_VERSION_V2 = "agent-controller-trusted-broker-ledger-v2"


@dataclass(frozen=True)
class EpochBoundBrokerAttemptRecord:
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
    broker_authority_id: str
    broker_epoch: str
    signature_digest: str
    signature_b64: str
    attempt_id: str
    state: BrokerAttemptState
    failure_code: Optional[str] = None


def _is_lower_hex_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _valid_attempt_id(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("attempt_"):
        return False
    suffix = value[len("attempt_") :]
    return bool(suffix) and len(suffix) <= 128 and all(
        char.isalnum() or char in "_-" for char in suffix
    )


_EXPECTED_META_COLUMNS = (
    ("key", "TEXT", 1, 1),
    ("value", "TEXT", 1, 0),
)
_EXPECTED_ATTEMPT_COLUMNS = (
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
    ("broker_authority_id", "TEXT", 1, 0),
    ("broker_epoch", "TEXT", 1, 0),
    ("signature_digest", "TEXT", 1, 0),
    ("signature_b64", "TEXT", 1, 0),
    ("attempt_id", "TEXT", 1, 0),
    ("state", "TEXT", 1, 0),
    ("failure_code", "TEXT", 0, 0),
)


class EpochBoundTrustedBrokerLedger:
    """V3-only broker-local anti-replay ledger.

    Existing v1 databases are rejected rather than migrated. Every stored row
    carries the public signature evidence needed to independently re-verify the
    reconstructed human approval; no private signing material is stored.
    """

    __slots__ = ("_db_path", "_timeout_seconds", "_gate")

    def __init__(
        self,
        *,
        db_path: str | Path,
        gate: EpochBoundApprovalGate,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not isinstance(gate, EpochBoundApprovalGate):
            raise TypeError("gate must be EpochBoundApprovalGate")
        path = Path(db_path)
        if str(path) in {"", "."}:
            raise ValueError("db_path must identify a database file")
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must be non-negative")
        existed = path.exists()
        self._db_path = str(path)
        self._timeout_seconds = float(timeout_seconds)
        self._gate = gate
        self._initialize(create_new=not existed)

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

    def _initialize(self, *, create_new: bool) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if create_new:
                connection.execute(
                    "CREATE TABLE broker_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL) STRICT"
                )
                connection.execute(
                    """
                    CREATE TABLE effect_attempts (
                        authorization_digest TEXT PRIMARY KEY NOT NULL CHECK(length(authorization_digest)=64),
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
                        broker_authority_id TEXT NOT NULL,
                        broker_epoch TEXT NOT NULL,
                        signature_digest TEXT NOT NULL CHECK(length(signature_digest)=64),
                        signature_b64 TEXT NOT NULL,
                        attempt_id TEXT NOT NULL UNIQUE,
                        state TEXT NOT NULL CHECK(state IN ('CLAIMED','EFFECT_VERIFIED','FAILED_AFTER_CLAIM')),
                        failure_code TEXT
                    ) STRICT
                    """
                )
                connection.execute(
                    "INSERT INTO broker_meta(key,value) VALUES('schema_version',?)",
                    (LEDGER_SCHEMA_VERSION_V2,),
                )
            self._validate_database(connection)
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
    def _table_shape(connection: sqlite3.Connection, table: str) -> tuple[tuple[object, ...], ...]:
        rows = connection.execute(f"PRAGMA table_info('{table}')").fetchall()
        return tuple((row[1], row[2], row[3], row[5]) for row in rows)

    @classmethod
    def _validate_database(cls, connection: sqlite3.Connection) -> None:
        if cls._table_shape(connection, "broker_meta") != _EXPECTED_META_COLUMNS:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_META_SCHEMA_INVALID")
        if cls._table_shape(connection, "effect_attempts") != _EXPECTED_ATTEMPT_COLUMNS:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_ATTEMPT_SCHEMA_INVALID")
        rows = connection.execute(
            "SELECT value FROM broker_meta WHERE key='schema_version'"
        ).fetchall()
        if rows != [(LEDGER_SCHEMA_VERSION_V2,)]:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_SCHEMA_VERSION_MISMATCH")

    @staticmethod
    def _audit_tuple(
        challenge: ApprovalChallengeV3,
        authorization_digest: str,
        signature_digest: str,
        signature_b64: str,
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
            challenge.broker_authority_id,
            challenge.broker_epoch,
            signature_digest,
            signature_b64,
        )

    @staticmethod
    def _row_to_record(row: tuple[object, ...]) -> EpochBoundBrokerAttemptRecord:
        if len(row) != 23:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_ROW_INVALID")
        if any(not isinstance(value, str) or not value for value in row[:22]):
            raise BrokerLedgerCorruptError("BROKER_LEDGER_ROW_FIELD_INVALID")
        if not _is_lower_hex_digest(row[0]) or not _is_lower_hex_digest(row[18]):
            raise BrokerLedgerCorruptError("BROKER_LEDGER_DIGEST_INVALID")
        if row[1] != SCHEMA_VERSION_V3:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_CHALLENGE_SCHEMA_INVALID")
        if not _valid_attempt_id(row[20]):
            raise BrokerLedgerCorruptError("BROKER_LEDGER_ATTEMPT_ID_INVALID")
        try:
            state = BrokerAttemptState(row[21])
        except (TypeError, ValueError) as exc:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_STATE_INVALID") from exc
        failure_code = row[22]
        if state in {BrokerAttemptState.CLAIMED, BrokerAttemptState.EFFECT_VERIFIED}:
            if failure_code is not None:
                raise BrokerLedgerCorruptError("BROKER_LEDGER_FAILURE_STATE_INVALID")
        elif not isinstance(failure_code, str) or not failure_code:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_FAILURE_STATE_INVALID")

        reconstructed = ApprovalChallengeV3(
            approval_id=row[2],
            approval_policy_id=row[3],
            controller_task_id=row[4],
            operation_id=row[5],
            operation_version=row[6],
            provider=row[7],
            requested_capability=row[8],
            effect=row[9],
            repo=row[10],
            target_kind=row[11],
            target_id=row[12],
            expected_head_sha=row[13],
            challenge_nonce=row[14],
            signer_key_id=row[15],
            broker_authority_id=row[16],
            broker_epoch=row[17],
            schema_version=row[1],
        )
        digest = hashlib.sha256(canonicalize_approval_challenge(reconstructed)).hexdigest()
        if digest != row[0]:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_AUTHORIZATION_BINDING_INVALID")
        try:
            signature_bytes = base64.b64decode(row[19], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_SIGNATURE_ENCODING_INVALID") from exc
        if hashlib.sha256(signature_bytes).hexdigest() != row[18]:
            raise BrokerLedgerCorruptError("BROKER_LEDGER_SIGNATURE_DIGEST_INVALID")
        verification = verify_signed_approval(
            challenge=reconstructed,
            signature_b64=row[19],
        )
        if (
            not verification.valid
            or verification.assurance is not ProvenanceAssurance.VERIFIED_EVENT_PROVENANCE
            or verification.signer_key_id != reconstructed.signer_key_id
        ):
            raise BrokerLedgerCorruptError("BROKER_LEDGER_SIGNATURE_INVALID")
        return EpochBoundBrokerAttemptRecord(*row[:21], state, failure_code)

    @classmethod
    def _read_connection(
        cls, connection: sqlite3.Connection, authorization_digest: str
    ) -> Optional[EpochBoundBrokerAttemptRecord]:
        row = connection.execute(
            "SELECT authorization_digest, challenge_schema_version, approval_id, approval_policy_id, "
            "controller_task_id, operation_id, operation_version, provider, requested_capability, "
            "effect, repo, target_kind, target_id, expected_head_sha, challenge_nonce, signer_key_id, "
            "broker_authority_id, broker_epoch, signature_digest, signature_b64, attempt_id, state, failure_code "
            "FROM effect_attempts WHERE authorization_digest=?",
            (authorization_digest,),
        ).fetchone()
        return None if row is None else cls._row_to_record(row)

    def read_attempt(self, *, authorization_digest: str) -> BrokerLedgerResult:
        if not _is_lower_hex_digest(authorization_digest):
            return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason="AUTHORIZATION_DIGEST_INVALID")
        try:
            connection = self._connect()
            try:
                self._validate_database(connection)
                record = self._read_connection(connection, authorization_digest)
            finally:
                connection.close()
        except BrokerLedgerCorruptError as exc:
            return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason=str(exc))
        except sqlite3.Error:
            return BrokerLedgerResult(BrokerLedgerDecision.UNCERTAIN, reason="BROKER_LEDGER_READ_UNCERTAIN")
        if record is None:
            return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason="BROKER_ATTEMPT_MISSING")
        return BrokerLedgerResult(BrokerLedgerDecision.PASS, record)  # type: ignore[arg-type]

    def claim_effect_attempt(
        self, *, challenge: ApprovalChallengeV3, signature_b64: str
    ) -> BrokerLedgerResult:
        validation = self._gate.validate_for_claim(
            challenge=challenge,
            signature_b64=signature_b64,
        )
        if not validation.valid or validation.authorization_digest is None:
            return BrokerLedgerResult(
                BrokerLedgerDecision.BLOCKED,
                reason=validation.reason or "EPOCH_BOUND_APPROVAL_INVALID",
            )
        try:
            signature_bytes = base64.b64decode(signature_b64, validate=True)
        except (binascii.Error, ValueError):
            return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason="SIGNATURE_ENCODING_INVALID")
        authorization_digest = validation.authorization_digest
        signature_digest = hashlib.sha256(signature_bytes).hexdigest()
        audit = self._audit_tuple(
            challenge,
            authorization_digest,
            signature_digest,
            signature_b64,
        )
        attempt_id = "attempt_" + secrets.token_urlsafe(24)

        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_database(connection)
                existing = self._read_connection(connection, authorization_digest)
                if existing is not None:
                    connection.execute("ROLLBACK")
                    if self._record_matches_audit(existing, audit):
                        return BrokerLedgerResult(
                            BrokerLedgerDecision.REPLAYED,
                            existing,  # type: ignore[arg-type]
                            "AUTHORIZATION_ALREADY_CONSUMED",
                        )
                    return BrokerLedgerResult(
                        BrokerLedgerDecision.BLOCKED,
                        existing,  # type: ignore[arg-type]
                        "AUTHORIZATION_DIGEST_BINDING_CONFLICT",
                    )
                connection.execute(
                    "INSERT INTO effect_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (*audit, attempt_id, BrokerAttemptState.CLAIMED.value),
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason="BROKER_LEDGER_UNIQUENESS_CONFLICT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                connection.close()
        except BrokerLedgerCorruptError as exc:
            return BrokerLedgerResult(BrokerLedgerDecision.BLOCKED, reason=str(exc))
        except sqlite3.Error:
            reread = self.read_attempt(authorization_digest=authorization_digest)
            if (
                reread.decision is BrokerLedgerDecision.PASS
                and reread.record is not None
                and getattr(reread.record, "attempt_id", None) == attempt_id
                and self._record_matches_audit(reread.record, audit)  # type: ignore[arg-type]
            ):
                return reread
            return BrokerLedgerResult(BrokerLedgerDecision.UNCERTAIN, reason="BROKER_LEDGER_CLAIM_UNCERTAIN")

        reread = self.read_attempt(authorization_digest=authorization_digest)
        if (
            reread.decision is not BrokerLedgerDecision.PASS
            or reread.record is None
            or getattr(reread.record, "attempt_id", None) != attempt_id
            or not self._record_matches_audit(reread.record, audit)  # type: ignore[arg-type]
            or getattr(reread.record, "state", None) is not BrokerAttemptState.CLAIMED
        ):
            return BrokerLedgerResult(
                BrokerLedgerDecision.UNCERTAIN,
                reason="BROKER_LEDGER_POSTCLAIM_VERIFY_FAILED",
            )
        return reread

    @staticmethod
    def _record_matches_audit(
        record: EpochBoundBrokerAttemptRecord,
        audit: tuple[str, ...],
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
            record.broker_authority_id,
            record.broker_epoch,
            record.signature_digest,
            record.signature_b64,
        ) == audit
