import multiprocessing
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_controller.private_ci_contract import PrivateCiTargetOs
from agent_controller.private_ci_durable_authority import (
    DurablePrivateCiAuthority,
    DurablePrivateCiAuthoritySchemaError,
    DurablePrivateCiAuthorityStateError,
    DurablePrivateCiBinding,
    DurablePrivateCiReservation,
)


REPOSITORY = "oimus1976/example-private"
HEAD = "1" * 40
NONCE = "nonce-209-alpha"
LABEL = f"ac-private-ci-{NONCE}"
WORKFLOW = "trusted-default-branch-private-ci-v1"
GENERATION = "generation-209-alpha"


def valid_binding(**overrides):
    values = {
        "repository": REPOSITORY,
        "pull_request_number": 17,
        "expected_head_sha": HEAD,
        "workflow_identity": WORKFLOW,
        "target_os": PrivateCiTargetOs.WINDOWS,
        "runner_scope_repository": REPOSITORY,
        "runner_nonce": NONCE,
        "runner_label": LABEL,
        "environment_generation": GENERATION,
    }
    values.update(overrides)
    return DurablePrivateCiBinding(**values)


def _reserve_in_process(database_path, start_event, output_queue):
    authority = DurablePrivateCiAuthority(database_path)
    start_event.wait(10)
    output_queue.put(authority.reserve(valid_binding()) is not None)


class DurablePrivateCiAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "authority.sqlite3"

    def tearDown(self):
        self.temp_dir.cleanup()

    def authority(self):
        return DurablePrivateCiAuthority(self.database_path)

    def test_reservation_survives_authority_reconstruction(self):
        first = self.authority()
        reservation = first.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        self.assertTrue(first.is_nonce_used(NONCE))

        reconstructed = self.authority()
        self.assertTrue(reconstructed.is_nonce_used(NONCE))
        self.assertEqual(reconstructed.binding_for(reservation), valid_binding())
        self.assertIsNone(reconstructed.reserve(valid_binding()))

    def test_two_independent_instances_racing_same_nonce_allow_exactly_one(self):
        self.authority()
        first = self.authority()
        second = self.authority()

        def attempt(authority):
            return authority.reserve(valid_binding()) is not None

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(attempt, (first, second)))
        self.assertEqual(sorted(outcomes), [False, True])

    def test_two_processes_racing_same_nonce_allow_exactly_one(self):
        self.authority()
        context = multiprocessing.get_context("spawn")
        start_event = context.Event()
        output_queue = context.Queue()
        processes = [
            context.Process(
                target=_reserve_in_process,
                args=(str(self.database_path), start_event, output_queue),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        start_event.set()
        outcomes = [output_queue.get(timeout=15) for _ in processes]
        for process in processes:
            process.join(15)
            self.assertEqual(process.exitcode, 0)
        output_queue.close()
        output_queue.join_thread()
        self.assertEqual(sorted(outcomes), [False, True])

    def test_consume_is_exactly_once_across_independent_instances(self):
        first = self.authority()
        reservation = first.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        second = self.authority()

        def consume(authority):
            return authority.consume(reservation, valid_binding())

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(consume, (first, second)))
        self.assertEqual(sorted(outcomes), [False, True])
        self.assertIsNone(self.authority().binding_for(reservation))
        self.assertTrue(self.authority().is_nonce_used(NONCE))

    def test_mismatched_binding_does_not_consume_reservation(self):
        authority = self.authority()
        reservation = authority.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        mismatch = valid_binding(
            repository="oimus1976/other-private",
            runner_scope_repository="oimus1976/other-private",
        )
        self.assertFalse(authority.consume(reservation, mismatch))
        self.assertEqual(authority.binding_for(reservation), valid_binding())
        self.assertTrue(authority.consume(reservation, valid_binding()))

    def test_stale_sha_mismatch_does_not_consume_reservation(self):
        authority = self.authority()
        reservation = authority.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        self.assertFalse(authority.consume(reservation, valid_binding(expected_head_sha="2" * 40)))
        self.assertEqual(authority.binding_for(reservation), valid_binding())

    def test_unknown_token_cannot_reconstruct_binding_from_caller_input(self):
        authority = self.authority()
        reservation = authority.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        forged = DurablePrivateCiReservation(token="0" * 64)
        self.assertIsNone(authority.binding_for(forged))
        self.assertFalse(authority.consume(forged, valid_binding()))
        self.assertEqual(authority.binding_for(reservation), valid_binding())

    def test_consumed_token_remains_consumed_after_restart(self):
        authority = self.authority()
        reservation = authority.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        self.assertTrue(authority.consume(reservation, valid_binding()))
        reconstructed = self.authority()
        self.assertIsNone(reconstructed.binding_for(reservation))
        self.assertFalse(reconstructed.consume(reservation, valid_binding()))
        self.assertIsNone(reconstructed.reserve(valid_binding()))

    def test_rejects_invalid_binding_before_persistence(self):
        authority = self.authority()
        with self.assertRaises(DurablePrivateCiAuthorityStateError):
            authority.reserve(valid_binding(expected_head_sha="short"))
        with self.assertRaises(DurablePrivateCiAuthorityStateError):
            authority.reserve(valid_binding(runner_scope_repository="oimus1976/other-private"))
        with self.assertRaises(DurablePrivateCiAuthorityStateError):
            authority.reserve(valid_binding(runner_label="not-canonical"))
        with self.assertRaises(DurablePrivateCiAuthorityStateError):
            authority.reserve(valid_binding(runner_nonce="UPPER", runner_label="ac-private-ci-UPPER"))
        self.assertFalse(authority.is_nonce_used(NONCE))

    def test_rejects_binding_and_reservation_subclasses(self):
        class BindingSubclass(DurablePrivateCiBinding):
            pass

        class ReservationSubclass(DurablePrivateCiReservation):
            pass

        authority = self.authority()
        base = valid_binding()
        with self.assertRaises(DurablePrivateCiAuthorityStateError):
            authority.reserve(BindingSubclass(
                repository=base.repository,
                pull_request_number=base.pull_request_number,
                expected_head_sha=base.expected_head_sha,
                workflow_identity=base.workflow_identity,
                target_os=base.target_os,
                runner_scope_repository=base.runner_scope_repository,
                runner_nonce=base.runner_nonce,
                runner_label=base.runner_label,
                environment_generation=base.environment_generation,
            ))
        with self.assertRaises(DurablePrivateCiAuthorityStateError):
            authority.binding_for(ReservationSubclass(token="0" * 64))

    def test_schema_version_mismatch_fails_closed(self):
        authority = self.authority()
        reservation = authority.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("UPDATE authority_meta SET schema_version = 999")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DurablePrivateCiAuthoritySchemaError):
            self.authority()

    def test_missing_nonce_unique_constraint_fails_closed(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("CREATE TABLE authority_meta (schema_version INTEGER NOT NULL)")
            connection.execute("INSERT INTO authority_meta(schema_version) VALUES (1)")
            connection.execute(
                """
                CREATE TABLE private_ci_authority (
                    token TEXT PRIMARY KEY NOT NULL,
                    repository TEXT NOT NULL,
                    pull_request_number INTEGER NOT NULL,
                    expected_head_sha TEXT NOT NULL,
                    workflow_identity TEXT NOT NULL,
                    target_os TEXT NOT NULL,
                    runner_scope_repository TEXT NOT NULL,
                    runner_nonce TEXT NOT NULL,
                    runner_label TEXT NOT NULL,
                    environment_generation TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('RESERVED', 'CONSUMED'))
                )
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DurablePrivateCiAuthoritySchemaError):
            self.authority()

    def test_corrupt_persisted_binding_fails_closed(self):
        authority = self.authority()
        reservation = authority.reserve(valid_binding())
        self.assertIsNotNone(reservation)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "UPDATE private_ci_authority SET target_os = 'unknown-os' WHERE token = ?",
                (reservation.token,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DurablePrivateCiAuthorityStateError):
            self.authority().binding_for(reservation)

    def test_database_contains_no_registration_or_provider_credential_columns(self):
        self.authority()
        connection = sqlite3.connect(self.database_path)
        try:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(private_ci_authority)").fetchall()
            }
        finally:
            connection.close()
        forbidden = {
            "credential",
            "credentials",
            "token_secret",
            "registration_token",
            "provider_token",
            "gh_token",
        }
        self.assertTrue(columns.isdisjoint(forbidden))

    def test_parent_directory_must_preexist(self):
        missing_path = Path(self.temp_dir.name) / "missing" / "authority.sqlite3"
        with self.assertRaises(DurablePrivateCiAuthoritySchemaError):
            DurablePrivateCiAuthority(missing_path)


if __name__ == "__main__":
    unittest.main()
