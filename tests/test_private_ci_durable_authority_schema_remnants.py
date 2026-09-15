import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_controller.private_ci_durable_authority import (
    DurablePrivateCiAuthority,
    DurablePrivateCiAuthoritySchemaError,
)


class DurablePrivateCiAuthoritySchemaRemnantTests(unittest.TestCase):
    def test_view_only_schema_remnant_fails_closed_without_authority_table_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "authority.sqlite3"
            connection = sqlite3.connect(database_path)
            try:
                connection.execute("CREATE VIEW leftover_authority_view AS SELECT 1 AS marker")
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(DurablePrivateCiAuthoritySchemaError):
                DurablePrivateCiAuthority(database_path)

            connection = sqlite3.connect(database_path)
            try:
                schema_objects = {
                    (row[0], row[1])
                    for row in connection.execute(
                        "SELECT type, name FROM sqlite_master WHERE substr(name, 1, 7) != 'sqlite_'
                    ).fetchall()
                }
            finally:
                connection.close()

            self.assertEqual(schema_objects, {("view", "leftover_authority_view")})

    def test_sqlitex_prefixed_view_is_not_treated_as_sqlite_internal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "authority.sqlite3"
            connection = sqlite3.connect(database_path)
            try:
                connection.execute("CREATE VIEW sqlitex_leftover AS SELECT 1 AS marker")
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(DurablePrivateCiAuthoritySchemaError):
                DurablePrivateCiAuthority(database_path)

            connection = sqlite3.connect(database_path)
            try:
                schema_objects = {
                    (row[0], row[1])
                    for row in connection.execute(
                        "SELECT type, name FROM sqlite_master "
                        "WHERE substr(name, 1, 7) != 'sqlite_'"
                    ).fetchall()
                }
            finally:
                connection.close()

            self.assertEqual(schema_objects, {("view", "sqlitex_leftover")})


if __name__ == "__main__":
    unittest.main()
