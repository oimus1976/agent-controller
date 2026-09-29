"""Issue #261: volume-open classification helpers for archive quiescence.

These helpers are pure or thread-bounded and run on every platform. The real
Windows handle-table regressions live in
``test_private_ci_burned_evidence_archive_windows.py``.
"""

import threading
import time
import unittest
from unittest import mock

from agent_controller import private_ci_windows_atomic_archive as m


class BareDeviceObjectNameTests(unittest.TestCase):
    def test_bare_device_names_are_volume_opens(self):
        for name in (
            "\\Device\\HarddiskVolume3",
            "\\Device\\HarddiskVolume12",
            "\\device\\HarddiskVolume3",
        ):
            with self.subTest(name=name):
                self.assertTrue(m._is_bare_device_object_name(name))

    def test_names_with_a_path_component_are_not_volume_opens(self):
        for name in (
            "\\Device\\HarddiskVolume3\\",
            "\\Device\\HarddiskVolume3\\Users",
            "\\Device\\HarddiskVolume3\\Users\\Public\\Documents\\agent-controller-handoff",
            "\\Device\\",
            "\\Device",
            "Device\\HarddiskVolume3",
            "\\??\\C:",
            "C:\\",
            "",
        ):
            with self.subTest(name=name):
                self.assertFalse(m._is_bare_device_object_name(name))


class BoundedObjectNameTests(unittest.TestCase):
    def test_timeout_is_not_proof(self):
        release = threading.Event()

        def blocked(_handle):
            release.wait(5)
            return "\\Device\\HarddiskVolume3"

        try:
            with mock.patch.object(m, "_object_name_once", side_effect=blocked):
                started = time.monotonic()
                self.assertIsNone(m._bounded_object_name(123, 0.2))
                self.assertLess(time.monotonic() - started, 2.0)
        finally:
            release.set()

    def test_query_error_is_not_proof(self):
        with mock.patch.object(
            m,
            "_object_name_once",
            side_effect=RuntimeError("NtQueryObject failed: ntstatus=0xc0000008"),
        ):
            self.assertIsNone(m._bounded_object_name(123, 1.0))

    def test_returns_name_when_query_completes(self):
        with mock.patch.object(
            m,
            "_object_name_once",
            return_value="\\Device\\HarddiskVolume3",
        ):
            self.assertEqual(
                m._bounded_object_name(123, 1.0),
                "\\Device\\HarddiskVolume3",
            )


class ProvenVolumeOpenTests(unittest.TestCase):
    def test_only_a_completed_bare_device_name_is_proof(self):
        cases = (
            (None, False),
            ("", False),
            ("\\Device\\HarddiskVolume3\\Users\\Public", False),
            ("\\Device\\HarddiskVolume3", True),
        )
        for name, expected in cases:
            with self.subTest(name=name):
                with mock.patch.object(
                    m,
                    "_bounded_object_name",
                    return_value=name,
                ) as bounded:
                    self.assertIs(m._proven_volume_open(456), expected)
                bounded.assert_called_once_with(
                    456,
                    m.VOLUME_OPEN_NAME_QUERY_TIMEOUT_SECONDS,
                )

    def test_native_directory_query_error_carries_ntstatus(self):
        error = m.NativeFileQueryError("probe", m.STATUS_INVALID_PARAMETER)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(error.ntstatus, 0xC000000D)
        self.assertEqual(str(error), "probe")


if __name__ == "__main__":
    unittest.main()
