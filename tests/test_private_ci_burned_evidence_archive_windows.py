import ctypes
import os
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Windows-only PowerShell 5.1 regression")
class PrivateCiBurnedEvidenceArchiveWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.script = (
            cls.repo_root / "scripts" / "Archive-PrivateCiBurnedEvidence.ps1"
        )
        cls.powershell = shutil.which("powershell.exe")
        if cls.powershell is None:
            raise unittest.SkipTest("Windows PowerShell 5.1 unavailable")

    def test_apply_bridge_parses_under_windows_powershell_51(self):
        quoted = str(self.script).replace("'", "''")
        command = (
            "$ErrorActionPreference='Stop';"
            "$Errors=$null;"
            "$Tokens=$null;"
            "[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{quoted}',[ref]$Tokens,[ref]$Errors) | Out-Null;"
            "if (@($Errors).Count -ne 0) {"
            "  @($Errors) | ForEach-Object { Write-Error $_.Message };"
            "  exit 2"
            "}"
        )
        completed = subprocess.run(
            [
                self.powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            cwd=self.repo_root,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + "\n" + completed.stderr,
        )


    def test_locked_source_blocks_write_replace_and_retires_same_handle(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            replacement = root / "replacement.bin"
            raw = b"frozen-source"
            source.write_bytes(raw)
            replacement.write_bytes(b"replacement")

            handle = m._open_locked_source(
                source,
                expected_sha256=hashlib.sha256(raw).hexdigest(),
                expected_size=len(raw),
            )
            try:
                with self.assertRaises(OSError):
                    source.write_bytes(b"drift")
                with self.assertRaises(OSError):
                    os.replace(replacement, source)
                m._mark_delete_on_close(handle)
            finally:
                handle.close()

            self.assertFalse(source.exists())

    def test_hardlinked_source_is_rejected(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            sibling = root / "sibling.bin"
            raw = b"hard-link-source"
            source.write_bytes(raw)
            os.link(source, sibling)
            with self.assertRaisesRegex(RuntimeError, "hard-linked"):
                m._open_locked_source(
                    source,
                    expected_sha256=hashlib.sha256(raw).hexdigest(),
                    expected_size=len(raw),
                )

    def test_destination_creation_is_exclusive(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "archive.bin"
            first = m._create_locked_destination(destination)
            try:
                with self.assertRaises(OSError):
                    m._create_locked_destination(destination)
            finally:
                first.close()

    def test_external_evidence_root_handle_blocks_quiescence(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            root.mkdir()
            child_code = r"""
import ctypes
import sys
import time
from ctypes import wintypes

path = sys.argv[1]
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

handle = kernel32.CreateFileW(
    path,
    0x00000002 | 0x00000004,
    0x00000001 | 0x00000002 | 0x00000004,
    None,
    3,
    0x02000000,
    None,
)
if handle == ctypes.c_void_p(-1).value:
    raise ctypes.WinError(ctypes.get_last_error())
print("READY", flush=True)
try:
    while True:
        time.sleep(60)
finally:
    kernel32.CloseHandle(handle)
"""
            child = subprocess.Popen(
                [sys.executable, "-c", child_code, str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "READY")
                handle = m._open_locked_directory(root)
                try:
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "external mutation handle",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
                finally:
                    handle.close()
            finally:
                child.terminate()
                child.wait(timeout=10)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()

            handle = m._open_locked_directory(root)
            try:
                m._require_no_external_mutation_handles(
                    handle,
                    "authoritative evidence root",
                )
            finally:
                handle.close()

    def test_quiescence_enables_debug_and_fails_closed_on_hidden_live_handles(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        module_path = (
            self.repo_root
            / "agent_controller"
            / "private_ci_windows_atomic_archive.py"
        )
        source = module_path.read_text(encoding="utf-8")
        start = source.index("def _require_no_external_mutation_handles(")
        end = source.index("\ndef _create_file(", start)
        region = source[start:end]
        debug = region.index("_enable_debug_privilege()")
        open_process = region.index("OpenProcess(")
        duplicate = region.index("DuplicateHandle(")
        self.assertLess(debug, open_process)
        self.assertLess(open_process, duplicate)
        self.assertIn("PROCESS_DUP_HANDLE", region)
        self.assertIn("PROCESS_QUERY_LIMITED_INFORMATION", region)
        self.assertLessEqual(region.count("_system_handle_entries()"), 2)
        self.assertIn('("uninspectable", entry)', region)
        self.assertIn('("unduplicable", entry)', region)
        self.assertIn("live_by_object", region)
        self.assertIn("retained_duplicates", region)
        self.assertIn("current_object_by_handle", region)
        self.assertIn("handed-off external mutation handle", region)
        self.assertIn("_native_file_is_directory_once", region)
        self.assertIn("FILE_STANDARD_INFORMATION_CLASS = 5", source)
        self.assertIn("_stable_file_id_identity", region)
        self.assertIn("_native_file_id_identity_once", source)
        self.assertIn("FILE_ID_INFORMATION_CLASS = 59", source)
        self.assertNotIn("_same_file_identity", region)
        self.assertIn("object_pointer", region)
        self.assertIn("external mutation handle object identity unavailable", region)
        self.assertIn("_process_is_protected", region)
        self.assertIn("uninspectable external mutation handle", region)
        self.assertIn("unduplicable external mutation handle", region)

    def test_00_file_id_info_supports_mutation_only_directory_handle(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mutation_handle = m._kernel32.CreateFileW(
                str(root),
                m.FILE_ADD_FILE | m.FILE_ADD_SUBDIRECTORY,
                m.FILE_SHARE_READ | m.FILE_SHARE_WRITE | 0x00000004,
                None,
                m.OPEN_EXISTING,
                m.FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            self.assertNotEqual(mutation_handle, m.INVALID_HANDLE_VALUE)
            try:
                normal = m._open_locked_directory(root)
                try:
                    self.assertEqual(
                        m._stable_file_id_identity(
                            int(mutation_handle),
                            "mutation-only directory handle",
                        ),
                        m._stable_file_id_identity(
                            int(normal.handle),
                            "normal directory handle",
                        ),
                    )
                finally:
                    normal.close()
            finally:
                m._kernel32.CloseHandle(mutation_handle)

    def test_01_native_file_id_supports_cross_process_duplicated_mutation_handle(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child_code = r"""
import ctypes
import sys
import time
from ctypes import wintypes

path = sys.argv[1]
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

handle = kernel32.CreateFileW(
    path,
    0x00000002 | 0x00000004,
    0x00000001 | 0x00000002 | 0x00000004,
    None,
    3,
    0x02000000,
    None,
)
if handle == ctypes.c_void_p(-1).value:
    raise ctypes.WinError(ctypes.get_last_error())
print(f"READY {int(handle)}", flush=True)
try:
    while True:
        time.sleep(60)
finally:
    kernel32.CloseHandle(handle)
"""
            child = subprocess.Popen(
                [sys.executable, "-c", child_code, str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            process = None
            duplicate = m.wintypes.HANDLE()
            try:
                ready = child.stdout.readline().strip().split()
                self.assertEqual(ready[0], "READY")
                source_handle = int(ready[1])

                process = m._kernel32.OpenProcess(
                    m.PROCESS_DUP_HANDLE
                    | m.PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    child.pid,
                )
                self.assertTrue(process)
                self.assertTrue(
                    m._kernel32.DuplicateHandle(
                        process,
                        m.wintypes.HANDLE(source_handle),
                        m._kernel32.GetCurrentProcess(),
                        ctypes.byref(duplicate),
                        0,
                        False,
                        m.DUPLICATE_SAME_ACCESS,
                    )
                )

                normal = m._open_locked_directory(root)
                try:
                    self.assertEqual(
                        m._native_file_id_identity_once(
                            int(duplicate.value),
                            "cross-process duplicated mutation handle",
                        ),
                        m._native_file_id_identity_once(
                            int(normal.handle),
                            "normal directory handle",
                        ),
                    )
                finally:
                    normal.close()
            finally:
                if duplicate.value:
                    m._kernel32.CloseHandle(duplicate)
                if process:
                    m._kernel32.CloseHandle(process)
                child.terminate()
                child.wait(timeout=10)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()

    def test_02_native_standard_info_filters_writable_file_bit_alias(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path = root / "writable.bin"
            file_path.write_bytes(b"x")

            directory_handle = m._kernel32.CreateFileW(
                str(root),
                m.FILE_ADD_FILE | m.FILE_ADD_SUBDIRECTORY,
                m.FILE_SHARE_READ | m.FILE_SHARE_WRITE | 0x00000004,
                None,
                m.OPEN_EXISTING,
                m.FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            self.assertNotEqual(directory_handle, m.INVALID_HANDLE_VALUE)

            file_handle = m._kernel32.CreateFileW(
                str(file_path),
                0x00000002 | 0x00000004,
                m.FILE_SHARE_READ | m.FILE_SHARE_WRITE | 0x00000004,
                None,
                m.OPEN_EXISTING,
                m.FILE_ATTRIBUTE_NORMAL,
                None,
            )
            self.assertNotEqual(file_handle, m.INVALID_HANDLE_VALUE)
            try:
                self.assertTrue(
                    m._native_file_is_directory_once(
                        int(directory_handle),
                        "mutation-only directory",
                    )
                )
                self.assertFalse(
                    m._native_file_is_directory_once(
                        int(file_handle),
                        "writable ordinary file",
                    )
                )
            finally:
                m._kernel32.CloseHandle(file_handle)
                m._kernel32.CloseHandle(directory_handle)

    def test_file_id_info_query_failure_blocks(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        def fail_query(*args):
            ctypes.set_last_error(5)
            return 0

        fake_kernel32 = SimpleNamespace(
            GetFileInformationByHandleEx=fail_query,
        )
        fake_ntdll = SimpleNamespace(
            NtQueryInformationFile=lambda *args: 0xC000000D,
        )
        with mock.patch.object(
            m,
            "_kernel32",
            fake_kernel32,
        ), mock.patch.object(
            m,
            "_ntdll",
            fake_ntdll,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "file identity query failed: winerror=5",
            ):
                m._file_id_identity_once(
                    0x99,
                    "synthetic mutation handle",
                )

    def test_stable_file_id_identity_rejects_change_between_reads(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with mock.patch.object(
            m,
            "_file_id_identity_once",
            side_effect=[
                (0xAABBCCDD, b"1" * 16),
                (0xAABBCCDD, b"2" * 16),
            ],
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "FileIdInfo identity changed during verification",
            ):
                m._stable_file_id_identity(
                    0x99,
                    "synthetic mutation handle",
                )


    def test_debug_privilege_is_mandatory_for_quiescence(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        module_path = (
            self.repo_root
            / "agent_controller"
            / "private_ci_windows_atomic_archive.py"
        )
        source = module_path.read_text(encoding="utf-8")
        self.assertIn('"SeDebugPrivilege"', source)
        self.assertIn("AdjustTokenPrivileges", source)
        self.assertIn("ERROR_NOT_ALL_ASSIGNED", source)

        with mock.patch.object(
            m,
            "_enable_debug_privilege",
            side_effect=RuntimeError("synthetic debug privilege failure"),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                handle = m._open_locked_directory(root)
                try:
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "synthetic debug privilege failure",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
                finally:
                    handle.close()

    def test_live_unduplicable_candidate_handle_blocks_instead_of_being_ignored(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                external = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                external.UniqueProcessId = os.getpid() + 1000
                external.HandleValue = 0x77
                external.Object = 0x22222222
                external.ObjectTypeIndex = 7
                external.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 0,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, external),
                        (own, external),
                    ],
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    return_value=(0xAABBCCDD, 0x1111),
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "uninspectable external mutation handle",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
            finally:
                handle.close()

    def test_stale_unduplicable_candidate_is_skipped_after_single_refresh(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                stale = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                stale.UniqueProcessId = os.getpid() + 1000
                stale.HandleValue = 0x77
                stale.Object = 0x22222222
                stale.ObjectTypeIndex = 7
                stale.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=lambda *args: 0,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, stale),
                        (own,),
                    ],
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    return_value=(0xAABBCCDD, 0x1111),
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    m._require_no_external_mutation_handles(
                        handle,
                        "authoritative evidence root",
                    )
            finally:
                handle.close()

    def test_handed_off_unduplicable_candidate_blocks_on_same_object_replacement(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                original = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                original.UniqueProcessId = os.getpid() + 1000
                original.HandleValue = 0x77
                original.Object = 0x22222222
                original.ObjectTypeIndex = 7
                original.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                replacement = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                replacement.UniqueProcessId = os.getpid() + 2000
                replacement.HandleValue = 0x88
                replacement.Object = original.Object
                replacement.ObjectTypeIndex = 7
                replacement.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=lambda *args: 0,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, original),
                        (own, replacement),
                    ],
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    return_value=(0xAABBCCDD, 0x1111),
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "unduplicable external mutation handle",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
            finally:
                handle.close()

    def test_equal_native_identity_blocks_external_mutation_handle(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                external = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                external.UniqueProcessId = os.getpid() + 1000
                external.HandleValue = 0x77
                external.Object = 0x22222222
                external.ObjectTypeIndex = 7
                external.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                def duplicate_handle(*args):
                    args[3]._obj.value = 0x99
                    return 1

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=duplicate_handle,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    return_value=(own, external),
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    side_effect=[
                        (0xAABBCCDD, 0x1111),
                        (0xAABBCCDD, 0x1111),
                    ],
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "pre-existing external mutation handles",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
            finally:
                handle.close()

    def test_directory_classification_failure_same_object_blocks(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                original = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                original.UniqueProcessId = os.getpid() + 1000
                original.HandleValue = 0x77
                original.Object = 0x22222222
                original.ObjectTypeIndex = 7
                original.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                duplicate_entry = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                duplicate_entry.UniqueProcessId = os.getpid()
                duplicate_entry.HandleValue = 0x99
                duplicate_entry.Object = original.Object
                duplicate_entry.ObjectTypeIndex = 7
                duplicate_entry.GrantedAccess = 0

                def duplicate_handle(*args):
                    args[3]._obj.value = 0x99
                    return 1

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=duplicate_handle,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, original),
                        (own, duplicate_entry, original),
                    ],
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    side_effect=RuntimeError(
                        "synthetic FileStandardInformation failure"
                    ),
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    return_value=(0xAABBCCDD, b"1" * 16),
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "directory classification unavailable for live snapshotted Object",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
            finally:
                handle.close()

    def test_file_id_failure_same_object_blocks_after_lineage_confirmation(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                original = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                original.UniqueProcessId = os.getpid() + 1000
                original.HandleValue = 0x77
                original.Object = 0x22222222
                original.ObjectTypeIndex = 7
                original.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                duplicate_entry = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                duplicate_entry.UniqueProcessId = os.getpid()
                duplicate_entry.HandleValue = 0x99
                duplicate_entry.Object = original.Object
                duplicate_entry.ObjectTypeIndex = 7
                duplicate_entry.GrantedAccess = 0

                def duplicate_handle(*args):
                    args[3]._obj.value = 0x99
                    return 1

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=duplicate_handle,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, original),
                        (own, duplicate_entry, original),
                    ],
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    side_effect=[
                        (0xAABBCCDD, b"1" * 16),
                        RuntimeError("synthetic FileIdInfo failure"),
                    ],
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "identity unavailable for live snapshotted Object",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
            finally:
                handle.close()

    def test_file_id_failure_on_reused_slot_is_ignored_after_original_lineage_dies(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                original = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                original.UniqueProcessId = os.getpid() + 1000
                original.HandleValue = 0x77
                original.Object = 0x22222222
                original.ObjectTypeIndex = 7
                original.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                duplicate_entry = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                duplicate_entry.UniqueProcessId = os.getpid()
                duplicate_entry.HandleValue = 0x99
                duplicate_entry.Object = 0x33333333
                duplicate_entry.ObjectTypeIndex = 7
                duplicate_entry.GrantedAccess = 0

                def duplicate_handle(*args):
                    args[3]._obj.value = 0x99
                    return 1

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=duplicate_handle,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, original),
                        (own, duplicate_entry),
                    ],
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    side_effect=[
                        (0xAABBCCDD, b"1" * 16),
                        RuntimeError("synthetic FileIdInfo failure"),
                    ],
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    m._require_no_external_mutation_handles(
                        handle,
                        "authoritative evidence root",
                    )
            finally:
                handle.close()

    def test_successful_mismatch_preserves_snapshot_lineage_across_slot_reuse(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                original = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                original.UniqueProcessId = os.getpid() + 1000
                original.HandleValue = 0x77
                original.Object = 0x22222222
                original.ObjectTypeIndex = 7
                original.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                replacement = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                replacement.UniqueProcessId = os.getpid() + 2000
                replacement.HandleValue = 0x88
                replacement.Object = original.Object
                replacement.ObjectTypeIndex = 7
                replacement.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                duplicate_entry = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                duplicate_entry.UniqueProcessId = os.getpid()
                duplicate_entry.HandleValue = 0x99
                duplicate_entry.Object = 0x33333333
                duplicate_entry.ObjectTypeIndex = 7
                duplicate_entry.GrantedAccess = 0

                def duplicate_handle(*args):
                    args[3]._obj.value = 0x99
                    return 1

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=duplicate_handle,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, original),
                        (own, duplicate_entry, replacement),
                    ],
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    side_effect=[
                        (0xAABBCCDD, 0x1111),
                        (0xAABBCCDD, 0x3333),
                    ],
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "handed-off external mutation handle",
                    ):
                        m._require_no_external_mutation_handles(
                            handle,
                            "authoritative evidence root",
                        )
            finally:
                handle.close()

    def test_successful_mismatch_same_object_is_confirmed_unrelated(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            handle = m._open_locked_directory(root)
            try:
                own = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                own.UniqueProcessId = os.getpid()
                own.HandleValue = int(handle.handle)
                own.Object = 0x11111111
                own.ObjectTypeIndex = 7
                own.GrantedAccess = 0

                unrelated = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                unrelated.UniqueProcessId = os.getpid() + 1000
                unrelated.HandleValue = 0x77
                unrelated.Object = 0x22222222
                unrelated.ObjectTypeIndex = 7
                unrelated.GrantedAccess = m.DIRECTORY_MUTATION_ACCESS

                duplicate_entry = m.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
                duplicate_entry.UniqueProcessId = os.getpid()
                duplicate_entry.HandleValue = 0x99
                duplicate_entry.Object = unrelated.Object
                duplicate_entry.ObjectTypeIndex = 7
                duplicate_entry.GrantedAccess = 0

                def duplicate_handle(*args):
                    args[3]._obj.value = 0x99
                    return 1

                fake_kernel32 = SimpleNamespace(
                    GetCurrentProcess=lambda: 1,
                    OpenProcess=lambda *args: 123,
                    DuplicateHandle=duplicate_handle,
                    CloseHandle=lambda *args: 1,
                )
                with mock.patch.object(
                    m,
                    "_enable_debug_privilege",
                    return_value=None,
                ), mock.patch.object(
                    m,
                    "_system_handle_entries",
                    side_effect=[
                        (own, unrelated),
                        (own, duplicate_entry, unrelated),
                    ],
                ), mock.patch.object(
                    m,
                    "_process_is_protected",
                    return_value=False,
                ), mock.patch.object(
                    m,
                    "_native_file_is_directory_once",
                    return_value=True,
                ), mock.patch.object(
                    m,
                    "_stable_file_id_identity",
                    side_effect=[
                        (0xAABBCCDD, 0x1111),
                        (0xAABBCCDD, 0x2222),
                    ],
                ), mock.patch.object(
                    m,
                    "_kernel32",
                    fake_kernel32,
                ):
                    m._require_no_external_mutation_handles(
                        handle,
                        "authoritative evidence root",
                    )
            finally:
                handle.close()

    def test_archive_transaction_runs_quiescence_at_start_and_before_pass(self):
        module_path = (
            self.repo_root
            / "agent_controller"
            / "private_ci_windows_atomic_archive.py"
        )
        source = module_path.read_text(encoding="utf-8")
        start = source.index("def apply_windows_archive_transaction(")
        region = source[start:]
        self.assertGreaterEqual(
            region.count("_require_no_external_mutation_handles("),
            2,
        )

    def test_trusted_icacls_ignores_inherited_windir(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        original = os.environ.get("WINDIR")
        try:
            os.environ["WINDIR"] = r"C:\attacker-controlled-windir"
            observed = m._trusted_icacls_path()
            system_directory = m._trusted_system_directory()
            self.assertEqual(observed.parent, system_directory)
            self.assertEqual(observed.name.casefold(), "icacls.exe")
            self.assertNotIn(
                "attacker-controlled-windir",
                str(observed).casefold(),
            )
        finally:
            if original is None:
                os.environ.pop("WINDIR", None)
            else:
                os.environ["WINDIR"] = original

    def test_recreated_canonical_name_blocks_authoritative_pass_publication(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            archive = root / "archive" / "issue216-burned-test"
            root.mkdir()
            source = root / "issue216-phase0-canonical.json"
            raw = b"phase0"
            source.write_bytes(raw)
            item = SimpleNamespace(
                filename=source.name,
                sha256=hashlib.sha256(raw).hexdigest(),
                size=len(raw),
            )
            calls = 0

            def staged_absence(parent, name):
                nonlocal calls
                calls += 1
                if calls <= 2:
                    return True
                return False

            with mock.patch.object(
                m,
                "_protect_archive_container",
                return_value=None,
            ), mock.patch.object(
                m,
                "_require_no_external_mutation_handles",
                return_value=None,
            ), mock.patch.object(
                m,
                "_relative_path_absent",
                side_effect=staged_absence,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "recreated before archive PASS commit",
                ):
                    m.apply_windows_archive_transaction(
                        evidence_root=root,
                        archive_path=archive,
                        items=(item,),
                        canonical_names=(
                            item.filename,
                            "issue225-phase5-plan.json",
                        ),
                        manifest_raw=b"manifest",
                        result_raw=b"result",
                    )

            self.assertFalse(
                (archive / "retirement-complete.json").exists()
            )
            self.assertTrue(
                (archive / "retirement-complete.pending.json").exists()
            )

    def test_retirement_result_is_atomically_published_after_final_gate(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            archive = root / "archive" / "issue216-burned-test"
            root.mkdir()
            source = root / "issue216-phase0-canonical.json"
            raw = b"phase0"
            source.write_bytes(raw)
            item = SimpleNamespace(
                filename=source.name,
                sha256=hashlib.sha256(raw).hexdigest(),
                size=len(raw),
            )

            with mock.patch.object(
                m,
                "_protect_archive_container",
                return_value=None,
            ), mock.patch.object(
                m,
                "_require_no_external_mutation_handles",
                return_value=None,
            ):
                m.apply_windows_archive_transaction(
                    evidence_root=root,
                    archive_path=archive,
                    items=(item,),
                    canonical_names=(item.filename,),
                    manifest_raw=b"manifest",
                    result_raw=b"result",
                )

            self.assertFalse(
                (archive / "retirement-complete.pending.json").exists()
            )
            self.assertEqual(
                (archive / "retirement-complete.json").read_bytes(),
                b"result",
            )
            self.assertFalse(source.exists())

    def test_relative_destination_stays_under_locked_directory_after_rename(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root_handle = m._open_locked_directory(parent)
            try:
                archive_handle = m._create_relative_directory(
                    root_handle, "archive"
                )
                try:
                    renamed = parent / "archive-renamed"
                    os.replace(parent / "archive", renamed)
                    (parent / "archive").mkdir()

                    destination = m._create_locked_destination_relative(
                        archive_handle,
                        "evidence.bin",
                    )
                    try:
                        m._write_all(destination, b"locked-destination")
                    finally:
                        destination.close()

                    self.assertEqual(
                        (renamed / "evidence.bin").read_bytes(),
                        b"locked-destination",
                    )
                    self.assertFalse(
                        (parent / "archive" / "evidence.bin").exists()
                    )
                finally:
                    archive_handle.close()
            finally:
                root_handle.close()

    def test_canonical_root_identity_rejects_path_replacement(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp)
            evidence = outer / "evidence"
            renamed = outer / "evidence-renamed"
            evidence.mkdir()

            root_handle = m._open_locked_directory(evidence)
            try:
                os.replace(evidence, renamed)
                evidence.mkdir()
                with self.assertRaisesRegex(RuntimeError, "identity drift"):
                    m._require_path_directory_identity(
                        evidence,
                        root_handle,
                        "authoritative evidence root",
                    )
            finally:
                root_handle.close()

    def test_relative_source_open_stays_bound_to_evidence_root_handle(self):
        from agent_controller import private_ci_windows_atomic_archive as m

        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp)
            evidence = outer / "evidence"
            evidence.mkdir()
            source = evidence / "source.bin"
            raw = b"relative-source"
            source.write_bytes(raw)

            root_handle = m._open_locked_directory(evidence)
            try:
                renamed = outer / "evidence-renamed"
                os.replace(evidence, renamed)
                evidence.mkdir()
                (evidence / "source.bin").write_bytes(b"replacement")

                handle = m._open_locked_source_relative(
                    root_handle,
                    "source.bin",
                    expected_sha256=hashlib.sha256(raw).hexdigest(),
                    expected_size=len(raw),
                )
                try:
                    self.assertEqual(m._hash_handle(handle), hashlib.sha256(raw).hexdigest())
                finally:
                    handle.close()
            finally:
                root_handle.close()


if __name__ == "__main__":
    unittest.main()
