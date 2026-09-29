from __future__ import annotations

import ctypes
import hashlib
import ntpath
import os
import subprocess
import threading
from contextlib import ExitStack
from ctypes import wintypes
from pathlib import Path
from typing import Iterable


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000
FILE_READ_ATTRIBUTES = 0x00000080
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
CREATE_NEW = 1
OPEN_EXISTING = 3
NT_FILE_OPEN = 1
NT_FILE_CREATE = 2
NT_FILE_OPEN_IF = 3
FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_NON_DIRECTORY_FILE = 0x00000040
NT_FILE_OPEN_REPARSE_POINT = 0x00200000
OBJ_CASE_INSENSITIVE = 0x00000040
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_INVALID_INFO_CLASS = 0xC0000003
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
STATUS_BUFFER_OVERFLOW = 0x80000005
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
FILE_ID_INFO_CLASS = 0x12
FILE_STANDARD_INFORMATION_CLASS = 5
FILE_ID_INFORMATION_CLASS = 59
OBJECT_NAME_INFORMATION_CLASS = 1
VOLUME_OPEN_NAME_QUERY_TIMEOUT_SECONDS = 2.0
OBJECT_NAME_BUFFER_LIMIT = 64 * 1024
FILE_TYPE_UNKNOWN = 0x0000
FILE_TYPE_DISK = 0x0001
FILE_TYPE_CHAR = 0x0002
FILE_TYPE_PIPE = 0x0003
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DUPLICATE_SAME_ACCESS = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_NOT_ALL_ASSIGNED = 1300
PROCESS_PROTECTION_LEVEL_INFO_CLASS = 7
PROTECTION_LEVEL_NONE = 0xFFFFFFFE
SYSTEM_PROCESS_ID = 4
NERR_SUCCESS = 0
ERROR_MORE_DATA = 234
NERR_SERVER_NOT_STARTED = 2114
MAX_PREFERRED_LENGTH = 0xFFFFFFFF
STYPE_MASK = 0x000000FF
STYPE_DISKTREE = 0
STYPE_SPECIAL = 0x80000000
FILE_ADD_FILE = 0x00000002
FILE_ADD_SUBDIRECTORY = 0x00000004
FILE_DELETE_CHILD = 0x00000040
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
DIRECTORY_MUTATION_ACCESS = (
    FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
)
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_BEGIN = 0
FILE_DISPOSITION_INFO_CLASS = 4
MOVEFILE_WRITE_THROUGH = 0x00000008
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
BUFFER_SIZE = 1024 * 1024


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class FILE_STANDARD_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AllocationSize", ctypes.c_longlong),
        ("EndOfFile", ctypes.c_longlong),
        ("NumberOfLinks", wintypes.ULONG),
        ("DeletePending", ctypes.c_ubyte),
        ("Directory", ctypes.c_ubyte),
    ]


class FILE_ID_128(ctypes.Structure):
    _fields_ = [("Identifier", ctypes.c_ubyte * 16)]


class FILE_ID_INFO(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", FILE_ID_128),
    ]


class FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOL)]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [
        ("Status", ctypes.c_ssize_t),
        ("Information", ctypes.c_size_t),
    ]


class SHARE_INFO_2(ctypes.Structure):
    _fields_ = [
        ("shi2_netname", wintypes.LPWSTR),
        ("shi2_type", wintypes.DWORD),
        ("shi2_remark", wintypes.LPWSTR),
        ("shi2_permissions", wintypes.DWORD),
        ("shi2_max_uses", wintypes.DWORD),
        ("shi2_current_uses", wintypes.DWORD),
        ("shi2_path", wintypes.LPWSTR),
        ("shi2_passwd", wintypes.LPWSTR),
    ]


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", wintypes.LPVOID),
        ("UniqueProcessId", ctypes.c_size_t),
        ("HandleValue", ctypes.c_size_t),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES_ONE(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class PROCESS_PROTECTION_LEVEL_INFORMATION(ctypes.Structure):
    _fields_ = [("ProtectionLevel", wintypes.DWORD)]


class LockedHandle:
    def __init__(self, handle: int, path: Path):
        self.handle = handle
        self.path = path
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        if not _kernel32.CloseHandle(self.handle):
            raise ctypes.WinError(ctypes.get_last_error())
        self.closed = True

    def __enter__(self) -> "LockedHandle":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self.closed:
            _kernel32.CloseHandle(self.handle)
            self.closed = True


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _netapi32 = ctypes.WinDLL("netapi32")
    _netapi32.NetShareEnum.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _netapi32.NetShareEnum.restype = wintypes.DWORD
    _netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    _netapi32.NetApiBufferFree.restype = wintypes.DWORD

    _ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(OBJECT_ATTRIBUTES),
        ctypes.POINTER(IO_STATUS_BLOCK),
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _ntdll.NtCreateFile.restype = ctypes.c_long

    _ntdll.NtQuerySystemInformation.argtypes = [
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _ntdll.NtQuerySystemInformation.restype = ctypes.c_long

    _ntdll.NtQueryInformationFile.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(IO_STATUS_BLOCK),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    ]
    _ntdll.NtQueryInformationFile.restype = ctypes.c_long

    _ntdll.NtQueryObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _ntdll.NtQueryObject.restype = ctypes.c_long

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE

    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _kernel32.OpenProcess.argtypes = [
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    _kernel32.OpenProcess.restype = wintypes.HANDLE

    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    _kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    _kernel32.GetFileType.restype = wintypes.DWORD

    _kernel32.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    _kernel32.DuplicateHandle.restype = wintypes.BOOL

    _kernel32.GetProcessInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.GetProcessInformation.restype = wintypes.BOOL

    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL

    _advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(LUID),
    ]
    _advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

    _advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TOKEN_PRIVILEGES_ONE),
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    _advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL


    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL

    _kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL

    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL

    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL

    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL

    _kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    _kernel32.SetFilePointerEx.restype = wintypes.BOOL

    _kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.SetFileInformationByHandle.restype = wintypes.BOOL

    _kernel32.MoveFileExW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    _kernel32.MoveFileExW.restype = wintypes.BOOL
else:
    _kernel32 = None
    _ntdll = None
    _advapi32 = None
    _netapi32 = None


def _require_windows() -> None:
    if (
        os.name != "nt"
        or _kernel32 is None
        or _ntdll is None
        or _advapi32 is None
    ):
        raise RuntimeError("Windows atomic archive backend requires Windows")


def _ntstatus_code(status: int) -> int:
    return int(status) & 0xFFFFFFFF


class NativeFileQueryError(RuntimeError):
    """A native file query failed with a specific NTSTATUS."""

    def __init__(self, message: str, ntstatus: int) -> None:
        super().__init__(message)
        self.ntstatus = ntstatus


def _is_bare_device_object_name(name: str) -> bool:
    # A bare device name such as \Device\HarddiskVolume3 is a volume open.
    # Any further path component names a file or directory on that volume.
    parts = name.split("\\")
    return (
        len(parts) == 3
        and parts[0] == ""
        and parts[1].lower() == "device"
        and parts[2] != ""
    )


def _object_name_once(handle_value: int) -> str:
    size = 4096
    while True:
        buffer = ctypes.create_string_buffer(size)
        returned = wintypes.ULONG(0)
        status = _ntdll.NtQueryObject(
            wintypes.HANDLE(handle_value),
            OBJECT_NAME_INFORMATION_CLASS,
            buffer,
            size,
            ctypes.byref(returned),
        )
        code = _ntstatus_code(status)
        if code in (STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_OVERFLOW):
            wanted = int(returned.value)
            if wanted <= size or wanted > OBJECT_NAME_BUFFER_LIMIT:
                raise RuntimeError(
                    f"object name size unsupported: {wanted}"
                )
            size = wanted
            continue
        if code != 0:
            raise RuntimeError(f"NtQueryObject failed: ntstatus=0x{code:08x}")
        name = UNICODE_STRING.from_buffer(buffer)
        length = int(name.Length)
        if length == 0 or not name.Buffer:
            return ""
        return ctypes.wstring_at(name.Buffer, length // 2)


def _bounded_object_name(handle_value: int, timeout: float) -> str | None:
    # Name queries on File objects can block behind another I/O. Run the query
    # on a daemon thread and treat a timeout or error as "not proven".
    result: dict[str, str] = {}

    def worker() -> None:
        try:
            result["name"] = _object_name_once(handle_value)
        except Exception:
            pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return None
    return result.get("name")


def _proven_volume_open(handle_value: int) -> bool:
    name = _bounded_object_name(
        handle_value,
        VOLUME_OPEN_NAME_QUERY_TIMEOUT_SECONDS,
    )
    return name is not None and _is_bare_device_object_name(name)


def _system_handle_entries() -> tuple[SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, ...]:
    _require_windows()
    size = 1024 * 1024
    while True:
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG()
        status = _ntdll.NtQuerySystemInformation(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            buffer,
            size,
            ctypes.byref(needed),
        )
        code = _ntstatus_code(status)
        if code == 0:
            break
        if code != STATUS_INFO_LENGTH_MISMATCH:
            raise OSError(
                code,
                f"NtQuerySystemInformation failed: 0x{code:08x}",
            )
        size = max(size * 2, int(needed.value) + 65536)
        if size > 256 * 1024 * 1024:
            raise RuntimeError("system handle table unexpectedly large")

    pointer_size = ctypes.sizeof(ctypes.c_size_t)
    count = ctypes.c_size_t.from_buffer_copy(
        buffer.raw[:pointer_size]
    ).value
    offset = pointer_size * 2
    entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    required = offset + count * entry_size
    if required > len(buffer):
        raise RuntimeError("system handle table payload truncated")

    entries = []
    for index in range(count):
        entry_offset = offset + index * entry_size
        entries.append(
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer_copy(
                buffer.raw[entry_offset : entry_offset + entry_size]
            )
        )
    return tuple(entries)


def _file_type_once(
    handle_value: int,
    description: str,
) -> int:
    ctypes.set_last_error(0)
    file_type = int(
        _kernel32.GetFileType(wintypes.HANDLE(handle_value))
    )
    error = ctypes.get_last_error()
    if file_type == FILE_TYPE_UNKNOWN and error != 0:
        raise RuntimeError(
            f"{description} GetFileType failed: winerror={error}"
        )
    return file_type


def _native_file_is_directory_once(
    handle_value: int,
    description: str,
) -> bool | None:
    info = FILE_STANDARD_INFORMATION()
    io_status = IO_STATUS_BLOCK()
    status = _ntdll.NtQueryInformationFile(
        wintypes.HANDLE(handle_value),
        ctypes.byref(io_status),
        ctypes.byref(info),
        ctypes.sizeof(info),
        FILE_STANDARD_INFORMATION_CLASS,
    )
    code = _ntstatus_code(status)
    if code in (
        STATUS_NOT_IMPLEMENTED,
        STATUS_INVALID_INFO_CLASS,
        STATUS_INVALID_DEVICE_REQUEST,
    ):
        return None
    if code != 0:
        raise NativeFileQueryError(
            f"{description} native FileStandardInformation query failed: "
            f"ntstatus=0x{code:08x}",
            code,
        )
    if int(io_status.Information) < ctypes.sizeof(info):
        raise RuntimeError(
            f"{description} native FileStandardInformation payload truncated"
        )
    return bool(info.Directory)


def _validated_file_id_identity(
    info: FILE_ID_INFO,
    description: str,
) -> tuple[int, bytes]:
    file_id = bytes(info.FileId.Identifier)
    if file_id == b"\\x00" * 16:
        raise RuntimeError(
            f"{description} file identity unavailable: zero 128-bit FileId"
        )
    return int(info.VolumeSerialNumber), file_id


def _native_file_id_identity_once(
    handle_value: int,
    description: str,
) -> tuple[int, bytes]:
    info = FILE_ID_INFO()
    io_status = IO_STATUS_BLOCK()
    status = _ntdll.NtQueryInformationFile(
        wintypes.HANDLE(handle_value),
        ctypes.byref(io_status),
        ctypes.byref(info),
        ctypes.sizeof(info),
        FILE_ID_INFORMATION_CLASS,
    )
    code = _ntstatus_code(status)
    if code != 0:
        raise RuntimeError(
            f"{description} native FileIdInformation query failed: "
            f"ntstatus=0x{code:08x}"
        )
    if int(io_status.Information) < ctypes.sizeof(info):
        raise RuntimeError(
            f"{description} native FileIdInformation payload truncated"
        )
    return _validated_file_id_identity(info, description)


def _file_id_identity_once(
    handle_value: int,
    description: str,
) -> tuple[int, bytes]:
    info = FILE_ID_INFO()
    ctypes.set_last_error(0)
    if _kernel32.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle_value),
        FILE_ID_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        return _validated_file_id_identity(info, description)

    win32_error = ctypes.get_last_error()
    try:
        return _native_file_id_identity_once(
            handle_value,
            description,
        )
    except Exception as exc:
        raise RuntimeError(
            f"{description} file identity query failed: "
            f"winerror={win32_error}; native={exc}"
        ) from exc


def _stable_file_id_identity(
    handle_value: int,
    description: str,
) -> tuple[int, bytes]:
    first = _file_id_identity_once(handle_value, description)
    second = _file_id_identity_once(handle_value, description)
    if first != second:
        raise RuntimeError(
            f"{description} FileIdInfo identity changed during verification"
        )
    return first


def _enable_debug_privilege() -> None:
    _require_windows()
    token = wintypes.HANDLE()
    current_process = _kernel32.GetCurrentProcess()
    if not _advapi32.OpenProcessToken(
        current_process,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        luid = LUID()
        if not _advapi32.LookupPrivilegeValueW(
            None,
            "SeDebugPrivilege",
            ctypes.byref(luid),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        privileges = TOKEN_PRIVILEGES_ONE()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ctypes.set_last_error(0)
        if not _advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(privileges),
            0,
            None,
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        error = ctypes.get_last_error()
        if error == ERROR_NOT_ALL_ASSIGNED:
            raise RuntimeError(
                "SeDebugPrivilege is unavailable to the elevated archive broker"
            )
        if error != 0:
            raise ctypes.WinError(error)
    finally:
        _kernel32.CloseHandle(token)


def _process_is_protected(process: int) -> bool:
    info = PROCESS_PROTECTION_LEVEL_INFORMATION()
    if not _kernel32.GetProcessInformation(
        process,
        PROCESS_PROTECTION_LEVEL_INFO_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(info.ProtectionLevel) != PROTECTION_LEVEL_NONE


def _handle_entry_key(
    entry: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
) -> tuple[int, int, int, int, int]:
    return (
        int(entry.UniqueProcessId),
        int(entry.HandleValue),
        int(entry.Object or 0),
        int(entry.ObjectTypeIndex),
        int(entry.GrantedAccess),
    )


def _windows_path_is_same_or_under(child: str, parent: str) -> bool:
    child_norm = ntpath.normcase(ntpath.normpath(child)).rstrip("\\")
    parent_norm = ntpath.normcase(ntpath.normpath(parent)).rstrip("\\")
    if not child_norm or not parent_norm:
        return False
    return child_norm == parent_norm or child_norm.startswith(
        parent_norm + "\\"
    )


def _smb_disk_shares() -> tuple[tuple[str, str, int], ...]:
    """Return (name, path, type) for every share on this host.

    A stopped SMB server exposes nothing. Any other enumeration failure
    raises, so callers fail closed.
    """
    if os.name != "nt" or _netapi32 is None:
        raise RuntimeError("SMB share enumeration requires Windows")
    shares: list[tuple[str, str, int]] = []
    resume = wintypes.DWORD(0)
    while True:
        buffer = ctypes.c_void_p()
        read = wintypes.DWORD(0)
        total = wintypes.DWORD(0)
        status = int(
            _netapi32.NetShareEnum(
                None,
                2,
                ctypes.byref(buffer),
                MAX_PREFERRED_LENGTH,
                ctypes.byref(read),
                ctypes.byref(total),
                ctypes.byref(resume),
            )
        )
        if status == NERR_SERVER_NOT_STARTED:
            return ()
        if status not in (NERR_SUCCESS, ERROR_MORE_DATA):
            raise RuntimeError(f"SMB share enumeration failed: status={status}")
        try:
            if buffer.value:
                entries = ctypes.cast(buffer, ctypes.POINTER(SHARE_INFO_2))
                for index in range(int(read.value)):
                    entry = entries[index]
                    shares.append(
                        (
                            entry.shi2_netname or "",
                            entry.shi2_path or "",
                            int(entry.shi2_type),
                        )
                    )
        finally:
            if buffer.value:
                _netapi32.NetApiBufferFree(buffer)
        if status == NERR_SUCCESS:
            return tuple(shares)


def _shares_expose_path(
    shares: Iterable[tuple[str, str, int]],
    root_forms: Iterable[str],
) -> bool:
    roots = [form for form in root_forms if form]
    if not roots:
        raise RuntimeError("SMB exposure check needs a root path")
    for name, path, share_type in shares:
        if share_type & STYPE_SPECIAL:
            # Administrative shares (C$, ADMIN$, IPC$) are reachable only by
            # administrators, who are already trusted.
            continue
        if (share_type & STYPE_MASK) != STYPE_DISKTREE:
            continue
        if not path:
            raise RuntimeError(f"SMB disk share has no path: {name}")
        for root in roots:
            if _windows_path_is_same_or_under(root, path):
                return True
    return False


def _evidence_root_exposed_by_smb(root: Path) -> bool:
    shares = _smb_disk_shares()
    expanded: list[tuple[str, str, int]] = []
    for name, path, share_type in shares:
        expanded.append((name, path, share_type))
        if share_type & STYPE_SPECIAL:
            continue
        if (share_type & STYPE_MASK) != STYPE_DISKTREE or not path:
            continue
        # A share path may be an alias or reparse path whose target is an
        # ancestor of the root. If it cannot be resolved, exposure cannot be
        # proven absent, so fail closed.
        try:
            resolved = str(Path(path).resolve(strict=False))
        except OSError as exc:
            raise RuntimeError(
                f"SMB share path cannot be resolved: {name}: {exc}"
            ) from exc
        if resolved != path:
            expanded.append((name, resolved, share_type))
    root_forms = {str(root)}
    root_forms.add(str(Path(root).resolve(strict=True)))
    return _shares_expose_path(expanded, root_forms)


def _require_no_external_mutation_handles(
    handle: LockedHandle,
    description: str,
) -> None:
    _enable_debug_privilege()
    entries = _system_handle_entries()
    current_pid = os.getpid()
    handle_value = int(handle.handle)

    own_type_index = None
    for entry in entries:
        if (
            int(entry.UniqueProcessId) == current_pid
            and int(entry.HandleValue) == handle_value
        ):
            own_type_index = int(entry.ObjectTypeIndex)
            break
    if own_type_index is None:
        raise RuntimeError(
            f"{description} handle type not found in system table"
        )

    candidates_by_pid: dict[
        int, list[SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX]
    ] = {}
    for entry in entries:
        pid = int(entry.UniqueProcessId)
        if pid == current_pid:
            continue
        if int(entry.ObjectTypeIndex) != own_type_index:
            continue
        if int(entry.GrantedAccess) & DIRECTORY_MUTATION_ACCESS == 0:
            continue
        candidates_by_pid.setdefault(pid, []).append(entry)

    if not candidates_by_pid:
        return

    root_file_type = _file_type_once(
        handle_value,
        f"{description} authoritative root",
    )
    if root_file_type != FILE_TYPE_DISK:
        raise RuntimeError(
            f"{description} authoritative root is not a disk handle: "
            f"file_type={root_file_type}"
        )
    root_is_directory = _native_file_is_directory_once(
        handle_value,
        f"{description} authoritative root",
    )
    if root_is_directory is not True:
        raise RuntimeError(
            f"{description} authoritative root directory classification "
            f"unavailable"
        )

    root_file_id_identity = _stable_file_id_identity(
        handle_value,
        f"{description} authoritative root",
    )

    current_process = _kernel32.GetCurrentProcess()
    matching_pids: set[int] = set()
    pending: list[tuple[str, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX]] = []
    retained_duplicates: list[
        tuple[
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
            int,
            int | None,
            str | None,
            bool | None,
            str | None,
            tuple[int, bytes] | None,
            str | None,
        ]
    ] = []
    directory_status_by_duplicate: dict[int, int] = {}

    try:
        for pid, candidates in candidates_by_pid.items():
            process = _kernel32.OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                pid,
            )
            if not process:
                query_process = _kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    pid,
                )
                if not query_process:
                    if pid == 0:
                        continue
                    pending.extend(
                        ("uninspectable", entry) for entry in candidates
                    )
                    continue
                try:
                    _process_is_protected(query_process)
                finally:
                    _kernel32.CloseHandle(query_process)
                pending.extend(
                    ("uninspectable", entry) for entry in candidates
                )
                continue

            try:
                protected = _process_is_protected(process)
                if protected:
                    pending.extend(
                        ("uninspectable", entry) for entry in candidates
                    )
                    continue
                for entry in candidates:
                    duplicate = wintypes.HANDLE()
                    if not _kernel32.DuplicateHandle(
                        process,
                        wintypes.HANDLE(int(entry.HandleValue)),
                        current_process,
                        ctypes.byref(duplicate),
                        0,
                        False,
                        DUPLICATE_SAME_ACCESS,
                    ):
                        duplicate = wintypes.HANDLE()
                        if not _kernel32.DuplicateHandle(
                            process,
                            wintypes.HANDLE(int(entry.HandleValue)),
                            current_process,
                            ctypes.byref(duplicate),
                            0,
                            False,
                            DUPLICATE_SAME_ACCESS,
                        ):
                            pending.append(("unduplicable", entry))
                            continue

                    duplicate_value = int(duplicate.value)
                    duplicate_file_type = None
                    file_type_error = None
                    duplicate_is_directory = None
                    directory_error = None
                    duplicate_file_id_identity = None
                    identity_error = None
                    duplicate_description = (
                        f"{description} duplicated external mutation handle "
                        f"pid={pid} handle={int(entry.HandleValue)}"
                    )
                    try:
                        duplicate_file_type = _file_type_once(
                            duplicate_value,
                            duplicate_description,
                        )
                    except Exception as exc:
                        # The source slot may have been reused before
                        # DuplicateHandle. Defer fail-closed classification
                        # until the final snapshot proves which Object was
                        # actually duplicated.
                        file_type_error = str(exc)

                    if (
                        duplicate_file_type == FILE_TYPE_DISK
                        or file_type_error is not None
                    ):
                        try:
                            duplicate_is_directory = (
                                _native_file_is_directory_once(
                                    duplicate_value,
                                    duplicate_description,
                                )
                            )
                        except Exception as exc:
                            directory_error = str(exc)
                            status = getattr(exc, "ntstatus", None)
                            if isinstance(status, int):
                                directory_status_by_duplicate[
                                    duplicate_value
                                ] = status

                    if duplicate_is_directory is True:
                        try:
                            duplicate_file_id_identity = (
                                _stable_file_id_identity(
                                    duplicate_value,
                                    duplicate_description,
                                )
                            )
                        except Exception as exc:
                            identity_error = str(exc)

                    if (
                        duplicate_is_directory is True
                        and duplicate_file_id_identity is not None
                        and duplicate_file_id_identity
                        == root_file_id_identity
                    ):
                        _kernel32.CloseHandle(duplicate)
                        matching_pids.add(pid)
                        break

                    retained_duplicates.append(
                        (
                            entry,
                            duplicate_value,
                            duplicate_file_type,
                            file_type_error,
                            duplicate_is_directory,
                            directory_error,
                            duplicate_file_id_identity,
                            identity_error,
                        )
                    )
            finally:
                _kernel32.CloseHandle(process)

        if matching_pids:
            raise RuntimeError(
                f"{description} has pre-existing external mutation handles: "
                + ",".join(str(pid) for pid in sorted(matching_pids))
            )

        if not pending and not retained_duplicates:
            return

        final_entries = _system_handle_entries()
        live_by_object: dict[int, set[int]] = {}
        # Every external holder of an Object, regardless of access. Used only
        # for the PID 4 exclusivity check (Issue #263): a System handle is
        # trusted only when no other process holds that Object at all.
        all_holders_by_object: dict[int, set[int]] = {}
        current_object_by_handle: dict[int, int] = {}
        for current in final_entries:
            pid = int(current.UniqueProcessId)
            object_pointer = int(current.Object or 0)
            if pid == current_pid:
                current_object_by_handle[int(current.HandleValue)] = (
                    object_pointer
                )
                continue
            if int(current.ObjectTypeIndex) != own_type_index:
                continue
            if object_pointer == 0:
                continue
            all_holders_by_object.setdefault(object_pointer, set()).add(pid)
            if int(current.GrantedAccess) & DIRECTORY_MUTATION_ACCESS == 0:
                continue
            live_by_object.setdefault(object_pointer, set()).add(pid)

        for (
            entry,
            duplicate_value,
            duplicate_file_type,
            file_type_error,
            duplicate_is_directory,
            directory_error,
            duplicate_file_id_identity,
            identity_error,
        ) in retained_duplicates:
            original_object = int(entry.Object or 0)
            if original_object == 0:
                raise RuntimeError(
                    f"{description} external mutation handle object identity unavailable"
                )
            duplicate_object = current_object_by_handle.get(duplicate_value)
            if not duplicate_object:
                raise RuntimeError(
                    f"{description} duplicate lineage verification unavailable: "
                    f"handle={duplicate_value}"
                )
            if duplicate_object == original_object:
                if directory_error is not None:
                    if (
                        duplicate_file_type == FILE_TYPE_DISK
                        and directory_status_by_duplicate.get(duplicate_value)
                        == STATUS_INVALID_PARAMETER
                        and _proven_volume_open(duplicate_value)
                    ):
                        # Issue #261: a volume open (for example the Windows
                        # Search change-journal handle) rejects
                        # FileStandardInformation with
                        # STATUS_INVALID_PARAMETER. Its object name is a bare
                        # device path, so it cannot be the authoritative
                        # evidence directory. Without that positive proof the
                        # candidate still fails closed below.
                        continue
                    raise RuntimeError(
                        f"{description} duplicated external mutation handle "
                        f"directory classification unavailable for live "
                        f"snapshotted Object: pid={int(entry.UniqueProcessId)} "
                        f"handle={int(entry.HandleValue)} "
                        f"error={directory_error}"
                    )
                if duplicate_file_type is not None:
                    if duplicate_file_type != FILE_TYPE_DISK:
                        # Object-manager File handles also cover pipes,
                        # sockets, consoles, and devices. Their access-mask
                        # bit values can alias directory mutation bits, but a
                        # proven non-disk handle cannot be the authoritative
                        # evidence directory.
                        continue
                elif file_type_error is not None:
                    # GetFileType can fail on ambient File objects whose access
                    # masks alias directory mutation rights. The native
                    # FileStandardInformation query is the bounded fallback:
                    # True means continue to exact identity, while False/None
                    # proves this same Object is not the authoritative disk
                    # directory. Slot-reuse is already ruled out by the final
                    # Object comparison above.
                    if duplicate_is_directory is not True:
                        continue
                else:
                    raise RuntimeError(
                        f"{description} duplicated external mutation handle "
                        f"file type classification unavailable"
                    )
                if duplicate_is_directory is not True:
                    # The authoritative root was proven to be a disk
                    # directory whose FileStandardInformation query is
                    # supported. A retained same-Object candidate that is a
                    # regular file or whose disk/device does not implement
                    # FileStandardInformation cannot be that root. This
                    # allowance is reached only after final Object-lineage
                    # verification rules out source-slot reuse.
                    continue
                if identity_error is not None:
                    raise RuntimeError(
                        f"{description} duplicated external mutation handle "
                        f"identity unavailable for live snapshotted Object: "
                        f"pid={int(entry.UniqueProcessId)} "
                        f"handle={int(entry.HandleValue)} error={identity_error}"
                    )
                if duplicate_file_id_identity is None:
                    raise RuntimeError(
                        f"{description} duplicated external mutation handle "
                        f"identity unavailable for live snapshotted Object: "
                        f"pid={int(entry.UniqueProcessId)} "
                        f"handle={int(entry.HandleValue)}"
                    )
                # The duplicate is proven to represent the exact snapshotted
                # directory Object, and its stable file identity proved that
                # object is not the evidence root.
                continue

            # The source slot was reused before duplication. The retained
            # duplicate describes the replacement Object, so any FileIdInfo
            # failure on it is irrelevant. Preserve the original snapshotted
            # Object lineage and fail closed if any mutation-capable external
            # handle still carries it.
            live_pids = live_by_object.get(original_object)
            if live_pids:
                raise RuntimeError(
                    f"{description} has handed-off external mutation handle: "
                    f"pid={int(entry.UniqueProcessId)} "
                    f"handle={int(entry.HandleValue)} live_pids="
                    + ",".join(str(pid) for pid in sorted(live_pids))
                )

        system_handles_trusted: bool | None = None
        for pending_kind, entry in pending:
            object_pointer = int(entry.Object or 0)
            if object_pointer == 0:
                raise RuntimeError(
                    f"{description} external mutation handle object identity unavailable"
                )
            live_pids = live_by_object.get(object_pointer)
            if not live_pids:
                continue
            original_pid = int(entry.UniqueProcessId)
            if (
                pending_kind == "uninspectable"
                and original_pid == SYSTEM_PROCESS_ID
                and live_pids == {SYSTEM_PROCESS_ID}
                and all_holders_by_object.get(object_pointer)
                == {SYSTEM_PROCESS_ID}
            ):
                # Issue #263 (owner decision): the System process always holds
                # write-class kernel File handles that cannot be inspected.
                # Kernel handles are trusted like administrators, except that
                # the SMB server opens files in the System process for remote
                # clients. Trust them only when a fresh share enumeration
                # proves no non-administrative disk share reaches the root.
                if system_handles_trusted is None:
                    system_handles_trusted = not _evidence_root_exposed_by_smb(
                        handle.path
                    )
                if system_handles_trusted:
                    continue
            if pending_kind == "uninspectable":
                raise RuntimeError(
                    f"{description} has uninspectable external mutation handle: "
                    f"pid={original_pid} live_pids="
                    + ",".join(str(pid) for pid in sorted(live_pids))
                )
            raise RuntimeError(
                f"{description} has unduplicable external mutation handle: "
                f"pid={original_pid} handle={int(entry.HandleValue)} live_pids="
                + ",".join(str(pid) for pid in sorted(live_pids))
            )
    finally:
        for _, duplicate_value, _, _, _, _, _, _ in retained_duplicates:
            _kernel32.CloseHandle(wintypes.HANDLE(duplicate_value))

def _create_file(
    path: Path,
    *,
    desired_access: int,
    share_mode: int,
    creation_disposition: int,
    flags: int,
) -> LockedHandle:
    _require_windows()
    handle = _kernel32.CreateFileW(
        str(path),
        desired_access,
        share_mode,
        None,
        creation_disposition,
        flags,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    return LockedHandle(handle, path)


def _relative_component(name: str) -> str:
    if (
        type(name) is not str
        or not name
        or name in (".", "..")
        or "\\" in name
        or "/" in name
        or ":" in name
    ):
        raise ValueError("Windows archive relative component invalid")
    return name


def _nt_create_relative(
    parent: LockedHandle,
    name: str,
    *,
    desired_access: int,
    share_mode: int,
    create_disposition: int,
    create_options: int,
    file_attributes: int = FILE_ATTRIBUTE_NORMAL,
) -> LockedHandle:
    _require_windows()
    component = _relative_component(name)
    buffer = ctypes.create_unicode_buffer(component)
    encoded_length = len(component.encode("utf-16-le"))
    unicode_name = UNICODE_STRING(
        encoded_length,
        encoded_length + 2,
        ctypes.cast(buffer, wintypes.LPWSTR),
    )
    attributes = OBJECT_ATTRIBUTES(
        ctypes.sizeof(OBJECT_ATTRIBUTES),
        parent.handle,
        ctypes.pointer(unicode_name),
        OBJ_CASE_INSENSITIVE,
        None,
        None,
    )
    iosb = IO_STATUS_BLOCK()
    result_handle = wintypes.HANDLE()
    status = _ntdll.NtCreateFile(
        ctypes.byref(result_handle),
        desired_access | SYNCHRONIZE,
        ctypes.byref(attributes),
        ctypes.byref(iosb),
        None,
        file_attributes,
        share_mode,
        create_disposition,
        create_options
        | NT_FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
        0,
    )
    if status != 0:
        code = _ntstatus_code(status)
        raise OSError(
            code,
            f"NtCreateFile relative open failed: {component} "
            f"(NTSTATUS=0x{code:08x})",
        )
    return LockedHandle(
        int(result_handle.value),
        parent.path / component,
    )


def _file_identity(handle: LockedHandle) -> tuple[int, int]:
    info = _file_info(handle)
    index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
    return int(info.dwVolumeSerialNumber), index


def _require_same_identity(
    left: LockedHandle,
    right: LockedHandle,
    description: str,
) -> None:
    if _file_identity(left) != _file_identity(right):
        raise RuntimeError(f"{description} file identity drift")


def _file_info(handle: LockedHandle) -> BY_HANDLE_FILE_INFORMATION:
    info = BY_HANDLE_FILE_INFORMATION()
    if not _kernel32.GetFileInformationByHandle(
        handle.handle, ctypes.byref(info)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return info


def _file_size(info: BY_HANDLE_FILE_INFORMATION) -> int:
    return (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)


def _require_plain_directory_handle(handle: LockedHandle) -> None:
    info = _file_info(handle)
    attrs = int(info.dwFileAttributes)
    if not attrs & FILE_ATTRIBUTE_DIRECTORY:
        raise RuntimeError(f"locked path is not directory: {handle.path}")
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError(
            f"locked directory is a reparse point: {handle.path}"
        )


def _require_plain_single_link_file(
    handle: LockedHandle,
    *,
    expected_size: int | None = None,
) -> BY_HANDLE_FILE_INFORMATION:
    info = _file_info(handle)
    attrs = int(info.dwFileAttributes)
    if attrs & FILE_ATTRIBUTE_DIRECTORY:
        raise RuntimeError(f"locked path is directory: {handle.path}")
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError(f"locked file is reparse point: {handle.path}")
    if int(info.nNumberOfLinks) != 1:
        raise RuntimeError(f"locked file is hard-linked: {handle.path}")
    size = _file_size(info)
    if expected_size is not None and size != expected_size:
        raise RuntimeError(f"locked file size drift: {handle.path}")
    return info


def _seek_start(handle: LockedHandle) -> None:
    if not _kernel32.SetFilePointerEx(
        handle.handle, 0, None, FILE_BEGIN
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _read_chunks(handle: LockedHandle) -> Iterable[bytes]:
    _seek_start(handle)
    buffer = ctypes.create_string_buffer(BUFFER_SIZE)
    while True:
        read = wintypes.DWORD()
        if not _kernel32.ReadFile(
            handle.handle,
            buffer,
            BUFFER_SIZE,
            ctypes.byref(read),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        count = int(read.value)
        if count == 0:
            break
        yield buffer.raw[:count]


def _hash_handle(handle: LockedHandle) -> str:
    digest = hashlib.sha256()
    for chunk in _read_chunks(handle):
        digest.update(chunk)
    return digest.hexdigest()


def _write_all(handle: LockedHandle, raw: bytes) -> None:
    _seek_start(handle)
    offset = 0
    while offset < len(raw):
        chunk = raw[offset : offset + BUFFER_SIZE]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        if not _kernel32.WriteFile(
            handle.handle,
            buffer,
            len(chunk),
            ctypes.byref(written),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        count = int(written.value)
        if count <= 0:
            raise RuntimeError("Windows archive destination short write")
        offset += count
    if not _kernel32.FlushFileBuffers(handle.handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _copy_locked(source: LockedHandle, destination: LockedHandle) -> str:
    _seek_start(source)
    _seek_start(destination)
    digest = hashlib.sha256()
    for chunk in _read_chunks(source):
        digest.update(chunk)
        offset = 0
        while offset < len(chunk):
            part = chunk[offset:]
            buffer = ctypes.create_string_buffer(part)
            written = wintypes.DWORD()
            if not _kernel32.WriteFile(
                destination.handle,
                buffer,
                len(part),
                ctypes.byref(written),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            count = int(written.value)
            if count <= 0:
                raise RuntimeError("Windows archive destination short write")
            offset += count
    if not _kernel32.FlushFileBuffers(destination.handle):
        raise ctypes.WinError(ctypes.get_last_error())
    return digest.hexdigest()


def _mark_delete_on_close(handle: LockedHandle) -> None:
    disposition = FILE_DISPOSITION_INFO(True)
    if not _kernel32.SetFileInformationByHandle(
        handle.handle,
        FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _open_locked_directory(path: Path) -> LockedHandle:
    handle = _create_file(
        path,
        desired_access=FILE_READ_ATTRIBUTES,
        share_mode=FILE_SHARE_READ | FILE_SHARE_WRITE,
        creation_disposition=OPEN_EXISTING,
        flags=FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        _require_plain_directory_handle(handle)
    except Exception:
        handle.close()
        raise
    return handle


def _open_or_create_relative_directory(
    parent: LockedHandle,
    name: str,
) -> LockedHandle:
    handle = _nt_create_relative(
        parent,
        name,
        desired_access=FILE_READ_ATTRIBUTES,
        share_mode=FILE_SHARE_READ | FILE_SHARE_WRITE,
        create_disposition=NT_FILE_OPEN_IF,
        create_options=FILE_DIRECTORY_FILE,
        file_attributes=FILE_ATTRIBUTE_DIRECTORY,
    )
    try:
        _require_plain_directory_handle(handle)
    except Exception:
        handle.close()
        raise
    return handle


def _create_relative_directory(
    parent: LockedHandle,
    name: str,
) -> LockedHandle:
    handle = _nt_create_relative(
        parent,
        name,
        desired_access=FILE_READ_ATTRIBUTES,
        share_mode=FILE_SHARE_READ | FILE_SHARE_WRITE,
        create_disposition=NT_FILE_CREATE,
        create_options=FILE_DIRECTORY_FILE,
        file_attributes=FILE_ATTRIBUTE_DIRECTORY,
    )
    try:
        _require_plain_directory_handle(handle)
    except Exception:
        handle.close()
        raise
    return handle


def _open_locked_source_relative(
    parent: LockedHandle,
    name: str,
    *,
    expected_sha256: str,
    expected_size: int,
) -> LockedHandle:
    handle = _nt_create_relative(
        parent,
        name,
        desired_access=GENERIC_READ | DELETE,
        share_mode=FILE_SHARE_READ,
        create_disposition=NT_FILE_OPEN,
        create_options=FILE_NON_DIRECTORY_FILE,
    )
    try:
        _require_plain_single_link_file(
            handle, expected_size=expected_size
        )
        observed = _hash_handle(handle)
        if observed != expected_sha256:
            raise RuntimeError(
                f"locked source hash drift: {parent.path / name}"
            )
    except Exception:
        handle.close()
        raise
    return handle


def _create_locked_destination_relative(
    parent: LockedHandle,
    name: str,
    *,
    allow_delete: bool = False,
) -> LockedHandle:
    desired_access = GENERIC_READ | GENERIC_WRITE
    if allow_delete:
        desired_access |= DELETE
    handle = _nt_create_relative(
        parent,
        name,
        desired_access=desired_access,
        share_mode=FILE_SHARE_READ,
        create_disposition=NT_FILE_CREATE,
        create_options=FILE_NON_DIRECTORY_FILE,
    )
    try:
        _require_plain_single_link_file(handle, expected_size=0)
    except Exception:
        handle.close()
        raise
    return handle


def _open_locked_existing_relative(
    parent: LockedHandle,
    name: str,
    *,
    expected_sha256: str,
    expected_size: int,
) -> LockedHandle:
    handle = _nt_create_relative(
        parent,
        name,
        desired_access=GENERIC_READ,
        share_mode=FILE_SHARE_READ,
        create_disposition=NT_FILE_OPEN,
        create_options=FILE_NON_DIRECTORY_FILE,
    )
    try:
        _require_plain_single_link_file(
            handle,
            expected_size=expected_size,
        )
        if _hash_handle(handle) != expected_sha256:
            raise RuntimeError(
                f"locked existing file hash drift: {parent.path / name}"
            )
    except Exception:
        handle.close()
        raise
    return handle


def _open_relative_directory(
    parent: LockedHandle,
    name: str,
) -> LockedHandle:
    handle = _nt_create_relative(
        parent,
        name,
        desired_access=FILE_READ_ATTRIBUTES,
        share_mode=FILE_SHARE_READ | FILE_SHARE_WRITE,
        create_disposition=NT_FILE_OPEN,
        create_options=FILE_DIRECTORY_FILE,
        file_attributes=FILE_ATTRIBUTE_DIRECTORY,
    )
    try:
        _require_plain_directory_handle(handle)
    except Exception:
        handle.close()
        raise
    return handle


def _require_relative_directory_identity(
    parent: LockedHandle,
    name: str,
    expected: LockedHandle,
    description: str,
) -> None:
    observed = _open_relative_directory(parent, name)
    try:
        _require_same_identity(observed, expected, description)
    finally:
        observed.close()


def _relative_path_absent(parent: LockedHandle, name: str) -> bool:
    try:
        handle = _nt_create_relative(
            parent,
            name,
            desired_access=FILE_READ_ATTRIBUTES,
            share_mode=FILE_SHARE_READ | FILE_SHARE_WRITE,
            create_disposition=NT_FILE_OPEN,
            create_options=FILE_NON_DIRECTORY_FILE,
        )
    except OSError as error:
        if error.errno in (
            STATUS_OBJECT_NAME_NOT_FOUND,
            STATUS_OBJECT_PATH_NOT_FOUND,
        ):
            return True
        raise
    else:
        handle.close()
        return False


def _require_path_directory_identity(
    path: Path,
    expected: LockedHandle,
    description: str,
) -> None:
    observed = _open_locked_directory(path)
    try:
        _require_same_identity(observed, expected, description)
    finally:
        observed.close()


def _open_locked_source(
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> LockedHandle:
    handle = _create_file(
        path,
        desired_access=GENERIC_READ | DELETE,
        share_mode=FILE_SHARE_READ,
        creation_disposition=OPEN_EXISTING,
        flags=FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        _require_plain_single_link_file(
            handle, expected_size=expected_size
        )
        observed = _hash_handle(handle)
        if observed != expected_sha256:
            raise RuntimeError(f"locked source hash drift: {path}")
    except Exception:
        handle.close()
        raise
    return handle


def _create_locked_destination(path: Path) -> LockedHandle:
    handle = _create_file(
        path,
        desired_access=GENERIC_READ | GENERIC_WRITE,
        share_mode=FILE_SHARE_READ,
        creation_disposition=CREATE_NEW,
        flags=FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    try:
        _require_plain_single_link_file(handle, expected_size=0)
    except Exception:
        handle.close()
        raise
    return handle


def _publish_pending_result(
    archive_path: Path,
    *,
    pending_name: str,
    final_name: str,
) -> None:
    pending_path = archive_path / pending_name
    final_path = archive_path / final_name
    if not _kernel32.MoveFileExW(
        str(pending_path),
        str(final_path),
        MOVEFILE_WRITE_THROUGH,
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _trusted_system_directory() -> Path:
    _require_windows()
    get_system_directory = _kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_system_directory.restype = wintypes.UINT
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    count = get_system_directory(buffer, size)
    if count == 0 or count >= size:
        raise ctypes.WinError(ctypes.get_last_error())
    path = Path(buffer.value)
    _require_plain_directory_path(path, "trusted Windows system directory")
    return path


def _require_plain_directory_path(path: Path, description: str) -> None:
    stat_result = path.lstat()
    if path.is_symlink() or (
        getattr(stat_result, "st_file_attributes", 0)
        & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RuntimeError(f"{description} is symlink or reparse point")
    if not path.is_dir():
        raise RuntimeError(f"{description} is not directory")


def _trusted_icacls_path() -> Path:
    path = _trusted_system_directory() / "icacls.exe"
    stat_result = path.lstat()
    if path.is_symlink() or (
        getattr(stat_result, "st_file_attributes", 0)
        & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RuntimeError("trusted icacls.exe is symlink or reparse point")
    if not path.is_file():
        raise RuntimeError("trusted icacls.exe missing")
    return path

def _protect_archive_container(path: Path) -> None:
    command = [
        str(_trusted_icacls_path()),
        str(path),
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "*S-1-5-32-545:(OI)(CI)RX",
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "archive ACL protection failed: "
            + completed.stderr.strip()
        )


def apply_windows_archive_transaction(
    *,
    evidence_root: Path,
    archive_path: Path,
    items: tuple[object, ...],
    canonical_names: tuple[str, ...],
    manifest_raw: bytes,
    result_raw: bytes,
) -> None:
    _require_windows()

    archive_parent = archive_path.parent
    with ExitStack() as stack:
        root_handle = stack.enter_context(
            _open_locked_directory(evidence_root)
        )
        _require_path_directory_identity(
            evidence_root,
            root_handle,
            "authoritative evidence root",
        )
        _require_no_external_mutation_handles(
            root_handle,
            "authoritative evidence root",
        )
        parent_handle = stack.enter_context(
            _open_or_create_relative_directory(root_handle, "archive")
        )
        _protect_archive_container(archive_parent)
        _require_relative_directory_identity(
            root_handle,
            "archive",
            parent_handle,
            "archive parent",
        )

        archive_handle = stack.enter_context(
            _create_relative_directory(parent_handle, archive_path.name)
        )
        _protect_archive_container(archive_path)
        _require_relative_directory_identity(
            parent_handle,
            archive_path.name,
            archive_handle,
            "archive directory",
        )

        source_handles: list[tuple[object, LockedHandle]] = []
        destination_handles: list[tuple[object, LockedHandle]] = []

        for item in items:
            source = stack.enter_context(
                _open_locked_source_relative(
                    root_handle,
                    item.filename,
                    expected_sha256=item.sha256,
                    expected_size=item.size,
                )
            )
            source_handles.append((item, source))

        for item, source in source_handles:
            destination = stack.enter_context(
                _create_locked_destination_relative(
                    archive_handle,
                    item.filename,
                )
            )
            observed = _copy_locked(source, destination)
            if observed != item.sha256:
                raise RuntimeError(
                    "archive copy source hash drift: " + item.filename
                )
            _require_plain_single_link_file(
                destination, expected_size=item.size
            )
            if _hash_handle(destination) != item.sha256:
                raise RuntimeError(
                    "archive destination hash mismatch: " + item.filename
                )
            destination_handles.append((item, destination))

        manifest_handle = stack.enter_context(
            _create_locked_destination_relative(
                archive_handle, "manifest.json"
            )
        )
        _write_all(manifest_handle, manifest_raw)
        _require_plain_single_link_file(
            manifest_handle, expected_size=len(manifest_raw)
        )
        if _hash_handle(manifest_handle) != hashlib.sha256(
            manifest_raw
        ).hexdigest():
            raise RuntimeError("archive manifest hash mismatch")

        # Every source remains open without FILE_SHARE_WRITE/DELETE from the
        # initial hash check until it is retired by handle. Reconfirm that the
        # canonical evidence-root pathname still names the held root before
        # any source is marked for retirement.
        _require_path_directory_identity(
            evidence_root,
            root_handle,
            "authoritative evidence root before retirement",
        )
        for item, source in source_handles:
            if _hash_handle(source) != item.sha256:
                raise RuntimeError(
                    "locked source changed before retirement: "
                    + item.filename
                )
        for _, source in source_handles:
            _mark_delete_on_close(source)

        # Close source handles now so delete-on-close becomes effective, while
        # archive directory and destination handles remain locked and exact.
        for _, source in source_handles:
            source.close()

        for item, _ in source_handles:
            if not _relative_path_absent(root_handle, item.filename):
                raise RuntimeError(
                    "canonical source still present after handle retirement: "
                    + item.filename
                )

        _require_relative_directory_identity(
            root_handle,
            "archive",
            parent_handle,
            "archive parent after retirement",
        )
        _require_relative_directory_identity(
            parent_handle,
            archive_path.name,
            archive_handle,
            "archive directory after retirement",
        )
        _require_path_directory_identity(
            evidence_root,
            root_handle,
            "authoritative evidence root after retirement",
        )

        for item, destination in destination_handles:
            _require_plain_single_link_file(
                destination, expected_size=item.size
            )
            if _hash_handle(destination) != item.sha256:
                raise RuntimeError(
                    "archive destination changed after retirement: "
                    + item.filename
                )
        if _hash_handle(manifest_handle) != hashlib.sha256(
            manifest_raw
        ).hexdigest():
            raise RuntimeError(
                "archive manifest changed after source retirement"
            )

        pending_result_name = "retirement-complete.pending.json"
        final_result_name = "retirement-complete.json"
        pending_result_handle = stack.enter_context(
            _create_locked_destination_relative(
                archive_handle,
                pending_result_name,
            )
        )
        _write_all(pending_result_handle, result_raw)
        _require_plain_single_link_file(
            pending_result_handle,
            expected_size=len(result_raw),
        )
        result_sha256 = hashlib.sha256(result_raw).hexdigest()
        if _hash_handle(pending_result_handle) != result_sha256:
            raise RuntimeError("archive provisional retirement result hash mismatch")

        # The authoritative PASS filename does not exist yet. While the
        # elevated bootstrap holds the evidence-root namespace against
        # low-privilege creation, recheck the complete canonical allowlist.
        _require_path_directory_identity(
            evidence_root,
            root_handle,
            "authoritative evidence root before PASS commit",
        )
        _require_no_external_mutation_handles(
            root_handle,
            "authoritative evidence root before PASS commit",
        )
        recreated = []
        for canonical_name in canonical_names:
            _relative_component(canonical_name)
            if not _relative_path_absent(root_handle, canonical_name):
                recreated.append(canonical_name)
        if recreated:
            raise RuntimeError(
                "canonical source recreated before archive PASS commit: "
                + ",".join(recreated)
            )

        # Close the non-authoritative pending handle, then atomically publish
        # it to the authoritative final name inside the already protected
        # archive directory. MoveFileExW is called without REPLACE_EXISTING.
        pending_result_handle.close()
        _publish_pending_result(
            archive_path,
            pending_name=pending_result_name,
            final_name=final_result_name,
        )
        result_handle = stack.enter_context(
            _open_locked_existing_relative(
                archive_handle,
                final_result_name,
                expected_sha256=result_sha256,
                expected_size=len(result_raw),
            )
        )
        _require_relative_directory_identity(
            parent_handle,
            archive_path.name,
            archive_handle,
            "archive directory after PASS publication",
        )
