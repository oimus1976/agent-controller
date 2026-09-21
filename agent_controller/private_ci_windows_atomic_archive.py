from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
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
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_BEGIN = 0
FILE_DISPOSITION_INFO_CLASS = 4
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

    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL

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
else:
    _kernel32 = None
    _ntdll = None


def _require_windows() -> None:
    if os.name != "nt" or _kernel32 is None or _ntdll is None:
        raise RuntimeError("Windows atomic archive backend requires Windows")


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


def _ntstatus_code(status: int) -> int:
    return int(status) & 0xFFFFFFFF


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
) -> LockedHandle:
    handle = _nt_create_relative(
        parent,
        name,
        desired_access=GENERIC_READ | GENERIC_WRITE,
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


def _trusted_icacls_path() -> Path:
    windir = os.environ.get("WINDIR", r"C:\Windows")
    path = Path(windir) / "System32" / "icacls.exe"
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
    manifest_raw: bytes,
    result_raw: bytes,
) -> None:
    _require_windows()

    archive_parent = archive_path.parent
    with ExitStack() as stack:
        root_handle = stack.enter_context(
            _open_locked_directory(evidence_root)
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
        # initial hash check until it is retired by handle. A pathname swap
        # cannot occur between verification and deletion.
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

        result_handle = stack.enter_context(
            _create_locked_destination_relative(
                archive_handle, "retirement-complete.json"
            )
        )
        _write_all(result_handle, result_raw)
        _require_plain_single_link_file(
            result_handle, expected_size=len(result_raw)
        )
        if _hash_handle(result_handle) != hashlib.sha256(
            result_raw
        ).hexdigest():
            raise RuntimeError("archive retirement result hash mismatch")
