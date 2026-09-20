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
FILE_READ_ATTRIBUTES = 0x00000080
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
CREATE_NEW = 1
OPEN_EXISTING = 3
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


def _require_windows() -> None:
    if os.name != "nt" or _kernel32 is None:
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

        if archive_parent.exists() or archive_parent.is_symlink():
            parent_handle = stack.enter_context(
                _open_locked_directory(archive_parent)
            )
        else:
            archive_parent.mkdir()
            parent_handle = stack.enter_context(
                _open_locked_directory(archive_parent)
            )

        # The parent handle excludes FILE_SHARE_DELETE, so the directory cannot
        # be swapped while its ACL is tightened. After this point ordinary
        # Users have read/execute only and cannot race child creation.
        _protect_archive_container(archive_parent)

        if archive_path.exists() or archive_path.is_symlink():
            raise RuntimeError("archive directory already exists")
        archive_path.mkdir()
        archive_handle = stack.enter_context(
            _open_locked_directory(archive_path)
        )
        _protect_archive_container(archive_path)

        source_handles: list[tuple[object, LockedHandle]] = []
        destination_handles: list[tuple[object, LockedHandle]] = []

        for item in items:
            source = stack.enter_context(
                _open_locked_source(
                    evidence_root / item.filename,
                    expected_sha256=item.sha256,
                    expected_size=item.size,
                )
            )
            source_handles.append((item, source))

        for item, source in source_handles:
            destination = stack.enter_context(
                _create_locked_destination(
                    archive_path / item.filename
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
            _create_locked_destination(archive_path / "manifest.json")
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
            source_path = evidence_root / item.filename
            if source_path.exists() or source_path.is_symlink():
                raise RuntimeError(
                    "canonical source still present after handle retirement: "
                    + item.filename
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
            _create_locked_destination(
                archive_path / "retirement-complete.json"
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
