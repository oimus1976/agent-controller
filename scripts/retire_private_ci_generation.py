from __future__ import annotations

import argparse
import ctypes
import os
import secrets
import sys
from pathlib import Path


PRIVATE_CI_ROOT = Path(r"C:\ProgramData\agent-controller\private-ci")
PASS_MARKER = "PHASE6_GENERATION_RETIREMENT_IDENTITY_BOUND"

_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_DELETE = 0x00010000
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_RENAME_INFO = 3
_FILE_DISPOSITION_INFO = 4
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.c_uint32),
        ("dwHighDateTime", ctypes.c_uint32),
    ]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


class _FILE_DISPOSITION_INFO_STRUCT(ctypes.Structure):
    _fields_ = [("DeleteFile", ctypes.c_ubyte)]


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("generation retirement is Windows-only")


def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    kernel32.GetFileInformationByHandle.restype = ctypes.c_int
    kernel32.SetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    kernel32.SetFileInformationByHandle.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    return kernel32


def _open_directory_handle(path: Path):
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(
        str(path),
        _DELETE | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE or handle is None:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed", str(path))
    return kernel32, handle


def _identity(kernel32, handle) -> tuple[int, int]:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
    if info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError("generation root reparse point blocked")
    file_index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
    return int(info.dwVolumeSerialNumber), file_index


def _rename_by_handle(kernel32, handle, destination: Path) -> None:
    encoded = str(destination).encode("utf-16-le")
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    root_offset = pointer_size
    length_offset = root_offset + pointer_size
    name_offset = length_offset + ctypes.sizeof(ctypes.c_uint32)
    size = name_offset + len(encoded)
    buffer = ctypes.create_string_buffer(size)
    buffer[0] = 0
    ctypes.c_void_p.from_buffer(buffer, root_offset).value = None
    ctypes.c_uint32.from_buffer(buffer, length_offset).value = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + name_offset, encoded, len(encoded))
    if not kernel32.SetFileInformationByHandle(
        handle,
        _FILE_RENAME_INFO,
        buffer,
        size,
    ):
        raise OSError(
            ctypes.get_last_error(),
            "SetFileInformationByHandle(FileRenameInfo) failed",
        )


def _mark_delete_by_handle(kernel32, handle) -> None:
    info = _FILE_DISPOSITION_INFO_STRUCT(DeleteFile=1)
    if not kernel32.SetFileInformationByHandle(
        handle,
        _FILE_DISPOSITION_INFO,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise OSError(
            ctypes.get_last_error(),
            "SetFileInformationByHandle(FileDispositionInfo) failed",
        )


def _assert_no_reparse_tree(root: Path) -> None:
    pending = [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                stat_result = entry.stat(follow_symlinks=False)
                attributes = getattr(stat_result, "st_file_attributes", 0)
                if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                    raise RuntimeError(
                        f"generation descendant reparse point blocked: {entry.path}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))


def _delete_children(root: Path) -> None:
    entries = list(os.scandir(root))
    for entry in entries:
        stat_result = entry.stat(follow_symlinks=False)
        attributes = getattr(stat_result, "st_file_attributes", 0)
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError(
                f"generation descendant reparse point blocked: {entry.path}"
            )
        path = Path(entry.path)
        if entry.is_dir(follow_symlinks=False):
            _delete_children(path)
            os.rmdir(path)
        else:
            os.unlink(path)


def _validate_generation_path(
    generation_root: Path,
    expected_generation: str,
) -> Path:
    if (
        not expected_generation.startswith("ac-pilot-")
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
            for character in expected_generation
        )
    ):
        raise ValueError("expected generation invalid")
    root = Path(os.path.abspath(str(generation_root)))
    parent = Path(os.path.abspath(str(PRIVATE_CI_ROOT)))
    if root.parent != parent:
        raise ValueError("generation root parent mismatch")
    if root.name != expected_generation:
        raise ValueError("generation root name mismatch")
    if not root.is_dir():
        raise ValueError("generation root missing")
    return root


def retire_generation(generation_root: Path, expected_generation: str) -> None:
    _require_windows()
    root = _validate_generation_path(generation_root, expected_generation)
    _assert_no_reparse_tree(root)

    kernel32, handle = _open_directory_handle(root)
    tombstone = root.parent / (
        f".retiring-{expected_generation}-{secrets.token_hex(16)}"
    )
    try:
        original_identity = _identity(kernel32, handle)
        if tombstone.exists():
            raise RuntimeError("generation retirement tombstone collision")

        _rename_by_handle(kernel32, handle, tombstone)

        if root.exists():
            raise RuntimeError("generation root still present after handle rename")
        if not tombstone.is_dir():
            raise RuntimeError("generation tombstone missing after handle rename")

        verify_kernel32, verify_handle = _open_directory_handle(tombstone)
        try:
            if _identity(verify_kernel32, verify_handle) != original_identity:
                raise RuntimeError("generation identity changed after handle rename")
        finally:
            verify_kernel32.CloseHandle(verify_handle)

        _assert_no_reparse_tree(tombstone)
        _delete_children(tombstone)
        _mark_delete_by_handle(kernel32, handle)
    finally:
        kernel32.CloseHandle(handle)

    if tombstone.exists():
        raise RuntimeError("generation tombstone remains after handle deletion")
    if root.exists():
        raise RuntimeError("generation root reappeared during retirement")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generation-root", required=True)
    parser.add_argument("--expected-generation", required=True)
    args = parser.parse_args()
    try:
        retire_generation(
            Path(args.generation_root),
            args.expected_generation,
        )
    except Exception as error:
        print(f"PHASE6_GENERATION_RETIREMENT_BLOCKED: {error}", file=sys.stderr)
        return 1
    print(PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
