from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath


RUNNER_GENERATION_SNAPSHOT_SCHEMA = (
    "agent-controller.private-ci-runner-generation-snapshot.v1"
)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse(stat_result: os.stat_result) -> bool:
    return bool(
        getattr(stat_result, "st_file_attributes", 0)
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _require_plain_directory(path: Path, description: str) -> os.stat_result:
    try:
        stat_result = path.lstat()
    except OSError as error:
        raise ValueError(f"{description} missing") from error
    if path.is_symlink() or _is_reparse(stat_result):
        raise ValueError(f"{description} is symlink or reparse point")
    if not path.is_dir():
        raise ValueError(f"{description} is not directory")
    return stat_result


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError as error:
        raise ValueError(f"runner snapshot file read failed: {path}") from error
    return hasher.hexdigest()


def _snapshot_entries(
    *,
    generation_root: Path,
    runner_root: Path,
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    pending = [runner_root]

    while pending:
        current = pending.pop()
        relative = current.relative_to(generation_root).as_posix()
        _require_plain_directory(current, f"runner snapshot directory {relative}")
        entries.append({"kind": "directory", "path": relative})

        try:
            children = sorted(
                os.scandir(current),
                key=lambda entry: entry.name.casefold(),
            )
        except OSError as error:
            raise ValueError(
                f"runner snapshot directory read failed: {relative}"
            ) from error

        directories: list[Path] = []
        for child in children:
            child_path = Path(child.path)
            child_relative = child_path.relative_to(
                generation_root
            ).as_posix()
            try:
                stat_result = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ValueError(
                    f"runner snapshot stat failed: {child_relative}"
                ) from error
            if child.is_symlink() or _is_reparse(stat_result):
                raise ValueError(
                    f"runner snapshot symlink or reparse point blocked: "
                    f"{child_relative}"
                )
            if child.is_dir(follow_symlinks=False):
                directories.append(child_path)
                continue
            if child.is_file(follow_symlinks=False):
                entries.append(
                    {
                        "kind": "file",
                        "path": child_relative,
                        "sha256": _file_sha256(child_path),
                        "size": stat_result.st_size,
                    }
                )
                continue
            raise ValueError(
                f"runner snapshot unsupported filesystem entry: "
                f"{child_relative}"
            )

        pending.extend(reversed(directories))

    entries.sort(
        key=lambda entry: (
            str(entry["path"]).casefold(),
            str(entry["path"]),
            str(entry["kind"]),
        )
    )
    return entries


def runner_generation_snapshot_bytes(
    *,
    generation_root: Path,
    runner_root: Path,
    work_folder: str,
) -> bytes:
    if not isinstance(generation_root, Path) or not isinstance(runner_root, Path):
        raise ValueError("runner snapshot paths must be Path")
    if (
        type(work_folder) is not str
        or not work_folder
        or work_folder in (".", "..")
        or "/" in work_folder
        or "\\" in work_folder
    ):
        raise ValueError("runner snapshot work folder invalid")

    _require_plain_directory(generation_root, "generation root")
    _require_plain_directory(runner_root, "runner root")

    try:
        relative_runner = runner_root.relative_to(generation_root)
    except ValueError as error:
        raise ValueError("runner root escapes generation root") from error
    if relative_runner.parts != ("runner",):
        raise ValueError("runner root is not canonical generation child")

    try:
        generation_children = sorted(
            os.scandir(generation_root),
            key=lambda entry: entry.name.casefold(),
        )
    except OSError as error:
        raise ValueError("generation root read failed") from error
    if len(generation_children) != 1:
        raise ValueError("generation root contains unexpected sibling state")
    only_child = generation_children[0]
    try:
        only_stat = only_child.stat(follow_symlinks=False)
    except OSError as error:
        raise ValueError("generation root child stat failed") from error
    if (
        only_child.name != "runner"
        or only_child.is_symlink()
        or _is_reparse(only_stat)
        or not only_child.is_dir(follow_symlinks=False)
    ):
        raise ValueError("generation root child is not canonical runner")

    work_path = runner_root / work_folder
    if work_path.exists() or work_path.is_symlink():
        raise ValueError("runner work folder already exists")

    payload = {
        "schema": RUNNER_GENERATION_SNAPSHOT_SCHEMA,
        "runner_directory": "runner",
        "work_folder": work_folder,
        "entries": _snapshot_entries(
            generation_root=generation_root,
            runner_root=runner_root,
        ),
    }
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def runner_generation_snapshot_sha256(
    *,
    generation_root: Path,
    runner_root: Path,
    work_folder: str,
) -> str:
    return hashlib.sha256(
        runner_generation_snapshot_bytes(
            generation_root=generation_root,
            runner_root=runner_root,
            work_folder=work_folder,
        )
    ).hexdigest()


def parse_runner_generation_snapshot_bytes(
    raw: bytes,
) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ValueError("runner generation snapshot must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("runner generation snapshot JSON invalid") from error
    if (
        type(payload) is not dict
        or set(payload)
        != {
            "schema",
            "runner_directory",
            "work_folder",
            "entries",
        }
    ):
        raise ValueError("runner generation snapshot shape invalid")
    if payload["schema"] != RUNNER_GENERATION_SNAPSHOT_SCHEMA:
        raise ValueError("runner generation snapshot schema invalid")
    if payload["runner_directory"] != "runner":
        raise ValueError("runner generation snapshot runner directory invalid")
    work_folder = payload["work_folder"]
    if (
        type(work_folder) is not str
        or not work_folder
        or work_folder in (".", "..")
        or "/" in work_folder
        or "\\" in work_folder
    ):
        raise ValueError("runner generation snapshot work folder invalid")
    entries = payload["entries"]
    if type(entries) is not list or not entries:
        raise ValueError("runner generation snapshot entries invalid")

    seen: set[str] = set()
    seen_casefold: set[str] = set()
    sort_keys: list[tuple[str, str, str]] = []
    for entry in entries:
        if type(entry) is not dict:
            raise ValueError("runner generation snapshot entry invalid")
        kind = entry.get("kind")
        path = entry.get("path")
        if type(path) is not str or not path or "\\" in path:
            raise ValueError("runner generation snapshot path invalid")
        pure = PurePosixPath(path)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or "." in pure.parts
            or not pure.parts
            or pure.parts[0] != "runner"
            or str(pure) != path
        ):
            raise ValueError("runner generation snapshot path invalid")
        if (
            len(pure.parts) >= 2
            and pure.parts[1] == work_folder
        ):
            raise ValueError("runner generation snapshot contains work folder")
        folded = path.casefold()
        if path in seen or folded in seen_casefold:
            raise ValueError("runner generation snapshot duplicate path")
        seen.add(path)
        seen_casefold.add(folded)
        sort_keys.append((folded, path, str(kind)))
        if kind == "directory":
            if set(entry) != {"kind", "path"}:
                raise ValueError(
                    "runner generation snapshot directory shape invalid"
                )
        elif kind == "file":
            if set(entry) != {"kind", "path", "sha256", "size"}:
                raise ValueError(
                    "runner generation snapshot file shape invalid"
                )
            digest = entry["sha256"]
            if (
                type(digest) is not str
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
            ):
                raise ValueError(
                    "runner generation snapshot file SHA-256 invalid"
                )
            if type(entry["size"]) is not int or entry["size"] < 0:
                raise ValueError(
                    "runner generation snapshot file size invalid"
                )
        else:
            raise ValueError("runner generation snapshot kind invalid")

    expected_sort_keys = sorted(sort_keys)
    if sort_keys != expected_sort_keys:
        raise ValueError("runner generation snapshot entries not sorted")
    if not any(
        entry.get("kind") == "directory" and entry.get("path") == "runner"
        for entry in entries
    ):
        raise ValueError("runner generation snapshot runner root missing")

    canonical = (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise ValueError("runner generation snapshot is not canonical")
    return payload
