from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath


ARCHIVE_PLAN_SCHEMA = (
    "agent-controller.private-ci-burned-evidence-archive-plan.v1"
)
ARCHIVE_MANIFEST_SCHEMA = (
    "agent-controller.private-ci-burned-evidence-archive-manifest.v1"
)
ARCHIVE_RETIREMENT_SCHEMA = (
    "agent-controller.private-ci-burned-evidence-retirement-result.v1"
)
ARCHIVE_COPIES_VERIFIED = "ARCHIVE_COPIES_VERIFIED_PENDING_RETIREMENT"
ARCHIVE_RETIREMENT_PASS = "BURNED_CANONICAL_EVIDENCE_ARCHIVED"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
HELPER_ARCHIVE_NAME_RE = re.compile(r"^issue216-burned-[0-9a-f]{16}$")

CANONICAL_RESTART_BLOCKING_FILENAMES = (
    "issue216-pilot-identity-freeze.json",
    "issue216-phase0-canonical.json",
    "issue217-live-registration-candidate.ps1",
    "issue217-live-registration-plan.json",
    "issue217-live-registration-result.json",
    "issue217-live-registration.log",
    "issue225-registration-handoff.pending.json",
    "issue225-registration-handoff.json",
    "issue225-phase4-target-environment-candidate.ps1",
    "issue225-phase4-plan.json",
    "issue225-phase4-result.json",
    "issue225-phase4-target-environment.log",
    "issue225-phase5-candidate.ps1",
    "issue225-phase5-plan.json",
    "issue225-phase5-result.json",
    "issue225-phase5-exactly-one-job.log",
)


@dataclass(frozen=True, slots=True)
class ArchiveItem:
    filename: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ArchivePlan:
    schema: str
    evidence_root: str
    controller_main_sha: str
    controller_tree: str
    python_executable: str
    python_sha256: str
    inventory_sha256: str
    archive_directory: str
    items: tuple[ArchiveItem, ...]


@dataclass(frozen=True, slots=True)
class ArchiveManifest:
    schema: str
    plan_sha256: str
    evidence_root: str
    controller_main_sha: str
    controller_tree: str
    archive_directory: str
    items: tuple[ArchiveItem, ...]
    copies_verified_at: str
    status: str


@dataclass(frozen=True, slots=True)
class ArchiveRetirementResult:
    schema: str
    plan_sha256: str
    manifest_sha256: str
    archive_directory: str
    items: tuple[ArchiveItem, ...]
    completed_at: str
    status: str


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_git_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_reparse(stat_result: os.stat_result) -> bool:
    return bool(
        getattr(stat_result, "st_file_attributes", 0)
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _require_plain_directory(path: Path, description: str) -> None:
    try:
        stat_result = path.lstat()
    except OSError as error:
        raise ValueError(f"{description} missing") from error
    if path.is_symlink() or _is_reparse(stat_result):
        raise ValueError(f"{description} is symlink or reparse point")
    if not path.is_dir():
        raise ValueError(f"{description} is not directory")


def _require_regular_nonreparse_file(path: Path, description: str) -> os.stat_result:
    try:
        stat_result = path.lstat()
    except OSError as error:
        raise ValueError(f"{description} missing") from error
    if path.is_symlink() or _is_reparse(stat_result):
        raise ValueError(f"{description} is symlink or reparse point")
    if not path.is_file():
        raise ValueError(f"{description} is not regular file")
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
        raise RuntimeError(f"archive evidence read failed: {path}") from error
    return hasher.hexdigest()


def _item_for_path(path: Path, filename: str) -> ArchiveItem:
    stat_result = _require_regular_nonreparse_file(
        path,
        f"canonical archive source {filename}",
    )
    return ArchiveItem(
        filename=filename,
        sha256=_file_sha256(path),
        size=stat_result.st_size,
    )


def _item_payload(item: ArchiveItem) -> dict[str, object]:
    return {
        "filename": item.filename,
        "sha256": item.sha256,
        "size": item.size,
    }


def _canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _validate_item(item: ArchiveItem) -> None:
    if item.filename not in CANONICAL_RESTART_BLOCKING_FILENAMES:
        raise ValueError("archive item filename is outside canonical allowlist")
    if not _valid_sha256(item.sha256):
        raise ValueError("archive item SHA-256 invalid")
    if type(item.size) is not int or item.size < 0:
        raise ValueError("archive item size invalid")


def _validate_items(items: tuple[ArchiveItem, ...]) -> None:
    if type(items) is not tuple or not items:
        raise ValueError("archive items must be non-empty tuple")
    seen: set[str] = set()
    positions = {
        name: index
        for index, name in enumerate(CANONICAL_RESTART_BLOCKING_FILENAMES)
    }
    order = []
    for item in items:
        if type(item) is not ArchiveItem:
            raise ValueError("archive item type invalid")
        _validate_item(item)
        if item.filename in seen:
            raise ValueError("archive item duplicate filename")
        seen.add(item.filename)
        order.append(positions[item.filename])
    if order != sorted(order):
        raise ValueError("archive items not in canonical allowlist order")


def _validate_python_binding(
    python_executable: object,
    python_sha256: object,
) -> None:
    if type(python_executable) is not str or not python_executable:
        raise ValueError("archive plan Python executable invalid")
    pure = PureWindowsPath(python_executable)
    if (
        not pure.is_absolute()
        or pure.suffix.casefold() != ".exe"
        or ".." in pure.parts
    ):
        raise ValueError("archive plan Python executable must be absolute exe")
    if not _valid_sha256(python_sha256):
        raise ValueError("archive plan Python SHA-256 invalid")


def _payload_items(payload: object, description: str) -> tuple[ArchiveItem, ...]:
    if type(payload) is not list:
        raise RuntimeError(f"{description} items invalid")
    parsed = []
    for item in payload:
        if (
            type(item) is not dict
            or set(item) != {"filename", "sha256", "size"}
        ):
            raise RuntimeError(f"{description} item shape invalid")
        parsed.append(
            ArchiveItem(
                filename=item["filename"],
                sha256=item["sha256"],
                size=item["size"],
            )
        )
    items = tuple(parsed)
    _validate_items(items)
    return items


def _validate_completed_helper_archive(
    evidence_root: Path,
    archive_path: Path,
) -> None:
    _require_plain_directory(archive_path, "prior helper archive")
    expected_relative = f"archive/{archive_path.name}"
    manifest_path = archive_path / "manifest.json"
    result_path = archive_path / "retirement-complete.json"
    _require_regular_nonreparse_file(
        manifest_path, "prior helper archive manifest"
    )
    _require_regular_nonreparse_file(
        result_path, "prior helper retirement result"
    )
    manifest_raw = manifest_path.read_bytes()
    result_raw = result_path.read_bytes()
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
        result = json.loads(result_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("prior helper archive JSON invalid") from error

    if type(manifest) is not dict or set(manifest) != {
        "schema",
        "plan_sha256",
        "evidence_root",
        "controller_main_sha",
        "controller_tree",
        "archive_directory",
        "items",
        "copies_verified_at",
        "status",
    }:
        raise RuntimeError("prior helper archive manifest shape invalid")
    if manifest["schema"] != ARCHIVE_MANIFEST_SCHEMA:
        raise RuntimeError("prior helper archive manifest schema invalid")
    if manifest["status"] != ARCHIVE_COPIES_VERIFIED:
        raise RuntimeError("prior helper archive manifest status invalid")
    if manifest["evidence_root"] != str(evidence_root):
        raise RuntimeError("prior helper archive evidence root mismatch")
    if manifest["archive_directory"] != expected_relative:
        raise RuntimeError("prior helper archive directory mismatch")
    if not _valid_sha256(manifest["plan_sha256"]):
        raise RuntimeError("prior helper archive plan SHA invalid")
    manifest_items = _payload_items(
        manifest["items"], "prior helper archive manifest"
    )

    if type(result) is not dict or set(result) != {
        "schema",
        "plan_sha256",
        "manifest_sha256",
        "archive_directory",
        "items",
        "completed_at",
        "status",
    }:
        raise RuntimeError("prior helper retirement result shape invalid")
    if result["schema"] != ARCHIVE_RETIREMENT_SCHEMA:
        raise RuntimeError("prior helper retirement result schema invalid")
    if result["status"] != ARCHIVE_RETIREMENT_PASS:
        raise RuntimeError("prior helper retirement result status invalid")
    if result["archive_directory"] != expected_relative:
        raise RuntimeError("prior helper retirement directory mismatch")
    if result["plan_sha256"] != manifest["plan_sha256"]:
        raise RuntimeError("prior helper plan binding mismatch")
    if result["manifest_sha256"] != _sha256_bytes(manifest_raw):
        raise RuntimeError("prior helper manifest SHA mismatch")
    result_items = _payload_items(
        result["items"], "prior helper retirement result"
    )
    if result_items != manifest_items:
        raise RuntimeError("prior helper archive item binding mismatch")

    for item in manifest_items:
        _require_item_exact(
            archive_path / item.filename,
            item,
            "prior helper archive copy",
        )


def _validate_no_incomplete_helper_archive_residue(
    evidence_root: Path,
) -> None:
    archive_parent = evidence_root / "archive"
    if not archive_parent.exists() and not archive_parent.is_symlink():
        return
    _require_plain_directory(archive_parent, "archive parent")
    try:
        children = sorted(
            archive_parent.iterdir(),
            key=lambda path: path.name.casefold(),
        )
    except OSError as error:
        raise RuntimeError("archive parent inventory read failed") from error
    for child in children:
        if HELPER_ARCHIVE_NAME_RE.fullmatch(child.name) is None:
            continue
        try:
            _validate_completed_helper_archive(evidence_root, child)
        except Exception as error:
            raise RuntimeError(
                "incomplete prior helper archive residue requires "
                f"manual recovery: {child}"
            ) from error


def _inventory_bytes(items: tuple[ArchiveItem, ...]) -> bytes:
    _validate_items(items)
    return _canonical_json_bytes(
        {
            "schema": "agent-controller.private-ci-burned-evidence-inventory.v1",
            "items": [_item_payload(item) for item in items],
        }
    )


def build_archive_plan(
    *,
    evidence_root: Path,
    controller_main_sha: str,
    controller_tree: str,
    python_executable: str,
    python_sha256: str,
) -> ArchivePlan | None:
    if not isinstance(evidence_root, Path):
        raise ValueError("evidence root must be Path")
    _require_plain_directory(evidence_root, "authoritative evidence root")
    if not _valid_git_sha(controller_main_sha):
        raise ValueError("controller main SHA invalid")
    if type(controller_tree) is not str or not controller_tree.strip():
        raise ValueError("controller tree invalid")
    _validate_python_binding(python_executable, python_sha256)
    _validate_no_incomplete_helper_archive_residue(evidence_root)

    items = []
    for filename in CANONICAL_RESTART_BLOCKING_FILENAMES:
        path = evidence_root / filename
        if path.exists() or path.is_symlink():
            items.append(_item_for_path(path, filename))
    if not items:
        return None

    frozen_items = tuple(items)
    inventory_sha = _sha256_bytes(_inventory_bytes(frozen_items))
    archive_directory = (
        "archive/issue216-burned-" + inventory_sha[:16]
    )
    archive_parent = evidence_root / "archive"
    if archive_parent.exists() or archive_parent.is_symlink():
        _require_plain_directory(archive_parent, "archive parent")
    archive_path = evidence_root / "archive" / (
        "issue216-burned-" + inventory_sha[:16]
    )
    if archive_path.exists() or archive_path.is_symlink():
        raise RuntimeError(
            "archive directory already exists; manual recovery is required"
        )
    plan = ArchivePlan(
        schema=ARCHIVE_PLAN_SCHEMA,
        evidence_root=str(evidence_root),
        controller_main_sha=controller_main_sha,
        controller_tree=controller_tree,
        python_executable=python_executable,
        python_sha256=python_sha256,
        inventory_sha256=inventory_sha,
        archive_directory=archive_directory,
        items=frozen_items,
    )
    archive_plan_bytes(plan)
    return plan


def archive_plan_bytes(plan: ArchivePlan) -> bytes:
    if type(plan) is not ArchivePlan:
        raise ValueError("archive plan type invalid")
    if plan.schema != ARCHIVE_PLAN_SCHEMA:
        raise ValueError("archive plan schema invalid")
    if type(plan.evidence_root) is not str or not plan.evidence_root:
        raise ValueError("archive plan evidence root invalid")
    if not _valid_git_sha(plan.controller_main_sha):
        raise ValueError("archive plan controller main SHA invalid")
    if type(plan.controller_tree) is not str or not plan.controller_tree:
        raise ValueError("archive plan controller tree invalid")
    _validate_python_binding(plan.python_executable, plan.python_sha256)
    _validate_items(plan.items)
    observed_inventory = _sha256_bytes(_inventory_bytes(plan.items))
    if plan.inventory_sha256 != observed_inventory:
        raise ValueError("archive plan inventory SHA-256 mismatch")
    expected_directory = (
        "archive/issue216-burned-" + observed_inventory[:16]
    )
    if plan.archive_directory != expected_directory:
        raise ValueError("archive plan directory binding invalid")
    pure = PurePosixPath(plan.archive_directory)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or "." in pure.parts
        or len(pure.parts) != 2
        or pure.parts[0] != "archive"
    ):
        raise ValueError("archive plan directory invalid")

    return _canonical_json_bytes(
        {
            "schema": plan.schema,
            "evidence_root": plan.evidence_root,
            "controller_main_sha": plan.controller_main_sha,
            "controller_tree": plan.controller_tree,
            "python_executable": plan.python_executable,
            "python_sha256": plan.python_sha256,
            "inventory_sha256": plan.inventory_sha256,
            "archive_directory": plan.archive_directory,
            "items": [_item_payload(item) for item in plan.items],
        }
    )


def archive_plan_sha256(plan: ArchivePlan) -> str:
    return _sha256_bytes(archive_plan_bytes(plan))


def parse_archive_plan_bytes(raw: bytes) -> ArchivePlan:
    if type(raw) is not bytes:
        raise ValueError("archive plan must be exact bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("archive plan JSON invalid") from error
    if type(payload) is not dict or set(payload) != {
        "schema",
        "evidence_root",
        "controller_main_sha",
        "controller_tree",
        "python_executable",
        "python_sha256",
        "inventory_sha256",
        "archive_directory",
        "items",
    }:
        raise ValueError("archive plan shape invalid")
    if type(payload["items"]) is not list:
        raise ValueError("archive plan items invalid")
    try:
        items = tuple(
            ArchiveItem(
                filename=item["filename"],
                sha256=item["sha256"],
                size=item["size"],
            )
            for item in payload["items"]
            if type(item) is dict
            and set(item) == {"filename", "sha256", "size"}
        )
    except (KeyError, TypeError) as error:
        raise ValueError("archive plan item shape invalid") from error
    if len(items) != len(payload["items"]):
        raise ValueError("archive plan item shape invalid")
    plan = ArchivePlan(
        schema=payload["schema"],
        evidence_root=payload["evidence_root"],
        controller_main_sha=payload["controller_main_sha"],
        controller_tree=payload["controller_tree"],
        python_executable=payload["python_executable"],
        python_sha256=payload["python_sha256"],
        inventory_sha256=payload["inventory_sha256"],
        archive_directory=payload["archive_directory"],
        items=items,
    )
    canonical = archive_plan_bytes(plan)
    if raw != canonical:
        raise ValueError("archive plan is not canonical")
    return plan


def _isoformat(value: datetime, description: str) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{description} must be timezone-aware")
    return value.isoformat()


def _manifest_bytes(manifest: ArchiveManifest) -> bytes:
    if manifest.schema != ARCHIVE_MANIFEST_SCHEMA:
        raise ValueError("archive manifest schema invalid")
    if not _valid_sha256(manifest.plan_sha256):
        raise ValueError("archive manifest plan SHA-256 invalid")
    _validate_items(manifest.items)
    if manifest.status != ARCHIVE_COPIES_VERIFIED:
        raise ValueError("archive manifest status invalid")
    return _canonical_json_bytes(
        {
            "schema": manifest.schema,
            "plan_sha256": manifest.plan_sha256,
            "evidence_root": manifest.evidence_root,
            "controller_main_sha": manifest.controller_main_sha,
            "controller_tree": manifest.controller_tree,
            "archive_directory": manifest.archive_directory,
            "items": [_item_payload(item) for item in manifest.items],
            "copies_verified_at": manifest.copies_verified_at,
            "status": manifest.status,
        }
    )


def _retirement_result_bytes(result: ArchiveRetirementResult) -> bytes:
    if result.schema != ARCHIVE_RETIREMENT_SCHEMA:
        raise ValueError("archive retirement result schema invalid")
    if not _valid_sha256(result.plan_sha256):
        raise ValueError("archive retirement result plan SHA invalid")
    if not _valid_sha256(result.manifest_sha256):
        raise ValueError("archive retirement result manifest SHA invalid")
    _validate_items(result.items)
    if result.status != ARCHIVE_RETIREMENT_PASS:
        raise ValueError("archive retirement status invalid")
    return _canonical_json_bytes(
        {
            "schema": result.schema,
            "plan_sha256": result.plan_sha256,
            "manifest_sha256": result.manifest_sha256,
            "archive_directory": result.archive_directory,
            "items": [_item_payload(item) for item in result.items],
            "completed_at": result.completed_at,
            "status": result.status,
        }
    )


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _copy_source_file(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination, follow_symlinks=False)


def _remove_source_file(path: Path) -> None:
    path.unlink()


def _require_item_exact(path: Path, expected: ArchiveItem, description: str) -> None:
    observed = _item_for_path(path, expected.filename)
    if observed != expected:
        raise RuntimeError(f"{description} drift: {expected.filename}")


def _verify_archive_items(
    archive_path: Path,
    items: tuple[ArchiveItem, ...],
) -> None:
    _require_plain_directory(archive_path, "archive directory")
    for item in items:
        _require_item_exact(
            archive_path / item.filename,
            item,
            "archive copy",
        )


def _verify_archive_manifest(
    manifest_path: Path,
    expected_raw: bytes,
) -> None:
    _require_regular_nonreparse_file(
        manifest_path,
        "archive manifest",
    )
    observed = manifest_path.read_bytes()
    if observed != expected_raw:
        raise RuntimeError("archive manifest changed during verification")
    if _sha256_bytes(observed) != _sha256_bytes(expected_raw):
        raise RuntimeError("archive manifest SHA-256 mismatch")


def apply_archive_plan(
    *,
    evidence_root: Path,
    plan: ArchivePlan,
    expected_plan_sha256: str,
    completed_at: datetime,
) -> ArchiveRetirementResult:
    if not _valid_sha256(expected_plan_sha256):
        raise ValueError("expected archive plan SHA-256 invalid")
    exact_plan_raw = archive_plan_bytes(plan)
    observed_plan_sha = _sha256_bytes(exact_plan_raw)
    if observed_plan_sha != expected_plan_sha256:
        raise RuntimeError("reviewed archive plan SHA-256 mismatch")
    if str(evidence_root) != plan.evidence_root:
        raise RuntimeError("archive evidence root binding drift")

    current = build_archive_plan(
        evidence_root=evidence_root,
        controller_main_sha=plan.controller_main_sha,
        controller_tree=plan.controller_tree,
        python_executable=plan.python_executable,
        python_sha256=plan.python_sha256,
    )
    if current is None or archive_plan_bytes(current) != exact_plan_raw:
        raise RuntimeError("burned canonical evidence drift before archival")

    archive_relative = PurePosixPath(plan.archive_directory)
    archive_parent = evidence_root / archive_relative.parts[0]
    archive_path = evidence_root.joinpath(*archive_relative.parts)

    if archive_parent.exists() or archive_parent.is_symlink():
        _require_plain_directory(archive_parent, "archive parent")
    else:
        archive_parent.mkdir()
        _require_plain_directory(archive_parent, "archive parent")
    if archive_path.exists() or archive_path.is_symlink():
        raise RuntimeError("archive directory already exists")
    archive_path.mkdir()
    _require_plain_directory(archive_path, "archive directory")

    for item in plan.items:
        source = evidence_root / item.filename
        _require_item_exact(source, item, "canonical archive source")
        destination = archive_path / item.filename
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("archive destination already exists")
        _copy_source_file(source, destination)

    _verify_archive_items(archive_path, plan.items)

    timestamp = _isoformat(completed_at, "archive completion time")
    manifest = ArchiveManifest(
        schema=ARCHIVE_MANIFEST_SCHEMA,
        plan_sha256=observed_plan_sha,
        evidence_root=plan.evidence_root,
        controller_main_sha=plan.controller_main_sha,
        controller_tree=plan.controller_tree,
        archive_directory=plan.archive_directory,
        items=plan.items,
        copies_verified_at=timestamp,
        status=ARCHIVE_COPIES_VERIFIED,
    )
    manifest_raw = _manifest_bytes(manifest)
    manifest_path = archive_path / "manifest.json"
    _write_exclusive(manifest_path, manifest_raw)
    _verify_archive_manifest(manifest_path, manifest_raw)

    # Revalidate every canonical source after all archive copies and the
    # manifest are verified. No source deletion is permitted before this point.
    for item in plan.items:
        _require_item_exact(
            evidence_root / item.filename,
            item,
            "canonical archive source before retirement",
        )

    for item in plan.items:
        source = evidence_root / item.filename
        _require_item_exact(
            source,
            item,
            "canonical archive source immediately before retirement",
        )
        _remove_source_file(source)

    for item in plan.items:
        source = evidence_root / item.filename
        if source.exists() or source.is_symlink():
            raise RuntimeError(
                "canonical archive source still present after retirement: "
                + item.filename
            )
    _verify_archive_items(archive_path, plan.items)
    _verify_archive_manifest(manifest_path, manifest_raw)

    result = ArchiveRetirementResult(
        schema=ARCHIVE_RETIREMENT_SCHEMA,
        plan_sha256=observed_plan_sha,
        manifest_sha256=_sha256_bytes(manifest_raw),
        archive_directory=plan.archive_directory,
        items=plan.items,
        completed_at=timestamp,
        status=ARCHIVE_RETIREMENT_PASS,
    )
    result_raw = _retirement_result_bytes(result)
    result_path = archive_path / "retirement-complete.json"
    _write_exclusive(result_path, result_raw)
    if result_path.read_bytes() != result_raw:
        raise RuntimeError("archive retirement result changed after write")
    return result
