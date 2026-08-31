from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class ParsedTextPatch:
    old_path: Optional[str]
    new_path: Optional[str]
    new_text: Optional[str]


def _path(raw: str) -> Optional[str]:
    value = raw.strip()
    if value == "/dev/null":
        return None
    if value.startswith(("a/", "b/")):
        value = value[2:]
    if not value or value.startswith("/") or "\\" in value or "\x00" in value:
        raise ValueError("PATCH_PATH_INVALID")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("PATCH_PATH_TRAVERSAL")
    return value


def _apply(base: str, body: Sequence[str]) -> str:
    source = base.splitlines(keepends=True)
    out: list[str] = []
    src = 0
    i = 0
    while i < len(body):
        match = _HUNK.match(body[i])
        if match is None:
            raise ValueError("PATCH_HUNK_HEADER_MALFORMED")
        target = max(int(match.group(1)) - 1, 0)
        if target < src or target > len(source):
            raise ValueError("PATCH_HUNK_RANGE_INVALID")
        out.extend(source[src:target])
        src = target
        i += 1
        while i < len(body) and not body[i].startswith("@@ "):
            line = body[i]
            if line.startswith("\\ No newline at end of file"):
                raise ValueError("PATCH_NO_NEWLINE_UNSUPPORTED")
            if not line or line[0] not in {" ", "+", "-"}:
                raise ValueError("PATCH_HUNK_LINE_MALFORMED")
            text = line[1:]
            if line[0] == " ":
                if src >= len(source) or source[src] != text:
                    raise ValueError("PATCH_CONTEXT_MISMATCH")
                out.append(text)
                src += 1
            elif line[0] == "-":
                if src >= len(source) or source[src] != text:
                    raise ValueError("PATCH_REMOVAL_MISMATCH")
                src += 1
            else:
                out.append(text)
            i += 1
    out.extend(source[src:])
    return "".join(out)


def parse_and_apply_text_patch(
    patch: str,
    get_base_text: Callable[[str], Optional[str]],
) -> tuple[ParsedTextPatch, ...]:
    """Parse only regular UTF-8 text git diffs; reject ambiguous/unsupported forms."""
    if not isinstance(patch, str) or not patch:
        raise ValueError("PATCH_REQUIRED")
    forbidden = ("GIT binary patch", "Binary files ", "old mode ", "new mode ", "new file mode 120000")
    if any(marker in patch for marker in forbidden):
        raise ValueError("PATCH_UNSUPPORTED_FORM")

    lines = patch.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("diff --git ")]
    if not starts:
        raise ValueError("PATCH_DIFF_HEADER_REQUIRED")
    starts.append(len(lines))
    result: list[ParsedTextPatch] = []

    for n in range(len(starts) - 1):
        block = list(lines[starts[n] : starts[n + 1]])
        old_i = next((i for i, line in enumerate(block) if line.startswith("--- ")), None)
        new_i = next((i for i, line in enumerate(block) if line.startswith("+++ ")), None)
        if old_i is None or new_i is None or new_i != old_i + 1:
            raise ValueError("PATCH_FILE_HEADERS_MALFORMED")
        old_path = _path(block[old_i][4:].rstrip("\r\n"))
        new_path = _path(block[new_i][4:].rstrip("\r\n"))
        if old_path is None and new_path is None:
            raise ValueError("PATCH_BOTH_PATHS_NULL")

        body = block[new_i + 1 :]
        while body and not body[0].startswith("@@ "):
            metadata = body.pop(0)
            if metadata.startswith(("index ", "similarity index ", "rename from ", "rename to ", "new file mode 100644", "deleted file mode 100644")):
                continue
            if metadata.strip():
                raise ValueError("PATCH_METADATA_UNSUPPORTED")
        if not body:
            raise ValueError("PATCH_HUNK_REQUIRED")

        base = "" if old_path is None else get_base_text(old_path)
        if old_path is not None and base is None:
            raise ValueError("PATCH_BASE_FILE_MISSING")
        assert base is not None
        new_text = _apply(base, body)
        result.append(ParsedTextPatch(old_path, new_path, None if new_path is None else new_text))

    # A path may appear as both old/new within one file block, but not across blocks.
    seen: set[str] = set()
    for change in result:
        local = {path for path in (change.old_path, change.new_path) if path is not None}
        if seen.intersection(local):
            raise ValueError("PATCH_PATH_COLLISION")
        seen.update(local)
    return tuple(result)


def changed_paths(changes: Sequence[ParsedTextPatch]) -> tuple[str, ...]:
    paths: list[str] = []
    for change in changes:
        for path in (change.old_path, change.new_path):
            if path is not None and path not in paths:
                paths.append(path)
    return tuple(paths)
