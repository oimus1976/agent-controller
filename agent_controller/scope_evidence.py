from __future__ import annotations

from typing import Any, Mapping, Sequence


def normalize_github_scope_files(files: Sequence[Any]) -> list[dict[str, Any]] | None:
    """Validate GitHub file facts and expose both sides of renames to scope policy.

    The existing scope evaluator consumes ``filename`` and ``changes``. GitHub
    represents a rename with the destination in ``filename`` and the source in
    ``previous_filename``. Callers must normalize before evaluating scope so a
    denied/out-of-scope source cannot disappear behind an allowed destination.

    ``None`` means the evidence is malformed and must fail closed.
    """

    if isinstance(files, (str, bytes)):
        return None

    normalized: list[dict[str, Any]] = []
    for item in files:
        if not isinstance(item, Mapping):
            return None

        filename = item.get("filename")
        changes = item.get("changes")
        if not isinstance(filename, str) or not filename:
            return None
        if isinstance(changes, bool) or not isinstance(changes, int) or changes < 0:
            return None

        normalized.append({"filename": filename, "changes": changes})

        if "previous_filename" in item:
            previous_filename = item.get("previous_filename")
            if not isinstance(previous_filename, str) or not previous_filename:
                return None
            normalized.append({"filename": previous_filename, "changes": changes})

    return normalized
