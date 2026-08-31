from __future__ import annotations

from dataclasses import asdict
import os
from typing import Callable, Mapping, Sequence

from agent_controller.attention_queue import build_attention_queue
from agent_controller.watcher import watch_pr_once


WatchOnce = Callable[[str, str, int, str, Mapping[str, object] | None], Mapping[str, object]]

_ALLOWED_TARGET_KEYS = frozenset(
    {
        "repo",
        "pr",
        "state_file",
        "allowed_paths",
        "denied_paths",
        "allow_docs_only",
        "workstream_id",
    }
)


def _validate_string_list(name: str, value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of strings")
    result = tuple(value)
    if any(not isinstance(item, str) or not item for item in result):
        raise ValueError(f"{name} entries must be nonempty strings")
    return result


def validate_targets(raw_targets: object) -> tuple[dict[str, object], ...]:
    if not isinstance(raw_targets, Sequence) or isinstance(raw_targets, (str, bytes)):
        raise TypeError("targets must be a sequence")

    raw_items = tuple(raw_targets)
    lane_mode = any(
        isinstance(raw, Mapping) and "workstream_id" in raw for raw in raw_items
    )

    validated: list[dict[str, object]] = []
    seen_targets: set[tuple[str, int]] = set()
    seen_state_files: set[str] = set()

    for index, raw in enumerate(raw_items):
        if not isinstance(raw, Mapping):
            raise TypeError(f"target[{index}] must be a mapping")

        unknown_keys = set(raw) - _ALLOWED_TARGET_KEYS
        if unknown_keys:
            names = ", ".join(sorted(str(key) for key in unknown_keys))
            raise ValueError(f"target[{index}] has unknown keys: {names}")

        repo = raw.get("repo")
        pr = raw.get("pr")
        state_file = raw.get("state_file")
        allowed_paths = _validate_string_list("allowed_paths", raw.get("allowed_paths"))
        denied_paths = _validate_string_list("denied_paths", raw.get("denied_paths"))
        allow_docs_only = raw.get("allow_docs_only", False)
        workstream_id = raw.get("workstream_id")

        if not isinstance(repo, str) or not repo or repo.count("/") != 1:
            raise ValueError(f"target[{index}].repo must be OWNER/REPO")
        owner, name = repo.split("/", 1)
        if not owner or not name:
            raise ValueError(f"target[{index}].repo must be OWNER/REPO")
        if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
            raise ValueError(f"target[{index}].pr must be a positive integer")
        if not isinstance(state_file, str) or not state_file:
            raise ValueError(f"target[{index}].state_file must be nonempty")
        if not isinstance(allow_docs_only, bool):
            raise ValueError(f"target[{index}].allow_docs_only must be bool")

        if lane_mode:
            if not isinstance(workstream_id, str) or not workstream_id:
                raise ValueError(
                    f"target[{index}].workstream_id must be nonempty when lane mode is used"
                )
        else:
            workstream_id = None

        target_identity = (repo.casefold(), pr)
        if target_identity in seen_targets:
            raise ValueError(f"target[{index}] duplicates repo/pr {repo}#{pr}")
        seen_targets.add(target_identity)

        state_identity = os.path.normcase(os.path.abspath(os.path.normpath(state_file)))
        if state_identity in seen_state_files:
            raise ValueError(f"target[{index}].state_file aliases another target")
        seen_state_files.add(state_identity)

        validated.append(
            {
                "repo": repo,
                "owner": owner,
                "name": name,
                "pr": pr,
                "state_file": state_file,
                "workstream_id": workstream_id,
                "scope_policy": {
                    "allowed_paths": list(allowed_paths) if allowed_paths is not None else None,
                    "denied_paths": list(denied_paths) if denied_paths is not None else None,
                    "allow_docs_only": allow_docs_only,
                },
            }
        )

    return tuple(validated)


def run_attention_watch(
    raw_targets: object,
    *,
    watch_once: WatchOnce = watch_pr_once,
) -> tuple[dict[str, object], ...]:
    """Validate every target first, then compose existing one-shot watchers.

    A watcher may return EVIDENCE_UNAVAILABLE for one target; that observation is
    still aggregated so other targets are not hidden. Configuration errors are
    rejected before the first watcher call. When any target opts into lane mode,
    every target must provide a Controller-owned workstream_id; provider/watch
    output cannot override that binding.
    """

    targets = validate_targets(raw_targets)
    observations: list[Mapping[str, object]] = []
    for target in targets:
        observation = dict(
            watch_once(
                str(target["owner"]),
                str(target["name"]),
                int(target["pr"]),
                str(target["state_file"]),
                target["scope_policy"],
            )
        )
        if target["workstream_id"] is not None:
            observation["workstream_id"] = target["workstream_id"]
        observations.append(observation)

    queue = build_attention_queue(observations)
    return tuple(asdict(item) for item in queue)
