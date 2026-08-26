from __future__ import annotations

from dataclasses import asdict
from typing import Callable, Mapping, Sequence

from agent_controller.attention_queue import build_attention_queue
from agent_controller.watcher import watch_pr_once


WatchOnce = Callable[[str, str, int, str, Mapping[str, object] | None], Mapping[str, object]]


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

    validated: list[dict[str, object]] = []
    for index, raw in enumerate(raw_targets):
        if not isinstance(raw, Mapping):
            raise TypeError(f"target[{index}] must be a mapping")

        repo = raw.get("repo")
        pr = raw.get("pr")
        state_file = raw.get("state_file")
        allowed_paths = _validate_string_list("allowed_paths", raw.get("allowed_paths"))
        denied_paths = _validate_string_list("denied_paths", raw.get("denied_paths"))
        allow_docs_only = raw.get("allow_docs_only", False)

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

        validated.append(
            {
                "repo": repo,
                "owner": owner,
                "name": name,
                "pr": pr,
                "state_file": state_file,
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
    rejected before the first watcher call.
    """

    targets = validate_targets(raw_targets)
    observations: list[Mapping[str, object]] = []
    for target in targets:
        observations.append(
            watch_once(
                str(target["owner"]),
                str(target["name"]),
                int(target["pr"]),
                str(target["state_file"]),
                target["scope_policy"],
            )
        )

    queue = build_attention_queue(observations)
    return tuple(asdict(item) for item in queue)
