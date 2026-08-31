from __future__ import annotations

from typing import Mapping, Sequence

from agent_controller.multi_watch import WatchOnce, run_attention_watch, validate_targets
from agent_controller.watcher import watch_pr_once
from agent_controller.workstream import (
    WorkstreamBinding,
    validate_pr_workstream,
    validate_workstream_set,
)


def run_workstream_attention_watch(
    raw_targets: object,
    *,
    bindings: Sequence[WorkstreamBinding],
    watch_once: WatchOnce = watch_pr_once,
) -> tuple[dict[str, object], ...]:
    """Observe concurrent lanes only after the full binding/target set is valid.

    This is the lane-aware composition boundary over the existing multi-watch.
    It prevents configured workstream labels from becoming authority by typo or
    heuristic: every repo/PR target must be an explicit member of the named
    binding, and the active binding set must have no overlapping ownership.
    All validation happens before the first watcher call.
    """

    set_result = validate_workstream_set(bindings)
    if not set_result.valid:
        raise ValueError(set_result.reason or "WORKSTREAM_SET_INVALID")

    binding_by_id = {binding.workstream_id: binding for binding in bindings}
    targets = validate_targets(raw_targets)
    for index, target in enumerate(targets):
        workstream_id = target.get("workstream_id")
        if not isinstance(workstream_id, str) or not workstream_id:
            raise ValueError(
                f"target[{index}].workstream_id is required for workstream attention watch"
            )
        binding = binding_by_id.get(workstream_id)
        if binding is None:
            raise ValueError(f"target[{index}] references unknown workstream_id")
        validation = validate_pr_workstream(
            binding=binding,
            repo=str(target["repo"]),
            pr=int(target["pr"]),
        )
        if not validation.valid:
            raise ValueError(
                f"target[{index}] is not owned by workstream {workstream_id}: "
                f"{validation.reason}"
            )

    return run_attention_watch(raw_targets, watch_once=watch_once)
