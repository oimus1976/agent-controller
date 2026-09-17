from __future__ import annotations

from typing import Callable

from agent_controller.private_ci_live_registration import (
    FROZEN_RUNNER_LABEL,
    FROZEN_RUNNER_NAME,
)


RunnerPageFetcher = Callable[[int], object]
RUNNER_PAGE_SIZE = 100
MAX_RUNNER_PAGES = 1000


def _validated_label_names(labels: object) -> tuple[str, ...]:
    if type(labels) is not list:
        raise RuntimeError("GitHub runner labels shape invalid")
    names: list[str] = []
    for item in labels:
        if type(item) is not dict:
            raise RuntimeError("GitHub runner label item shape invalid")
        name = item.get("name")
        if type(name) is not str or not name:
            raise RuntimeError("GitHub runner label name invalid")
        names.append(name)
    if len(set(names)) != len(names):
        raise RuntimeError("GitHub runner duplicate label name")
    return tuple(names)


def _read_runner_sweep(fetch_page: RunnerPageFetcher) -> tuple[dict[str, object], ...]:
    items: list[dict[str, object]] = []
    seen_ids: set[int] = set()
    expected_total: int | None = None
    page = 1

    while page <= MAX_RUNNER_PAGES:
        payload = fetch_page(page)
        if type(payload) is not dict or type(payload.get("runners")) is not list:
            raise RuntimeError("GitHub runner readback shape invalid")

        total_count = payload.get("total_count")
        if type(total_count) is not int or total_count < 0:
            raise RuntimeError("GitHub runner total_count invalid")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise RuntimeError("GitHub runner total_count changed across pages")

        raw_items = payload["runners"]
        if len(raw_items) > RUNNER_PAGE_SIZE:
            raise RuntimeError("GitHub runner page exceeds requested page size")

        for raw in raw_items:
            if type(raw) is not dict:
                raise RuntimeError("GitHub runner item shape invalid")
            runner_id = raw.get("id")
            if type(runner_id) is not int or runner_id <= 0:
                raise RuntimeError("GitHub runner id invalid")
            if runner_id in seen_ids:
                raise RuntimeError("GitHub runner pagination duplicate id")

            name = raw.get("name")
            if type(name) is not str or not name:
                raise RuntimeError("GitHub runner name invalid")
            label_names = _validated_label_names(raw.get("labels"))
            if name == FROZEN_RUNNER_NAME and FROZEN_RUNNER_LABEL not in label_names:
                raise RuntimeError("stale eligible runner name/label collision")

            seen_ids.add(runner_id)
            items.append(raw)

        if len(items) > expected_total:
            raise RuntimeError("GitHub runner pagination exceeds total_count")
        if len(items) == expected_total:
            return tuple(items)
        if len(raw_items) < RUNNER_PAGE_SIZE:
            raise RuntimeError("GitHub runner pagination incomplete for total_count")

        page += 1

    raise RuntimeError("GitHub runner pagination exceeded safety bound")


def _runner_set_fingerprint(
    items: tuple[dict[str, object], ...],
) -> tuple[tuple[int, str, tuple[str, ...]], ...]:
    fingerprint: list[tuple[int, str, tuple[str, ...]]] = []
    for raw in items:
        runner_id = raw.get("id")
        name = raw.get("name")
        if type(runner_id) is not int or type(name) is not str:
            raise RuntimeError("GitHub runner stable-set shape invalid")
        label_names = tuple(sorted(_validated_label_names(raw.get("labels"))))
        fingerprint.append((runner_id, name, label_names))
    return tuple(sorted(fingerprint))


def read_all_runner_items(fetch_page: RunnerPageFetcher) -> tuple[dict[str, object], ...]:
    if not callable(fetch_page):
        raise ValueError("runner page fetcher invalid")

    first = _read_runner_sweep(fetch_page)
    second = _read_runner_sweep(fetch_page)
    if _runner_set_fingerprint(first) != _runner_set_fingerprint(second):
        raise RuntimeError("GitHub runner set changed across sweeps")
    return second
