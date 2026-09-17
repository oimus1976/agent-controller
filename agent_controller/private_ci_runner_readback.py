from __future__ import annotations

from typing import Callable

from agent_controller.private_ci_live_registration import (
    FROZEN_RUNNER_LABEL,
    FROZEN_RUNNER_NAME,
)


RunnerPageFetcher = Callable[[int], object]
RUNNER_PAGE_SIZE = 100
MAX_RUNNER_PAGES = 1000


def read_all_runner_items(fetch_page: RunnerPageFetcher) -> tuple[dict[str, object], ...]:
    if not callable(fetch_page):
        raise ValueError("runner page fetcher invalid")

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

            if raw.get("name") == FROZEN_RUNNER_NAME:
                labels = raw.get("labels")
                if type(labels) is not list:
                    raise RuntimeError("GitHub runner labels shape invalid")
                label_names = {
                    item.get("name")
                    for item in labels
                    if type(item) is dict and type(item.get("name")) is str
                }
                if FROZEN_RUNNER_LABEL not in label_names:
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
