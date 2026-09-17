from __future__ import annotations

from typing import Callable


RunnerPageFetcher = Callable[[int], object]
RUNNER_PAGE_SIZE = 100
MAX_RUNNER_PAGES = 1000


def read_all_runner_items(fetch_page: RunnerPageFetcher) -> tuple[dict[str, object], ...]:
    if not callable(fetch_page):
        raise ValueError("runner page fetcher invalid")

    items: list[dict[str, object]] = []
    seen_ids: set[int] = set()
    page = 1

    while page <= MAX_RUNNER_PAGES:
        payload = fetch_page(page)
        if type(payload) is not dict or type(payload.get("runners")) is not list:
            raise RuntimeError("GitHub runner readback shape invalid")
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
            seen_ids.add(runner_id)
            items.append(raw)

        if len(raw_items) < RUNNER_PAGE_SIZE:
            return tuple(items)
        page += 1

    raise RuntimeError("GitHub runner pagination exceeded safety bound")
