#!/usr/bin/env python3
"""Hanging stub `codex app-server` for capacity_collect timeout tests.

Accepts the process spawn but never answers any JSON-RPC message, so the
collector's timeout path can be exercised without a real service.
"""

import time


def main():
    time.sleep(3600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
