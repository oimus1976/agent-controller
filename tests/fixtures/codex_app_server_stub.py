#!/usr/bin/env python3
"""Stub `codex app-server` for capacity_collect tests (synthetic data only).

Speaks just enough stdio JSON-RPC for the collector: answers `initialize`,
accepts the `initialized` notification, then answers
`account/rateLimits/read` — preceded by an interleaved
`account/rateLimits/updated` notification, like the real server may send —
with a fixed synthetic rate-limits result shaped like the documented
app-server protocol types. No real service is contacted.
"""

import json
import sys


RATE_LIMITS_RESULT = {
    "rateLimits": {
        "limitId": "codex",
        "limitName": None,
        "planType": "pro",
        "primary": {
            "usedPercent": 25,
            "windowDurationMins": 300,
            "resetsAt": 1795005000,
        },
        "secondary": {
            "usedPercent": 60,
            "windowDurationMins": 10080,
            "resetsAt": 1795478400,
        },
        "rateLimitReachedType": None,
    },
    "rateLimitsByLimitId": {
        "codex": {
            "limitId": "codex",
            "limitName": None,
            "planType": "pro",
            "primary": {
                "usedPercent": 25,
                "windowDurationMins": 300,
                "resetsAt": 1795005000,
            },
            "secondary": {
                "usedPercent": 60,
                "windowDurationMins": 10080,
                "resetsAt": 1795478400,
            },
            "credits": {"hasCredits": True, "unlimited": False, "balance": "10.00"},
            "rateLimitReachedType": None,
        }
    },
    "rateLimitResetCredits": {"availableCount": 2, "credits": None},
}


def _send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        message = json.loads(line)
        method = message.get("method")
        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "userAgent": "codex-app-server-stub/0",
                        "codexHome": "/stub",
                        "platformFamily": "unix",
                        "platformOs": "linux",
                    },
                }
            )
        elif method == "initialized":
            continue
        elif method == "account/rateLimits/read":
            _send(
                {
                    "jsonrpc": "2.0",
                    "method": "account/rateLimits/updated",
                    "params": {"rateLimits": None},
                }
            )
            _send(
                {"jsonrpc": "2.0", "id": message["id"], "result": RATE_LIMITS_RESULT}
            )
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
