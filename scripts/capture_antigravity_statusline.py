from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve(strict=True).parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent_controller.antigravity_capacity_observer import write_statusline_capture


MAX_CAPTURE_BYTES = 64 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture one Antigravity custom status-line JSON payload from stdin."
    )
    parser.add_argument("--capture-root", required=True, type=Path)
    parser.add_argument("--capture-path", required=True, type=Path)
    args = parser.parse_args()

    payload = sys.stdin.read(MAX_CAPTURE_BYTES + 1)
    write_statusline_capture(
        payload,
        capture_path=args.capture_path,
        capture_root=args.capture_root,
        max_bytes=MAX_CAPTURE_BYTES,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
