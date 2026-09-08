from pathlib import Path
import tempfile
import unittest

from agent_controller.antigravity_capacity_observer import (
    observe_antigravity_capacity_from_capture,
    read_statusline_capture,
    write_statusline_capture,
)
from agent_controller.provider_capacity import ProviderAvailability


PAYLOAD = (
    '{"product":"antigravity","version":"1.1.27",'
    '"quota":{"gemini-weekly":{"remaining_fraction":0.5,'
    '"reset_time":"2026-09-14T02:00:00Z"}}}'
)


class AntigravityCapacityObserverTests(unittest.TestCase):
    def test_capture_round_trip_preserves_raw_payload_and_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "latest.json"
            capture = write_statusline_capture(
                PAYLOAD,
                capture_path=path,
                capture_root=root,
                captured_at="2026-09-09T00:00:00Z",
            )
            observed = read_statusline_capture(
                capture_path=path,
                capture_root=root,
                now="2026-09-09T00:00:30Z",
                max_age_seconds=60,
            )
            self.assertEqual(observed, capture)
            self.assertEqual(observed.payload, PAYLOAD)

    def test_observer_reuses_existing_parser_and_capture_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "latest.json"
            write_statusline_capture(
                PAYLOAD,
                capture_path=path,
                capture_root=root,
                captured_at="2026-09-09T00:00:00Z",
            )
            observations = observe_antigravity_capacity_from_capture(
                capture_path=path,
                capture_root=root,
                now="2026-09-09T00:00:30Z",
                max_age_seconds=60,
                controller_task_id="task-177",
                workstream_id="antigravity-capacity",
                operation_id="live-capture",
                operation_version="1",
            )
            self.assertEqual(len(observations), 1)
            observation = observations[0].observation
            self.assertEqual(observation.observed_at, "2026-09-09T00:00:00Z")
            self.assertEqual(observation.availability, ProviderAvailability.AVAILABLE)
            self.assertEqual(observations[0].capacity_pool, "gemini-weekly")

    def test_stale_capture_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "latest.json"
            write_statusline_capture(
                PAYLOAD,
                capture_path=path,
                capture_root=root,
                captured_at="2026-09-09T00:00:00Z",
            )
            with self.assertRaisesRegex(ValueError, "stale"):
                read_statusline_capture(
                    capture_path=path,
                    capture_root=root,
                    now="2026-09-09T00:02:00Z",
                    max_age_seconds=60,
                )

    def test_future_capture_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "latest.json"
            write_statusline_capture(
                PAYLOAD,
                capture_path=path,
                capture_root=root,
                captured_at="2026-09-09T00:01:00Z",
            )
            with self.assertRaisesRegex(ValueError, "future"):
                read_statusline_capture(
                    capture_path=path,
                    capture_root=root,
                    now="2026-09-09T00:00:00Z",
                    max_age_seconds=60,
                )

    def test_empty_malformed_and_duplicate_payloads_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "latest.json"
            cases = (
                ("", "nonempty"),
                ("{not-json", "malformed"),
                ('{"product":"antigravity","product":"other"}', "duplicate JSON key"),
            )
            for payload, message in cases:
                with self.subTest(payload=payload):
                    with self.assertRaisesRegex(ValueError, message):
                        write_statusline_capture(
                            payload,
                            capture_path=path,
                            capture_root=root,
                            captured_at="2026-09-09T00:00:00Z",
                        )

    def test_oversize_payload_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "latest.json"
            with self.assertRaisesRegex(ValueError, "size limit"):
                write_statusline_capture(
                    '"' + ("x" * 100) + '"',
                    capture_path=path,
                    capture_root=root,
                    captured_at="2026-09-09T00:00:00Z",
                    max_bytes=32,
                )

    def test_capture_path_must_be_directly_beneath_resolved_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            root = base / "capture"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            path = root / "latest.json"

            def escaping_resolver(value: str) -> str:
                candidate = Path(value)
                if candidate == path.parent:
                    return str(outside)
                return str(candidate)

            with self.assertRaisesRegex(ValueError, "directly beneath"):
                write_statusline_capture(
                    PAYLOAD,
                    capture_path=path,
                    capture_root=root,
                    captured_at="2026-09-09T00:00:00Z",
                    canonical_path_resolver=escaping_resolver,
                )

    def test_unresolvable_capture_path_fails_closed_without_lexical_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "latest.json"

            def failing_resolver(value: str) -> str:
                if Path(value) == path.parent:
                    raise OSError("unresolved reparse target")
                return value

            with self.assertRaisesRegex(ValueError, "canonical resolution failed"):
                write_statusline_capture(
                    PAYLOAD,
                    capture_path=path,
                    capture_root=root,
                    captured_at="2026-09-09T00:00:00Z",
                    canonical_path_resolver=failing_resolver,
                )


if __name__ == "__main__":
    unittest.main()
