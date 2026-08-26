from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_controller.codex_live import (
    CodexOfficialSdkReadClient,
    CodexSnapshotReadClient,
    _reject_server_request,
    project_codex_thread_read,
)
from agent_controller.provider_adapters import CodexObservationAdapter
from agent_controller.provider_contract import ControllerState, ProviderOperationRef, TerminalClaim


THREAD_ID = "123e4567-e89b-12d3-a456-426614174000"
OTHER_THREAD_ID = "123e4567-e89b-12d3-a456-426614174001"


class FakeSdkClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def start(self):
        self.calls.append(("start",))

    def initialize(self):
        self.calls.append(("initialize",))
        return {"ok": True}

    def thread_read(self, thread_id, include_turns=False):
        self.calls.append(("thread_read", thread_id, include_turns))
        return self.response

    def close(self):
        self.calls.append(("close",))


class BlockingFakeSdkClient(FakeSdkClient):
    def __init__(self):
        super().__init__({})
        self.released = threading.Event()

    def thread_read(self, thread_id, include_turns=False):
        self.calls.append(("thread_read", thread_id, include_turns))
        self.released.wait(timeout=1.0)
        return self.response

    def close(self):
        self.calls.append(("close",))
        self.released.set()


class MutatingFakeSdkClient(FakeSdkClient):
    def __init__(self, response, mutate):
        super().__init__(response)
        self.mutate = mutate

    def thread_read(self, thread_id, include_turns=False):
        self.mutate()
        return super().thread_read(thread_id, include_turns)


class CodexLiveTests(unittest.TestCase):
    def operation(self):
        return ProviderOperationRef(
            provider="codex",
            provider_operation_id="thr_123",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )

    def snapshot_operation(self):
        return ProviderOperationRef(
            provider="codex",
            provider_operation_id=THREAD_ID,
            provider_url=None,
            controller_task_id="task-snapshot",
            operation_id="op-snapshot",
        )

    def disposable_home(self):
        return str(Path(tempfile.gettempdir()).resolve() / "agent-controller-codex-test")

    def completed_response(self, thread_id="thr_123"):
        return {
            "thread": {
                "id": thread_id,
                "status": {"type": "idle"},
                "turns": [{"id": "turn-1", "status": "completed"}],
            }
        }

    def make_rollout(self, source_home: Path, thread_id=THREAD_ID, *, compressed=False):
        sessions = source_home / "sessions" / "2026" / "08" / "27"
        sessions.mkdir(parents=True, exist_ok=True)
        suffix = ".jsonl.zst" if compressed else ".jsonl"
        rollout = sessions / f"rollout-2026-08-27T00-00-00-{thread_id}{suffix}"
        rollout.write_bytes(b'{"type":"session_meta"}\n')
        return rollout

    def test_active_thread_projects_to_running(self):
        raw = project_codex_thread_read(
            "thr_123",
            {"thread": {"id": "thr_123", "status": {"type": "active"}, "turns": []}},
        )
        self.assertEqual("running", raw["status"])

    def test_completed_latest_turn_projects_to_success_claim(self):
        fake = FakeSdkClient(self.completed_response())
        seen = []
        codex_home = self.disposable_home()
        client = CodexOfficialSdkReadClient(
            codex_home=codex_home,
            sdk_factory=lambda codex_bin, home: seen.append((codex_bin, home)) or fake,
            codex_bin="C:/Tools/codex.exe",
        )
        adapter = CodexObservationAdapter(client=client, observed_at=lambda: "2026-08-27T00:00:00Z")

        observation = adapter.observe(self.operation())

        self.assertEqual(ControllerState.ARTIFACT_READY, observation.mapped_state)
        self.assertEqual(TerminalClaim.SUCCESS, observation.terminal_claim)
        self.assertEqual([("C:/Tools/codex.exe", codex_home)], seen)
        self.assertEqual(
            [
                ("start",),
                ("initialize",),
                ("thread_read", "thr_123", True),
                ("close",),
            ],
            fake.calls,
        )

    def test_unknown_thread_status_cannot_promote_historical_completed_turn(self):
        raw = project_codex_thread_read(
            "thr_123",
            {
                "thread": {
                    "id": "thr_123",
                    "status": {"type": "futureStatus"},
                    "turns": [{"id": "turn-1", "status": "completed"}],
                }
            },
        )
        self.assertEqual("unknown", raw["status"])
        self.assertNotIn("result", raw)

    def test_failed_or_interrupted_latest_turn_blocks(self):
        for turn_status in ("failed", "interrupted"):
            with self.subTest(turn_status=turn_status):
                raw = project_codex_thread_read(
                    "thr_123",
                    {
                        "thread": {
                            "id": "thr_123",
                            "status": {"type": "idle"},
                            "turns": [{"status": turn_status}],
                        }
                    },
                )
                self.assertEqual("failed", raw["status"])
                self.assertEqual("failure", raw["result"])

    def test_idle_without_turn_evidence_remains_uncertain(self):
        fake = FakeSdkClient(
            {"thread": {"id": "thr_123", "status": {"type": "idle"}, "turns": []}}
        )
        client = CodexOfficialSdkReadClient(
            codex_home=self.disposable_home(),
            sdk_factory=lambda _codex_bin, _home: fake,
        )
        adapter = CodexObservationAdapter(client=client, observed_at=lambda: "2026-08-27T00:00:00Z")

        observation = adapter.observe(self.operation())

        self.assertEqual(ControllerState.UNCERTAIN, observation.mapped_state)
        self.assertEqual("CODEX_STATE_UNKNOWN", observation.uncertainty_reason)

    def test_mismatched_thread_identity_fails_closed(self):
        raw = project_codex_thread_read(
            "thr_123",
            {"thread": {"id": "thr_other", "status": {"type": "active"}, "turns": []}},
        )
        self.assertEqual("unknown", raw["status"])

    def test_wrong_provider_is_rejected_before_sdk_use(self):
        factory_calls = []
        client = CodexOfficialSdkReadClient(
            codex_home=self.disposable_home(),
            sdk_factory=lambda codex_bin, home: factory_calls.append((codex_bin, home))
            or FakeSdkClient({}),
        )
        operation = ProviderOperationRef(
            provider="jules",
            provider_operation_id="thr_123",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )

        with self.assertRaises(ValueError):
            client.get_operation_raw(operation)
        self.assertEqual([], factory_calls)

    def test_unexpected_server_request_is_rejected_not_approved(self):
        for method in (
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
            "item/permissions/requestApproval",
        ):
            with self.subTest(method=method):
                with self.assertRaisesRegex(RuntimeError, "read-only observation"):
                    _reject_server_request(method, {})

    def test_timeout_closes_provider_client_and_fails_closed(self):
        fake = BlockingFakeSdkClient()
        client = CodexOfficialSdkReadClient(
            codex_home=self.disposable_home(),
            sdk_factory=lambda _codex_bin, _home: fake,
            timeout_seconds=0.01,
        )

        with self.assertRaisesRegex(TimeoutError, "thread/read exceeded"):
            client.get_operation_raw(self.operation())

        self.assertIn(("close",), fake.calls)

    def test_low_level_reader_requires_explicit_absolute_codex_home(self):
        with self.assertRaises(ValueError):
            CodexOfficialSdkReadClient(codex_home="")
        with self.assertRaises(ValueError):
            CodexOfficialSdkReadClient(codex_home="relative/path")
        with self.assertRaises(ValueError):
            CodexOfficialSdkReadClient(codex_home=self.disposable_home(), codex_bin="")
        with self.assertRaises(ValueError):
            CodexOfficialSdkReadClient(codex_home=self.disposable_home(), timeout_seconds=0)

    def test_snapshot_observer_copies_only_target_rollout_and_never_uses_source_as_sdk_home(self):
        with tempfile.TemporaryDirectory() as source_dir:
            source_home = Path(source_dir).resolve()
            target_rollout = self.make_rollout(source_home)
            unrelated_rollout = self.make_rollout(source_home, OTHER_THREAD_ID)
            source_db = source_home / "state_5.sqlite"
            source_db.write_bytes(b"must-not-be-copied")
            original_target = target_rollout.read_bytes()
            seen = []
            fake = FakeSdkClient(self.completed_response(THREAD_ID))

            def factory(codex_bin, sdk_home):
                sdk_home_path = Path(sdk_home).resolve()
                self.assertNotEqual(source_home, sdk_home_path)
                copied_target = sdk_home_path / target_rollout.relative_to(source_home)
                self.assertTrue(copied_target.is_file())
                self.assertEqual(original_target, copied_target.read_bytes())
                self.assertFalse((sdk_home_path / unrelated_rollout.relative_to(source_home)).exists())
                self.assertFalse((sdk_home_path / source_db.relative_to(source_home)).exists())
                seen.append((codex_bin, sdk_home_path))
                return fake

            client = CodexSnapshotReadClient(
                source_codex_home=str(source_home),
                sdk_factory=factory,
            )
            raw = client.get_operation_raw(self.snapshot_operation())

            self.assertEqual("done", raw["status"])
            self.assertEqual(original_target, target_rollout.read_bytes())
            self.assertEqual(1, len(seen))
            self.assertFalse(seen[0][1].exists())

    def test_snapshot_parent_inside_source_is_rejected_before_temp_creation(self):
        with tempfile.TemporaryDirectory() as source_dir:
            source_home = Path(source_dir).resolve()
            self.make_rollout(source_home)
            descendant = source_home / "snapshot-parent"
            descendant.mkdir()
            factory_calls = []

            for parent in (source_home, descendant):
                with self.subTest(parent=parent):
                    before = {path.name for path in parent.iterdir()}
                    client = CodexSnapshotReadClient(
                        source_codex_home=str(source_home),
                        snapshot_parent=str(parent),
                        sdk_factory=lambda codex_bin, home: factory_calls.append(
                            (codex_bin, home)
                        )
                        or FakeSdkClient({}),
                    )
                    with self.assertRaisesRegex(RuntimeError, "outside source_codex_home"):
                        client.get_operation_raw(self.snapshot_operation())
                    self.assertEqual(before, {path.name for path in parent.iterdir()})

            self.assertEqual([], factory_calls)

    def test_default_temp_resolving_inside_source_is_rejected_before_temp_creation(self):
        with tempfile.TemporaryDirectory() as source_dir:
            source_home = Path(source_dir).resolve()
            self.make_rollout(source_home)
            fake_default_temp = source_home / "default-temp"
            fake_default_temp.mkdir()
            before = list(fake_default_temp.iterdir())
            factory_calls = []
            client = CodexSnapshotReadClient(
                source_codex_home=str(source_home),
                sdk_factory=lambda codex_bin, home: factory_calls.append((codex_bin, home))
                or FakeSdkClient({}),
            )

            with patch(
                "agent_controller.codex_live.tempfile.gettempdir",
                return_value=str(fake_default_temp),
            ):
                with self.assertRaisesRegex(RuntimeError, "outside source_codex_home"):
                    client.get_operation_raw(self.snapshot_operation())

            self.assertEqual(before, list(fake_default_temp.iterdir()))
            self.assertEqual([], factory_calls)

    def test_snapshot_parent_symlink_into_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir).resolve()
            source_home = root / "source"
            source_home.mkdir()
            self.make_rollout(source_home)
            descendant = source_home / "snapshot-parent"
            descendant.mkdir()
            symlink_parent = root / "snapshot-link"
            try:
                symlink_parent.symlink_to(descendant, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink unavailable on this platform: {exc}")

            factory_calls = []
            client = CodexSnapshotReadClient(
                source_codex_home=str(source_home),
                snapshot_parent=str(symlink_parent),
                sdk_factory=lambda codex_bin, home: factory_calls.append((codex_bin, home))
                or FakeSdkClient({}),
            )

            with self.assertRaisesRegex(RuntimeError, "outside source_codex_home"):
                client.get_operation_raw(self.snapshot_operation())
            self.assertEqual([], factory_calls)

    def test_snapshot_observer_supports_compressed_rollout_representation(self):
        with tempfile.TemporaryDirectory() as source_dir:
            source_home = Path(source_dir).resolve()
            target_rollout = self.make_rollout(source_home, compressed=True)
            fake = FakeSdkClient(self.completed_response(THREAD_ID))

            def factory(_codex_bin, sdk_home):
                copied_target = Path(sdk_home) / target_rollout.relative_to(source_home)
                self.assertTrue(copied_target.is_file())
                return fake

            client = CodexSnapshotReadClient(
                source_codex_home=str(source_home),
                sdk_factory=factory,
            )
            raw = client.get_operation_raw(self.snapshot_operation())
            self.assertEqual("done", raw["status"])

    def test_snapshot_observer_rejects_ambiguous_rollout_before_sdk_start(self):
        with tempfile.TemporaryDirectory() as source_dir:
            source_home = Path(source_dir).resolve()
            self.make_rollout(source_home)
            self.make_rollout(source_home, compressed=True)
            factory_calls = []
            client = CodexSnapshotReadClient(
                source_codex_home=str(source_home),
                sdk_factory=lambda codex_bin, home: factory_calls.append((codex_bin, home))
                or FakeSdkClient({}),
            )

            with self.assertRaisesRegex(RuntimeError, "Ambiguous Codex rollout evidence"):
                client.get_operation_raw(self.snapshot_operation())
            self.assertEqual([], factory_calls)

    def test_snapshot_observer_rejects_missing_or_noncanonical_thread_before_sdk_start(self):
        with tempfile.TemporaryDirectory() as source_dir:
            source_home = Path(source_dir).resolve()
            factory_calls = []
            client = CodexSnapshotReadClient(
                source_codex_home=str(source_home),
                sdk_factory=lambda codex_bin, home: factory_calls.append((codex_bin, home))
                or FakeSdkClient({}),
            )

            with self.assertRaises(FileNotFoundError):
                client.get_operation_raw(self.snapshot_operation())

            invalid_operation = ProviderOperationRef(
                provider="codex",
                provider_operation_id=THREAD_ID.upper(),
                provider_url=None,
                controller_task_id="task-invalid",
                operation_id="op-invalid",
            )
            with self.assertRaisesRegex(ValueError, "canonical lowercase UUID"):
                client.get_operation_raw(invalid_operation)
            self.assertEqual([], factory_calls)

    def test_snapshot_observer_fails_closed_if_source_changes_during_observation(self):
        with tempfile.TemporaryDirectory() as source_dir:
            source_home = Path(source_dir).resolve()
            target_rollout = self.make_rollout(source_home)

            def mutate_source():
                with target_rollout.open("ab") as handle:
                    handle.write(b'{"type":"late-write"}\n')

            fake = MutatingFakeSdkClient(
                self.completed_response(THREAD_ID),
                mutate=mutate_source,
            )
            client = CodexSnapshotReadClient(
                source_codex_home=str(source_home),
                sdk_factory=lambda _codex_bin, _home: fake,
            )

            with self.assertRaisesRegex(RuntimeError, "source rollout changed during observation"):
                client.get_operation_raw(self.snapshot_operation())


if __name__ == "__main__":
    unittest.main()
