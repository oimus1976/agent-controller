import unittest

from agent_controller.codex_live import CodexOfficialSdkReadClient, project_codex_thread_read
from agent_controller.provider_adapters import CodexObservationAdapter
from agent_controller.provider_contract import ControllerState, ProviderOperationRef, TerminalClaim


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


class CodexLiveTests(unittest.TestCase):
    def operation(self):
        return ProviderOperationRef(
            provider="codex",
            provider_operation_id="thr_123",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )

    def test_active_thread_projects_to_running(self):
        raw = project_codex_thread_read(
            "thr_123",
            {"thread": {"id": "thr_123", "status": {"type": "active"}, "turns": []}},
        )
        self.assertEqual("running", raw["status"])

    def test_completed_latest_turn_projects_to_success_claim(self):
        fake = FakeSdkClient(
            {
                "thread": {
                    "id": "thr_123",
                    "status": {"type": "idle"},
                    "turns": [{"id": "turn-1", "status": "completed"}],
                }
            }
        )
        client = CodexOfficialSdkReadClient(sdk_factory=lambda: fake)
        adapter = CodexObservationAdapter(client=client, observed_at=lambda: "2026-08-27T00:00:00Z")

        observation = adapter.observe(self.operation())

        self.assertEqual(ControllerState.ARTIFACT_READY, observation.mapped_state)
        self.assertEqual(TerminalClaim.SUCCESS, observation.terminal_claim)
        self.assertEqual(
            [
                ("start",),
                ("initialize",),
                ("thread_read", "thr_123", True),
                ("close",),
            ],
            fake.calls,
        )

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
        client = CodexOfficialSdkReadClient(sdk_factory=lambda: fake)
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
        fake = FakeSdkClient({})
        client = CodexOfficialSdkReadClient(sdk_factory=lambda: fake)
        operation = ProviderOperationRef(
            provider="jules",
            provider_operation_id="thr_123",
            provider_url=None,
            controller_task_id="task-1",
            operation_id="op-1",
        )

        with self.assertRaises(ValueError):
            client.get_operation_raw(operation)
        self.assertEqual([], fake.calls)


if __name__ == "__main__":
    unittest.main()
