import json
from pathlib import Path
import re
import unittest

from agent_controller.antigravity_capacity import parse_antigravity_statusline_capacity
from agent_controller.capacity_dashboard_export import (
    dashboard_document,
    pool_observation_to_dashboard_record,
    pool_observations_to_dashboard_records,
)
from agent_controller.claude_code_capacity import parse_claude_code_statusline_capacity
from agent_controller.codex_capacity import parse_codex_rate_limits_capacity
from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
    ProviderCapacityObservation,
)
from agent_controller.provider_capacity_pool import ProviderCapacityPoolObservation


FIXTURES = Path(__file__).parent / "fixtures"
BINDING = {
    "controller_task_id": "task-capacity-dashboard-export",
    "workstream_id": "ai-usage-dashboard",
    "operation_id": "capacity-collect",
    "operation_version": "1",
    "observed_at": "2026-11-18T00:42:00.000Z",
}

# The exact field sets of life-dashboard's AiUsageObservation / SourceMetadata
# (client/src/lib/ai-usage-types.ts). The dashboard validator rejects any
# record carrying fields outside these sets.
RECORD_FIELDS = {
    "id",
    "provider",
    "capacity_pool",
    "capacity_kind",
    "availability",
    "observation_source",
    "remaining_fraction",
    "capacity_unit",
    "reset_at",
    "observed_at",
    "provenance",
    "source",
}
SOURCE_FIELDS = {
    "source_kind",
    "provenance",
    "schema_version",
    "data_status",
    "privacy_class",
    "pushed_at",
    "last_verified_at",
}
EXACT_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def fixture_pools():
    claude = parse_claude_code_statusline_capacity(
        (FIXTURES / "claude_code_statusline_rate_limits_synthetic.json").read_text(
            encoding="utf-8"
        ),
        **BINDING,
    )
    codex = parse_codex_rate_limits_capacity(
        (FIXTURES / "codex_app_server_rate_limits_synthetic.json").read_text(
            encoding="utf-8"
        ),
        **BINDING,
    )
    antigravity = parse_antigravity_statusline_capacity(
        (FIXTURES / "antigravity_statusline_quota.json").read_text(encoding="utf-8"),
        **BINDING,
    )
    return claude, codex, antigravity


def hand_built_pool(**observation_kwargs):
    fields = {
        "controller_task_id": "task-capacity-dashboard-export",
        "workstream_id": "ai-usage-dashboard",
        "operation_id": "capacity-collect",
        "operation_version": "1",
        "provider": "codex",
        "observed_at": "2026-11-18T00:42:00.000Z",
        "availability": ProviderAvailability.UNKNOWN,
        "source": CapacityObservationSource.UNKNOWN,
        "remaining_capacity": None,
        "capacity_unit": None,
        "reset_at": None,
    }
    fields.update(observation_kwargs)
    return ProviderCapacityPoolObservation(
        capacity_pool="codex-five-hour",
        observation=ProviderCapacityObservation(**fields),
        provenance="hand-built/test",
    )


class DashboardExportTests(unittest.TestCase):
    def test_document_shape_matches_dashboard_contract(self):
        claude, codex, antigravity = fixture_pools()
        records = pool_observations_to_dashboard_records(claude + codex + antigravity)
        document = dashboard_document(records)

        self.assertEqual(set(document), {"version", "document_kind", "observations"})
        self.assertEqual(document["version"], "1.0")
        self.assertEqual(document["document_kind"], "ai-usage-observations")
        # Pools are never aggregated: 2 Claude Code + 3 Codex + 2 Antigravity.
        self.assertEqual(len(document["observations"]), 7)

    def test_records_carry_exact_dashboard_fields(self):
        claude, codex, antigravity = fixture_pools()
        records = pool_observations_to_dashboard_records(claude + codex + antigravity)

        for record in records:
            self.assertEqual(set(record), RECORD_FIELDS)
            self.assertEqual(set(record["source"]), SOURCE_FIELDS)
            self.assertEqual(record["capacity_kind"], "window")
            self.assertEqual(record["source"]["source_kind"], "manual")
            self.assertEqual(record["source"]["schema_version"], "1.0")
            self.assertEqual(record["source"]["data_status"], "confirmed")
            self.assertEqual(record["source"]["privacy_class"], "private-low")
            self.assertIsNone(record["source"]["pushed_at"])
            self.assertEqual(
                record["source"]["last_verified_at"], record["observed_at"]
            )
            self.assertRegex(record["observed_at"], EXACT_TIMESTAMP)
            if record["reset_at"] is not None:
                self.assertRegex(record["reset_at"], EXACT_TIMESTAMP)
            # Controller binding fields never leak into the export.
            self.assertNotIn("controller_task_id", record)
            self.assertNotIn("workstream_id", record)

    def test_pool_ids_and_provenance_are_preserved_verbatim(self):
        claude, codex, antigravity = fixture_pools()
        records = pool_observations_to_dashboard_records(claude + codex + antigravity)
        by_id = {record["id"]: record for record in records}

        self.assertEqual(
            set(by_id),
            {
                "ai-usage-claude-code-five-hour",
                "ai-usage-claude-code-weekly",
                "ai-usage-codex-codex-five-hour",
                "ai-usage-codex-codex-weekly",
                "ai-usage-codex-codex_other-window-60m",
                "ai-usage-antigravity-claude-five-hour",
                "ai-usage-antigravity-gemini-weekly",
            },
        )
        five_hour = by_id["ai-usage-claude-code-five-hour"]
        self.assertEqual(five_hour["remaining_fraction"], 0.75)
        self.assertEqual(five_hour["capacity_unit"], "fraction")
        self.assertEqual(five_hour["reset_at"], "2026-11-18T12:00:00.000Z")
        self.assertEqual(
            five_hour["provenance"], "claude-code-statusline/2.1.999-fixture"
        )
        self.assertEqual(
            by_id["ai-usage-codex-codex-five-hour"]["provenance"],
            "codex-app-server/account/rateLimits/read",
        )
        self.assertEqual(
            by_id["ai-usage-antigravity-gemini-weekly"]["provenance"],
            "antigravity-cli-statusline/1.1.27",
        )

    def test_exhausted_zero_fraction_is_preserved(self):
        _, _, antigravity = fixture_pools()
        records = pool_observations_to_dashboard_records(antigravity)
        exhausted = [
            record for record in records if record["capacity_pool"] == "claude-five-hour"
        ]
        self.assertEqual(len(exhausted), 1)
        self.assertEqual(exhausted[0]["availability"], "EXHAUSTED")
        self.assertEqual(exhausted[0]["remaining_fraction"], 0.0)
        self.assertEqual(exhausted[0]["reset_at"], "2026-09-08T08:00:00.000Z")

    def test_unknown_observation_exports_null_fraction_and_unit(self):
        record = pool_observation_to_dashboard_record(hand_built_pool())
        self.assertEqual(record["availability"], "UNKNOWN")
        self.assertIsNone(record["remaining_fraction"])
        self.assertIsNone(record["capacity_unit"])
        self.assertIsNone(record["reset_at"])

    def test_unknown_availability_with_fraction_is_rejected(self):
        pool = hand_built_pool(
            remaining_capacity=0.5,
            capacity_unit="fraction",
        )
        with self.assertRaises(ValueError):
            pool_observation_to_dashboard_record(pool)

    def test_zero_fraction_without_exhausted_is_rejected(self):
        pool = hand_built_pool(
            availability=ProviderAvailability.AVAILABLE,
            source=CapacityObservationSource.PROVIDER_TELEMETRY,
            remaining_capacity=0.0,
            capacity_unit="fraction",
        )
        with self.assertRaises(ValueError):
            pool_observation_to_dashboard_record(pool)

    def test_unknown_provider_is_rejected(self):
        pool = hand_built_pool(provider="someone-else")
        with self.assertRaises(ValueError):
            pool_observation_to_dashboard_record(pool)

    def test_non_fraction_unit_is_rejected(self):
        pool = hand_built_pool(
            availability=ProviderAvailability.AVAILABLE,
            source=CapacityObservationSource.PROVIDER_TELEMETRY,
            remaining_capacity=0.5,
            capacity_unit="tokens",
        )
        with self.assertRaises(ValueError):
            pool_observation_to_dashboard_record(pool)

    def test_duplicate_records_are_rejected(self):
        claude, _, _ = fixture_pools()
        with self.assertRaises(ValueError):
            pool_observations_to_dashboard_records(claude + claude)
        records = pool_observations_to_dashboard_records(claude)
        with self.assertRaises(ValueError):
            dashboard_document(records + records)

    def test_document_observation_limit_is_enforced(self):
        records = [
            {
                "id": f"ai-usage-codex-pool-{index}",
            }
            for index in range(201)
        ]
        with self.assertRaises(ValueError):
            dashboard_document(records)


if __name__ == "__main__":
    unittest.main()
