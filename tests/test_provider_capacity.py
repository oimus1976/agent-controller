import unittest

from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
    ProviderCandidate,
    ProviderCapacityObservation,
    recommend_provider,
)


BINDING = {
    "controller_task_id": "task-168",
    "workstream_id": "efficiency-provider-capacity",
    "operation_id": "recommend-implementation-provider",
    "operation_version": "1",
}


def observation(provider, availability, *, source=CapacityObservationSource.OPERATOR_OBSERVED):
    return ProviderCapacityObservation(
        **BINDING,
        provider=provider,
        observed_at="2026-09-04T16:45:00+09:00",
        availability=availability,
        source=source,
    )


class ProviderCapacityObservationTests(unittest.TestCase):
    def test_operator_observed_is_not_promoted_to_provider_telemetry(self):
        item = observation("codex", ProviderAvailability.DEGRADED)
        self.assertFalse(item.provider_or_account_telemetry)
        self.assertEqual(item.source, CapacityObservationSource.OPERATOR_OBSERVED)

    def test_account_and_provider_sources_are_explicitly_telemetry(self):
        for source in (
            CapacityObservationSource.ACCOUNT_TELEMETRY,
            CapacityObservationSource.PROVIDER_TELEMETRY,
        ):
            with self.subTest(source=source):
                item = observation("codex", ProviderAvailability.AVAILABLE, source=source)
                self.assertTrue(item.provider_or_account_telemetry)

    def test_unknown_remains_unknown_without_fabricated_capacity(self):
        item = observation("codex", ProviderAvailability.UNKNOWN)
        self.assertIsNone(item.remaining_capacity)
        self.assertIsNone(item.capacity_unit)
        self.assertEqual(item.availability, ProviderAvailability.UNKNOWN)

    def test_quota_value_requires_unit_and_is_non_negative(self):
        with self.assertRaisesRegex(ValueError, "present together"):
            ProviderCapacityObservation(
                **BINDING,
                provider="codex",
                observed_at="2026-09-04T16:45:00+09:00",
                availability=ProviderAvailability.DEGRADED,
                source=CapacityObservationSource.OPERATOR_OBSERVED,
                remaining_capacity=9,
            )
        with self.assertRaisesRegex(ValueError, "non-negative"):
            ProviderCapacityObservation(
                **BINDING,
                provider="codex",
                observed_at="2026-09-04T16:45:00+09:00",
                availability=ProviderAvailability.DEGRADED,
                source=CapacityObservationSource.OPERATOR_OBSERVED,
                remaining_capacity=-1,
                capacity_unit="percent",
            )

    def test_timestamps_require_timezone(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            ProviderCapacityObservation(
                **BINDING,
                provider="codex",
                observed_at="2026-09-04T16:45:00",
                availability=ProviderAvailability.UNKNOWN,
                source=CapacityObservationSource.UNKNOWN,
            )


class ProviderRecommendationTests(unittest.TestCase):
    def recommend(self, candidates, observations, **kwargs):
        return recommend_provider(
            **BINDING,
            candidates=candidates,
            capacity_observations=observations,
            **kwargs,
        )

    def test_codex_exhausted_recommends_jules(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", True)],
            [
                observation("codex", ProviderAvailability.EXHAUSTED),
                observation("jules", ProviderAvailability.AVAILABLE),
            ],
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertIn("AVAILABLE_CAPACITY", result.reason_codes)
        self.assertIn(
            ("codex", "CAPACITY_EXHAUSTED"),
            [(item.provider, item.reason) for item in result.deferred],
        )

    def test_abundant_capacity_does_not_override_capability_ineligibility(self):
        result = self.recommend(
            [ProviderCandidate("codex", False), ProviderCandidate("jules", True)],
            [
                observation("codex", ProviderAvailability.AVAILABLE),
                observation("jules", ProviderAvailability.DEGRADED),
            ],
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertIn(
            ("codex", "INSUFFICIENT_CAPABILITY"),
            [(item.provider, item.reason) for item in result.deferred],
        )

    def test_unknown_capacity_is_not_zero_or_unlimited(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", True)],
            [observation("jules", ProviderAvailability.DEGRADED)],
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertEqual(result.eligible, ("jules", "codex"))
        self.assertIn("DEGRADED_CAPACITY", result.reason_codes)

    def test_reserved_independent_review_provider_is_preserved(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", True)],
            [
                observation("codex", ProviderAvailability.AVAILABLE),
                observation("jules", ProviderAvailability.AVAILABLE),
            ],
            reserved_independent_review_provider="codex",
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertIn("PRESERVE_SCARCE_REVIEW_PROVIDER", result.reason_codes)
        self.assertIn(
            ("codex", "PRESERVE_SCARCE_REVIEW_PROVIDER"),
            [(item.provider, item.reason) for item in result.deferred],
        )

    def test_reserved_provider_is_still_usable_when_it_is_only_option(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", False)],
            [observation("codex", ProviderAvailability.DEGRADED)],
            reserved_independent_review_provider="codex",
        )
        self.assertEqual(result.recommendation, "codex")
        self.assertNotIn("PRESERVE_SCARCE_REVIEW_PROVIDER", result.reason_codes)

    def test_unauthorized_paid_usage_is_deferred(self):
        result = self.recommend(
            [
                ProviderCandidate("paid-agent", True, additional_paid_usage_required=True),
                ProviderCandidate("jules", True),
            ],
            [
                observation("paid-agent", ProviderAvailability.AVAILABLE),
                observation("jules", ProviderAvailability.DEGRADED),
            ],
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertIn(
            ("paid-agent", "PAID_USAGE_NOT_AUTHORIZED"),
            [(item.provider, item.reason) for item in result.deferred],
        )

    def test_paid_usage_can_be_recommended_only_when_explicitly_authorized(self):
        result = self.recommend(
            [ProviderCandidate("paid-agent", True, additional_paid_usage_required=True)],
            [observation("paid-agent", ProviderAvailability.AVAILABLE)],
            paid_usage_authorized=True,
        )
        self.assertEqual(result.recommendation, "paid-agent")
        self.assertIn("PAID_USAGE_AUTHORIZED", result.reason_codes)

    def test_binding_mismatch_fails_closed(self):
        wrong = ProviderCapacityObservation(
            controller_task_id="other-task",
            workstream_id=BINDING["workstream_id"],
            operation_id=BINDING["operation_id"],
            operation_version=BINDING["operation_version"],
            provider="codex",
            observed_at="2026-09-04T16:45:00+09:00",
            availability=ProviderAvailability.AVAILABLE,
            source=CapacityObservationSource.OPERATOR_OBSERVED,
        )
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            self.recommend([ProviderCandidate("codex", True)], [wrong])

    def test_same_frozen_inputs_are_deterministic(self):
        candidates = [ProviderCandidate("jules", True), ProviderCandidate("codex", True)]
        observations = [
            observation("jules", ProviderAvailability.AVAILABLE),
            observation("codex", ProviderAvailability.AVAILABLE),
        ]
        first = self.recommend(candidates, observations)
        second = self.recommend(list(reversed(candidates)), list(reversed(observations)))
        self.assertEqual(first, second)
        self.assertEqual(first.recommendation, "codex")

    def test_no_eligible_provider_returns_none(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", False)],
            [observation("codex", ProviderAvailability.UNAVAILABLE)],
        )
        self.assertIsNone(result.recommendation)
        self.assertEqual(result.eligible, ())
        self.assertEqual(result.reason_codes, ())


if __name__ == "__main__":
    unittest.main()
