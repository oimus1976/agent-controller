import math
import unittest

from agent_controller.provider_capacity import (
    CapacityObservationSource,
    ProviderAvailability,
    ProviderCandidate,
    ProviderCapacityObservation,
    ProviderDeferralReason,
    recommend_provider,
)


BINDING = {
    "controller_task_id": "task-168",
    "workstream_id": "efficiency-provider-capacity",
    "operation_id": "recommend-implementation-provider",
    "operation_version": "1",
}
DECISION_AT = "2026-09-04T18:00:00+09:00"


def observation(
    provider,
    availability,
    *,
    source=CapacityObservationSource.OPERATOR_OBSERVED,
    observed_at="2026-09-04T16:45:00+09:00",
    reset_at=None,
):
    return ProviderCapacityObservation(
        **BINDING,
        provider=provider,
        observed_at=observed_at,
        availability=availability,
        source=source,
        reset_at=reset_at,
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

    def test_quota_value_requires_unit_and_is_finite_non_negative(self):
        with self.assertRaisesRegex(ValueError, "present together"):
            ProviderCapacityObservation(
                **BINDING,
                provider="codex",
                observed_at="2026-09-04T16:45:00+09:00",
                availability=ProviderAvailability.DEGRADED,
                source=CapacityObservationSource.OPERATOR_OBSERVED,
                remaining_capacity=9,
            )
        for value in (-1, math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "finite non-negative"):
                    ProviderCapacityObservation(
                        **BINDING,
                        provider="codex",
                        observed_at="2026-09-04T16:45:00+09:00",
                        availability=ProviderAvailability.DEGRADED,
                        source=CapacityObservationSource.OPERATOR_OBSERVED,
                        remaining_capacity=value,
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
        if "max_observation_validity_seconds" not in kwargs:
            kwargs["max_observation_validity_seconds"] = 7200.0
        return recommend_provider(
            **BINDING,
            decision_at=kwargs.pop("decision_at", DECISION_AT),
            candidates=candidates,
            capacity_observations=observations,
            **kwargs,
        )

    @staticmethod
    def deferred_pairs(result):
        return [(item.provider, item.reason) for item in result.deferred]

    def test_codex_exhausted_recommends_jules(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", True)],
            [
                observation("codex", ProviderAvailability.EXHAUSTED),
                observation("jules", ProviderAvailability.AVAILABLE),
            ],
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertEqual(result.eligible, ("codex", "jules"))
        self.assertIn("AVAILABLE_CAPACITY", result.reason_codes)
        self.assertIn(
            ("codex", ProviderDeferralReason.CAPACITY_EXHAUSTED),
            self.deferred_pairs(result),
        )

    def test_exhausted_provider_is_not_recommended_for_new_review_request(self):
        review_binding = {
            "controller_task_id": "task-168-review",
            "workstream_id": "efficiency-provider-capacity",
            "operation_id": "request-independent-review",
            "operation_version": "1",
        }
        exhausted_codex = ProviderCapacityObservation(
            **review_binding,
            provider="codex",
            observed_at="2026-09-04T18:50:00+09:00",
            availability=ProviderAvailability.EXHAUSTED,
            source=CapacityObservationSource.OPERATOR_OBSERVED,
        )
        result = recommend_provider(
            **review_binding,
            decision_at="2026-09-04T19:00:00+09:00",
            candidates=[ProviderCandidate("codex", True)],
            capacity_observations=[exhausted_codex],
            max_observation_validity_seconds=7200.0,
        )
        self.assertIsNone(result.recommendation)
        self.assertEqual(result.eligible, ("codex",))
        self.assertIn(
            ("codex", ProviderDeferralReason.CAPACITY_EXHAUSTED),
            self.deferred_pairs(result),
        )

    def test_reset_boundary_requires_reobservation_and_never_auto_promotes(self):
        exhausted = observation(
            "codex",
            ProviderAvailability.EXHAUSTED,
            observed_at="2026-09-07T11:26:00+09:00",
            reset_at="2026-09-07T11:27:00+09:00",
        )
        before = self.recommend(
            [ProviderCandidate("codex", True)],
            [exhausted],
            decision_at="2026-09-07T11:26:59+09:00",
        )
        self.assertIsNone(before.recommendation)
        self.assertIn(
            ("codex", ProviderDeferralReason.CAPACITY_EXHAUSTED),
            self.deferred_pairs(before),
        )

        at_reset = self.recommend(
            [ProviderCandidate("codex", True)],
            [exhausted],
            decision_at="2026-09-07T11:27:00+09:00",
        )
        self.assertIsNone(at_reset.recommendation)
        self.assertIn(
            ("codex", ProviderDeferralReason.CAPACITY_REOBSERVATION_REQUIRED),
            self.deferred_pairs(at_reset),
        )

        refreshed = ProviderCapacityObservation(
            **BINDING,
            provider="codex",
            observed_at="2026-09-07T11:28:00+09:00",
            availability=ProviderAvailability.AVAILABLE,
            source=CapacityObservationSource.OPERATOR_OBSERVED,
        )
        after_refresh = self.recommend(
            [ProviderCandidate("codex", True)],
            [refreshed],
            decision_at="2026-09-07T11:29:00+09:00",
        )
        self.assertEqual(after_refresh.recommendation, "codex")
        self.assertIn("AVAILABLE_CAPACITY", after_refresh.reason_codes)

    def test_future_observation_fails_closed(self):
        future = observation(
            "codex",
            ProviderAvailability.AVAILABLE,
            observed_at="2026-09-04T18:00:01+09:00",
        )
        with self.assertRaisesRegex(ValueError, "newer than decision_at"):
            self.recommend([ProviderCandidate("codex", True)], [future])

    def test_abundant_capacity_does_not_override_capability_ineligibility(self):
        result = self.recommend(
            [ProviderCandidate("codex", False), ProviderCandidate("jules", True)],
            [
                observation("codex", ProviderAvailability.AVAILABLE),
                observation("jules", ProviderAvailability.DEGRADED),
            ],
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertEqual(result.eligible, ("jules",))
        self.assertIn(
            ("codex", ProviderDeferralReason.INSUFFICIENT_CAPABILITY),
            self.deferred_pairs(result),
        )

    def test_unknown_capacity_is_not_zero_or_unlimited(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", True)],
            [observation("jules", ProviderAvailability.DEGRADED)],
        )
        self.assertEqual(result.recommendation, "jules")
        self.assertEqual(result.eligible, ("codex", "jules"))
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
        self.assertEqual(result.eligible, ("codex", "jules"))
        self.assertIn("PRESERVE_SCARCE_REVIEW_PROVIDER", result.reason_codes)
        self.assertIn(
            ("codex", ProviderDeferralReason.PRESERVE_SCARCE_REVIEW_PROVIDER),
            self.deferred_pairs(result),
        )

    def test_reserved_provider_is_still_usable_when_it_is_only_option(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", False)],
            [observation("codex", ProviderAvailability.DEGRADED)],
            reserved_independent_review_provider="codex",
        )
        self.assertEqual(result.recommendation, "codex")
        self.assertEqual(result.eligible, ("codex",))
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
        self.assertEqual(result.eligible, ("jules", "paid-agent"))
        self.assertIn(
            ("paid-agent", ProviderDeferralReason.PAID_USAGE_NOT_AUTHORIZED),
            self.deferred_pairs(result),
        )

    def test_paid_usage_can_be_recommended_only_when_explicitly_authorized(self):
        result = self.recommend(
            [ProviderCandidate("paid-agent", True, additional_paid_usage_required=True)],
            [observation("paid-agent", ProviderAvailability.AVAILABLE)],
            paid_usage_authorized=True,
        )
        self.assertEqual(result.recommendation, "paid-agent")
        self.assertEqual(result.eligible, ("paid-agent",))
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
        self.assertEqual(first.eligible, ("codex", "jules"))

    def test_no_recommendable_provider_preserves_capability_eligible_set(self):
        result = self.recommend(
            [ProviderCandidate("codex", True), ProviderCandidate("jules", False)],
            [observation("codex", ProviderAvailability.UNAVAILABLE)],
        )
        self.assertIsNone(result.recommendation)
        self.assertEqual(result.eligible, ("codex",))
        self.assertIn(
            ("codex", ProviderDeferralReason.PROVIDER_UNAVAILABLE),
            self.deferred_pairs(result),
        )
        self.assertEqual(result.reason_codes, ())


    def test_stale_observation_requires_reobservation(self):
        stale = observation("codex", ProviderAvailability.AVAILABLE, observed_at="2026-09-04T16:00:00+09:00")
        result = self.recommend(
            [ProviderCandidate("codex", True)],
            [stale],
            decision_at="2026-09-04T19:00:00+09:00",
            max_observation_validity_seconds=3600.0,
        )
        self.assertIsNone(result.recommendation)
        self.assertIn(
            ("codex", ProviderDeferralReason.CAPACITY_REOBSERVATION_REQUIRED),
            self.deferred_pairs(result),
        )

    def test_stale_observation_with_far_future_reset_at_requires_reobservation(self):
        stale = observation(
            "codex",
            ProviderAvailability.AVAILABLE,
            observed_at="2026-09-04T16:00:00+09:00",
            reset_at="2026-09-05T16:00:00+09:00"
        )
        result = self.recommend(
            [ProviderCandidate("codex", True)],
            [stale],
            decision_at="2026-09-04T19:00:00+09:00",
            max_observation_validity_seconds=3600.0,
        )
        self.assertIsNone(result.recommendation)
        self.assertIn(
            ("codex", ProviderDeferralReason.CAPACITY_REOBSERVATION_REQUIRED),
            self.deferred_pairs(result),
        )

    def test_fresh_observation_is_usable(self):
        fresh = observation("codex", ProviderAvailability.AVAILABLE, observed_at="2026-09-04T18:30:00+09:00")
        result = self.recommend(
            [ProviderCandidate("codex", True)],
            [fresh],
            decision_at="2026-09-04T19:00:00+09:00",
            max_observation_validity_seconds=3600.0,
        )
        self.assertEqual(result.recommendation, "codex")
        self.assertIn("AVAILABLE_CAPACITY", result.reason_codes)


    def test_max_observation_validity_seconds_validation(self):
        invalid_values = [True, False, math.nan, math.inf, -math.inf, 0, -1, -5.5, "3600", None]
        for val in invalid_values:
            with self.subTest(value=val):
                with self.assertRaises((ValueError, TypeError)):
                    self.recommend(
                        [ProviderCandidate("codex", True)],
                        [observation("codex", ProviderAvailability.AVAILABLE)],
                        max_observation_validity_seconds=val
                    )

    def test_huge_finite_validity_does_not_overflow(self):
        result = self.recommend(
            [ProviderCandidate("codex", True)],
            [observation("codex", ProviderAvailability.AVAILABLE)],
            decision_at="2026-09-04T19:00:00+09:00",
            max_observation_validity_seconds=1e300,
        )
        self.assertEqual(result.recommendation, "codex")

if __name__ == "__main__":
    unittest.main()
