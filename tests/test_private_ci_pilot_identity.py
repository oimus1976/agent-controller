import json
import unittest
from dataclasses import replace

from agent_controller.private_ci_pilot_identity import (
    HISTORICAL_CONSUMED_ENVIRONMENT_GENERATION,
    HISTORICAL_CONSUMED_RUNNER_NAME,
    PILOT_IDENTITY_FREEZE_SCHEMA,
    PRIVATE_CI_BROKER_IDENTITY,
    PRIVATE_CI_HOST,
    PRIVATE_CI_RUNNER_LABEL,
    PRIVATE_CI_TARGET_IDENTITY,
    PRIVATE_CI_WORK_FOLDER,
    PrivateCiPilotIdentityFreeze,
    canonical_runner_root,
    parse_pilot_identity_freeze_bytes,
    pilot_identity_freeze_bytes,
    pilot_identity_freeze_reason_codes,
)


def valid_freeze():
    generation = "ac-pilot-0123456789abcdef"
    return PrivateCiPilotIdentityFreeze(
        schema=PILOT_IDENTITY_FREEZE_SCHEMA,
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        workflow_sha="2" * 40,
        workflow_path=".github/workflows/private-ci-windows-pilot.yml",
        runner_name="ac-ci-0123456789abcdef",
        runner_label=PRIVATE_CI_RUNNER_LABEL,
        environment_generation=generation,
        runner_root=canonical_runner_root(generation),
        work_folder=PRIVATE_CI_WORK_FOLDER,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
        host=PRIVATE_CI_HOST,
        broker_identity=PRIVATE_CI_BROKER_IDENTITY,
        target_identity=PRIVATE_CI_TARGET_IDENTITY,
    )


class PrivateCiPilotIdentityFreezeTests(unittest.TestCase):
    def test_valid_freeze_roundtrips_canonically(self):
        freeze = valid_freeze()
        raw = pilot_identity_freeze_bytes(freeze)

        self.assertEqual(parse_pilot_identity_freeze_bytes(raw), freeze)
        self.assertEqual(pilot_identity_freeze_reason_codes(freeze), ())

    def test_historical_consumed_identity_is_explicitly_rejected(self):
        historical_runner = replace(
            valid_freeze(),
            runner_name=HISTORICAL_CONSUMED_RUNNER_NAME,
        )
        self.assertIn(
            "PILOT_FREEZE_HISTORICAL_RUNNER_REUSE",
            pilot_identity_freeze_reason_codes(historical_runner),
        )

        historical_generation = HISTORICAL_CONSUMED_ENVIRONMENT_GENERATION
        historical = replace(
            valid_freeze(),
            environment_generation=historical_generation,
            runner_root=canonical_runner_root(historical_generation),
        )
        self.assertIn(
            "PILOT_FREEZE_HISTORICAL_GENERATION_REUSE",
            pilot_identity_freeze_reason_codes(historical),
        )

    def test_runner_root_must_be_derived_from_generation(self):
        freeze = replace(
            valid_freeze(),
            runner_root=r"C:\ProgramData\agent-controller\private-ci\other\runner",
        )
        self.assertIn(
            "PILOT_FREEZE_RUNNER_ROOT_NOT_CANONICAL",
            pilot_identity_freeze_reason_codes(freeze),
        )

    def test_noncanonical_json_is_rejected(self):
        payload = json.loads(
            pilot_identity_freeze_bytes(valid_freeze()).decode("utf-8")
        )
        raw = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            parse_pilot_identity_freeze_bytes(raw)


if __name__ == "__main__":
    unittest.main()
