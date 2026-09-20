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
    build_fresh_pilot_identity_freeze,
    canonical_runner_root,
    parse_pilot_identity_freeze_bytes,
    pilot_identity_freeze_bytes,
    pilot_identity_freeze_reason_codes,
    validate_pilot_workflow_runner_exclusivity,
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




    def test_workflow_runner_exclusivity_accepts_only_one_static_pilot_binding(self):
        validate_pilot_workflow_runner_exclusivity(
            {
                ".github/workflows/private-ci-windows-pilot.yml": (
                    "jobs:\n"
                    "  pilot:\n"
                    "    runs-on: private-ci-windows-pilot\n"
                ),
                ".github/workflows/project-ci.yml": (
                    "jobs:\n"
                    "  test:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - run: echo 'runs-on: private-ci-windows-pilot'\n"
                ),
            },
            trusted_workflow_path=(
                ".github/workflows/private-ci-windows-pilot.yml"
            ),
        )

    def test_workflow_runner_exclusivity_rejects_competing_or_dynamic_runner(self):
        trusted = (
            "jobs:\n"
            "  pilot:\n"
            "    runs-on: private-ci-windows-pilot\n"
        )
        bad_sources = (
            {
                ".github/workflows/private-ci-windows-pilot.yml": trusted,
                ".github/workflows/other.yml": (
                    "jobs:\n"
                    "  other:\n"
                    "    runs-on: private-ci-windows-pilot\n"
                ),
            },
            {
                ".github/workflows/private-ci-windows-pilot.yml": trusted,
                ".github/workflows/other.yml": (
                    "jobs:\n"
                    "  other:\n"
                    "    runs-on: ${{ matrix.runner }}\n"
                ),
            },
            {
                ".github/workflows/private-ci-windows-pilot.yml": (
                    "jobs:\n"
                    "  pilot:\n"
                    "    runs-on: ubuntu-latest\n"
                ),
            },
        )
        for sources in bad_sources:
            with self.subTest(sources=sources):
                with self.assertRaises(ValueError):
                    validate_pilot_workflow_runner_exclusivity(
                        sources,
                        trusted_workflow_path=(
                            ".github/workflows/private-ci-windows-pilot.yml"
                        ),
                    )


    def test_workflow_runner_exclusivity_rejects_inline_and_quoted_competitors(self):
        trusted = (
            "jobs:\n"
            "  pilot:\n"
            "    runs-on: private-ci-windows-pilot\n"
        )
        competitors = (
            (
                "jobs:\n"
                "  steal: { runs-on: private-ci-windows-pilot, steps: [] }\n"
            ),
            (
                "jobs:\n"
                "  steal:\n"
                "    'runs-on': private-ci-windows-pilot\n"
            ),
        )
        for other in competitors:
            with self.subTest(other=other):
                with self.assertRaises(ValueError):
                    validate_pilot_workflow_runner_exclusivity(
                        {
                            ".github/workflows/private-ci-windows-pilot.yml": trusted,
                            ".github/workflows/other.yml": other,
                        },
                        trusted_workflow_path=(
                            ".github/workflows/private-ci-windows-pilot.yml"
                        ),
                    )

    def test_workflow_runner_exclusivity_rejects_duplicate_dynamic_and_unsupported_jobs(self):
        trusted = (
            "jobs:\n"
            "  pilot:\n"
            "    runs-on: private-ci-windows-pilot\n"
        )
        bad = (
            (
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    runs-on: private-ci-windows-pilot\n"
            ),
            (
                "jobs:\n"
                "  test:\n"
                "    runs-on: [self-hosted, private-ci-windows-pilot]\n"
            ),
            (
                "jobs:\n"
                "  test:\n"
                "    uses: owner/repo/.github/workflows/reusable.yml@main\n"
            ),
        )
        for other in bad:
            with self.subTest(other=other):
                with self.assertRaises(ValueError):
                    validate_pilot_workflow_runner_exclusivity(
                        {
                            ".github/workflows/private-ci-windows-pilot.yml": trusted,
                            ".github/workflows/other.yml": other,
                        },
                        trusted_workflow_path=(
                            ".github/workflows/private-ci-windows-pilot.yml"
                        ),
                    )

    def test_trusted_workflow_must_have_exactly_one_static_pilot_job(self):
        multiple = (
            "jobs:\n"
            "  first:\n"
            "    runs-on: private-ci-windows-pilot\n"
            "  second:\n"
            "    runs-on: private-ci-windows-pilot\n"
        )
        with self.assertRaisesRegex(ValueError, "exactly one job"):
            validate_pilot_workflow_runner_exclusivity(
                {
                    ".github/workflows/private-ci-windows-pilot.yml": multiple,
                },
                trusted_workflow_path=(
                    ".github/workflows/private-ci-windows-pilot.yml"
                ),
            )

    def test_fresh_builder_derives_runner_and_generation_from_nonce(self):
        freeze = build_fresh_pilot_identity_freeze(
            repository="oimus1976/example-private",
            pull_request_number=4,
            target_sha="1" * 40,
            workflow_sha="2" * 40,
            workflow_path=".github/workflows/private-ci-windows-pilot.yml",
            nonce="0123456789abcdef",
            controller_main_sha="a" * 40,
            controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
        )
        self.assertEqual(freeze.runner_name, "ac-ci-0123456789abcdef")
        self.assertEqual(
            freeze.environment_generation,
            "ac-pilot-0123456789abcdef",
        )
        self.assertEqual(
            freeze.runner_root,
            canonical_runner_root("ac-pilot-0123456789abcdef"),
        )
        self.assertEqual(pilot_identity_freeze_reason_codes(freeze), ())

    def test_fresh_builder_rejects_bad_or_historical_nonce(self):
        with self.assertRaisesRegex(ValueError, "nonce"):
            build_fresh_pilot_identity_freeze(
                repository="oimus1976/example-private",
                pull_request_number=4,
                target_sha="1" * 40,
                workflow_sha="2" * 40,
                workflow_path=".github/workflows/private-ci-windows-pilot.yml",
                nonce="short",
                controller_main_sha="a" * 40,
                controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
            )

        historical_nonce = HISTORICAL_CONSUMED_RUNNER_NAME.removeprefix(
            "ac-ci-"
        )
        with self.assertRaisesRegex(ValueError, "HISTORICAL"):
            build_fresh_pilot_identity_freeze(
                repository="oimus1976/example-private",
                pull_request_number=4,
                target_sha="1" * 40,
                workflow_sha="2" * 40,
                workflow_path=".github/workflows/private-ci-windows-pilot.yml",
                nonce=historical_nonce,
                controller_main_sha="a" * 40,
                controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
            )

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
