import json
import unittest
from dataclasses import replace

from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding


def binding():
    generation = "ac-pilot-0123456789abcdef"
    return PrivateCiPilotBinding(
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-225",
        workflow_sha="2" * 40,
        workflow_path=".github/workflows/private-ci-windows-pilot.yml",
        runner_id=23,
        runner_name="ac-ci-0123456789abcdef",
        runner_label="private-ci-windows-pilot",
        environment_generation=generation,
        runner_root=(
            r"C:\ProgramData\agent-controller\private-ci"
            rf"\{generation}\runner"
        ),
        work_folder="_work",
        host="WOBBUFFET",
        broker_identity=r"WOBBUFFET\c-admin",
        target_identity="ac-runner",
    )


def run_payload(**overrides):
    payload = {
        "id": 9001,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_sha": binding().workflow_sha,
        "head_branch": "main",
        "path": ".github/workflows/private-ci-windows-pilot.yml",
        "actor": {"login": "oimus1976"},
        "triggering_actor": {"login": "oimus1976"},
        "run_attempt": 1,
    }
    payload.update(overrides)
    return payload


def job_payload(**overrides):
    payload = {
        "id": 7001,
        "name": "exact-head-windows-pilot",
        "status": "completed",
        "conclusion": "success",
        "runner_id": binding().runner_id,
        "runner_name": binding().runner_name,
        "labels": [binding().runner_label],
        "steps": [
            {
                "name": "Set up job",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Validate frozen workflow, runner, and PR binding",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Checkout exact frozen head without persisted credentials",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Verify exact checkout metadata only",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "name": "Complete job",
                "status": "completed",
                "conclusion": "success",
            },
        ],
    }
    payload.update(overrides)
    return payload


def result_evidence():
    m = __import__(
        "agent_controller.private_ci_phase5_result",
        fromlist=["Phase5ResultEvidence"],
    )
    return m.Phase5ResultEvidence(
        schema=m.PHASE5_RESULT_SCHEMA,
        binding=binding(),
        phase5_plan_sha256="1" * 64,
        phase4_result_sha256="2" * 64,
        human_approval_sha256="3" * 64,
        phase5_consumption_sha256="4" * 64,
        candidate_sha256="5" * 64,
        workflow_run_id=9001,
        workflow_run_attempt=1,
        job_id=7001,
        runner_id=binding().runner_id,
        runner_name=binding().runner_name,
        runner_label=binding().runner_label,
        runner_process_id=8123,
        runner_process_owner=r"WOBBUFFET\ac-runner",
        runner_child_exit_code=0,
        runner_stdout_sha256="6" * 64,
        runner_stderr_sha256="7" * 64,
        status=m.PHASE5_RESULT_STATUS,
        completed_at="2026-09-19T14:00:00+00:00",
    )


class PrivateCiPhase5ReadbackRedTests(unittest.TestCase):
    def module(self):
        from agent_controller import private_ci_phase5_result
        return private_ci_phase5_result


    def test_phase5_result_roundtrips_canonically(self):
        m = self.module()
        evidence = result_evidence()
        raw = m.phase5_result_bytes(evidence)
        self.assertEqual(m.parse_phase5_result_bytes(raw), evidence)

        payload = json.loads(raw.decode("utf-8"))
        noncanonical = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            m.parse_phase5_result_bytes(noncanonical)

    def test_phase5_result_cannot_claim_pass_with_child_or_binding_drift(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, "CHILD_EXIT"):
            m.phase5_result_bytes(
                replace(result_evidence(), runner_child_exit_code=1)
            )
        with self.assertRaisesRegex(ValueError, "RUNNER_ID_MISMATCH"):
            m.phase5_result_bytes(
                replace(result_evidence(), runner_id=24)
            )
        with self.assertRaisesRegex(ValueError, "RUN_ATTEMPT"):
            m.phase5_result_bytes(
                replace(result_evidence(), workflow_run_attempt=2)
            )
        with self.assertRaisesRegex(ValueError, "PROCESS_OWNER"):
            m.phase5_result_bytes(
                replace(
                    result_evidence(),
                    runner_process_owner=r"WOBBUFFET\c-admin",
                )
            )

    def test_workflow_path_api_ref_suffix_is_accepted_only_for_main(self):
        m = self.module()
        observed = m.validate_phase5_run_job_readback(
            run_payload=run_payload(
                path=(
                    ".github/workflows/private-ci-windows-pilot.yml"
                    "@refs/heads/main"
                )
            ),
            jobs_payload={"total_count": 1, "jobs": [job_payload()]},
            binding=binding(),
            expected_workflow_run_id=9001,
        )
        self.assertEqual(observed.workflow_run_id, 9001)

        with self.assertRaises(ValueError):
            m.validate_phase5_run_job_readback(
                run_payload=run_payload(
                    path=(
                        ".github/workflows/private-ci-windows-pilot.yml"
                        "@refs/heads/other"
                    )
                ),
                jobs_payload={"total_count": 1, "jobs": [job_payload()]},
                binding=binding(),
                expected_workflow_run_id=9001,
            )

    def test_exact_run_and_job_pass(self):
        m = self.module()
        observed = m.validate_phase5_run_job_readback(
            run_payload=run_payload(),
            jobs_payload={"total_count": 1, "jobs": [job_payload()]},
            binding=binding(),
            expected_workflow_run_id=9001,
        )
        self.assertEqual(observed.workflow_run_id, 9001)
        self.assertEqual(observed.job_id, 7001)
        self.assertEqual(observed.runner_id, binding().runner_id)
        self.assertEqual(observed.runner_name, binding().runner_name)
        self.assertEqual(observed.run_attempt, 1)

    def test_run_identity_drift_is_rejected(self):
        m = self.module()
        cases = (
            {"id": 9002},
            {"event": "pull_request"},
            {"status": "in_progress"},
            {"conclusion": "failure"},
            {"head_sha": "f" * 40},
            {"head_branch": "other"},
            {"path": ".github/workflows/other.yml"},
            {"actor": {"login": "someone-else"}},
            {"triggering_actor": {"login": "someone-else"}},
            {"run_attempt": 2},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    m.validate_phase5_run_job_readback(
                        run_payload=run_payload(**changes),
                        jobs_payload={"total_count": 1, "jobs": [job_payload()]},
                        binding=binding(),
                        expected_workflow_run_id=9001,
                    )

    def test_job_identity_or_cardinality_drift_is_rejected(self):
        m = self.module()
        bad_jobs = (
            {"total_count": 0, "jobs": []},
            {"total_count": 2, "jobs": [job_payload(), job_payload(id=7002)]},
            {"total_count": 1, "jobs": [job_payload(name="other")]},
            {"total_count": 1, "jobs": [job_payload(status="in_progress")]},
            {"total_count": 1, "jobs": [job_payload(conclusion="failure")]},
            {"total_count": 1, "jobs": [job_payload(runner_id=24)]},
            {"total_count": 1, "jobs": [job_payload(runner_name="other")]},
            {"total_count": 1, "jobs": [job_payload(labels=["self-hosted"])]},
        )
        for jobs in bad_jobs:
            with self.subTest(jobs=jobs):
                with self.assertRaises(ValueError):
                    m.validate_phase5_run_job_readback(
                        run_payload=run_payload(),
                        jobs_payload=jobs,
                        binding=binding(),
                        expected_workflow_run_id=9001,
                    )

    def test_each_expected_job_step_must_succeed_exactly_once(self):
        m = self.module()
        expected_steps = (
            "Validate frozen workflow, runner, and PR binding",
            "Checkout exact frozen head without persisted credentials",
            "Verify exact checkout metadata only",
        )
        for step_name in expected_steps:
            with self.subTest(step=step_name):
                steps = job_payload()["steps"]
                changed = []
                for step in steps:
                    if step["name"] == step_name:
                        changed.append({**step, "conclusion": "failure"})
                    else:
                        changed.append(step)
                with self.assertRaises(ValueError):
                    m.validate_phase5_run_job_readback(
                        run_payload=run_payload(),
                        jobs_payload={
                            "total_count": 1,
                            "jobs": [job_payload(steps=changed)],
                        },
                        binding=binding(),
                        expected_workflow_run_id=9001,
                    )

        duplicate = list(job_payload()["steps"])
        duplicate.append(
            {
                "name": expected_steps[0],
                "status": "completed",
                "conclusion": "success",
            }
        )
        with self.assertRaises(ValueError):
            m.validate_phase5_run_job_readback(
                run_payload=run_payload(),
                jobs_payload={
                    "total_count": 1,
                    "jobs": [job_payload(steps=duplicate)],
                },
                binding=binding(),
                expected_workflow_run_id=9001,
            )


if __name__ == "__main__":
    unittest.main()
