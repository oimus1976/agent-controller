import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class OperatorStepGateConcurrencyTests(unittest.TestCase):
    def run_isolated(self, source: str) -> None:
        completed = subprocess.run(
            [sys.executable, "-c", textwrap.dedent(source)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )

    def test_same_prior_evidence_capability_is_consumed_atomically(self):
        self.run_isolated(
            r'''
            import hashlib
            import hmac
            import threading

            import agent_controller.operator_step_gate as gate

            evidence_bytes = b"trusted prior operator evidence\n"
            evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
            spec = gate.OperatorStepSpec(
                operation_id="issue211-runner-registration",
                step_id="register-runner",
                workstream=gate.PRIVATE_LOCAL_CI_WORKSTREAM,
                repository="owner/private-repo",
                pull_request_number=42,
                target_sha="a" * 40,
                target_host_role="owner-machine-broker",
                required_identity="c-admin",
                shell_runtime=gate.WINDOWS_POWERSHELL_51,
                effect_class=gate.OperatorEffectClass.BOUNDED_MUTATION,
                evidence_root=gate.AUTHORITATIVE_EVIDENCE_ROOT,
                transcript_filename="issue211-race.log",
                expected_success_marker="ISSUE211_RACE_PASS",
                allowed_effect_families=("RUNNER_REGISTRATION",),
                prior_evidence_requirement=gate.PriorEvidenceRequirement(
                    producer_operation_id="issue211-preflight",
                    producer_step_id="readonly-preflight",
                    evidence_sha256=evidence_sha256,
                ),
                require_parser_attestation=True,
                require_heartbeat_or_progress=False,
                require_child_exit_code=False,
                require_fail_fast=False,
            )

            evidence_key = b"E" * 32
            authority = gate._ControllerAuthority(
                ast_hmac_key=b"A" * 32,
                evidence_hmac_key=evidence_key,
            )
            message = gate.prior_evidence_auth_message(
                repository=spec.repository,
                pull_request_number=spec.pull_request_number,
                target_sha=spec.target_sha,
                producer_operation_id=spec.prior_evidence_requirement.producer_operation_id,
                producer_step_id=spec.prior_evidence_requirement.producer_step_id,
                evidence_sha256=evidence_sha256,
            )
            auth_tag = hmac.new(evidence_key, message, hashlib.sha256).hexdigest()
            capability = authority.authenticate_evidence(
                repository=spec.repository,
                pull_request_number=spec.pull_request_number,
                target_sha=spec.target_sha,
                producer_operation_id=spec.prior_evidence_requirement.producer_operation_id,
                producer_step_id=spec.prior_evidence_requirement.producer_step_id,
                evidence_bytes=evidence_bytes,
                auth_tag=auth_tag,
            )

            compare_barrier = threading.Barrier(2)
            original_binding = authority._evidence_bindings[capability.token]

            class SynchronizingBinding:
                def __ne__(self, other):
                    try:
                        compare_barrier.wait(timeout=0.5)
                    except threading.BrokenBarrierError:
                        pass
                    return original_binding != other

            authority._evidence_bindings[capability.token] = SynchronizingBinding()
            start_barrier = threading.Barrier(3)
            results = []

            def worker():
                start_barrier.wait()
                results.append(authority.claim_evidence(capability, spec=spec))

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            start_barrier.wait()
            for thread in threads:
                thread.join(timeout=5)
                assert not thread.is_alive(), "claim thread did not finish"

            assert len(results) == 2, results
            successes = [claimed for claimed, _reason in results]
            assert successes.count(True) == 1, results
            assert successes.count(False) == 1, results
            reasons = [reason for claimed, reason in results if not claimed]
            assert reasons == ["PRIOR_EVIDENCE_ALREADY_CONSUMED"], results
            '''
        )

    def test_controller_authority_configuration_is_exactly_once_under_race(self):
        self.run_isolated(
            r'''
            import threading

            import agent_controller.operator_step_gate as gate

            gate._ACTIVE_CONTROLLER_AUTHORITY = None
            constructor_barrier = threading.Barrier(2)
            real_authority = gate._ControllerAuthority

            def synchronized_authority(*, ast_hmac_key, evidence_hmac_key):
                try:
                    constructor_barrier.wait(timeout=0.5)
                except threading.BrokenBarrierError:
                    pass
                return real_authority(
                    ast_hmac_key=ast_hmac_key,
                    evidence_hmac_key=evidence_hmac_key,
                )

            gate._ControllerAuthority = synchronized_authority
            start_barrier = threading.Barrier(3)
            outcomes = []

            def worker(ast_byte, evidence_byte):
                start_barrier.wait()
                try:
                    gate.configure_controller_authority(
                        ast_hmac_key=ast_byte * 32,
                        evidence_hmac_key=evidence_byte * 32,
                    )
                except RuntimeError:
                    outcomes.append("runtime-error")
                else:
                    outcomes.append("success")

            threads = [
                threading.Thread(target=worker, args=(b"A", b"E")),
                threading.Thread(target=worker, args=(b"B", b"F")),
            ]
            for thread in threads:
                thread.start()
            start_barrier.wait()
            for thread in threads:
                thread.join(timeout=5)
                assert not thread.is_alive(), "configure thread did not finish"

            assert sorted(outcomes) == ["runtime-error", "success"], outcomes
            assert gate._ACTIVE_CONTROLLER_AUTHORITY is not None
            '''
        )


if __name__ == "__main__":
    unittest.main()
