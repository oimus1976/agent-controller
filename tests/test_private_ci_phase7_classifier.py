import hashlib
import hmac
import inspect
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from agent_controller.operator_step_gate import (
    ResultPublicationCapability,
    authenticate_result_publication,
    configure_controller_authority,
    result_publication_auth_message,
)
from agent_controller.private_ci_phase4_contract import PrivateCiPilotBinding
from agent_controller.private_ci_phase5_result import (
    PHASE5_RESULT_SCHEMA,
    PHASE5_RESULT_STATUS,
    Phase5ResultEvidence,
    phase5_result_bytes,
)


AST_KEY = b"A" * 32
EVIDENCE_KEY = b"E" * 32


def setUpModule():
    try:
        configure_controller_authority(
            ast_hmac_key=AST_KEY,
            evidence_hmac_key=EVIDENCE_KEY,
        )
    except RuntimeError:
        pass


def protected_acl(*, untrusted_mutator: bool = False):
    rules = [
        {
            "sid": "S-1-5-18",
            "access_type": "Allow",
            "inherited": False,
            "can_mutate": True,
        },
        {
            "sid": "S-1-5-32-544",
            "access_type": "Allow",
            "inherited": False,
            "can_mutate": True,
        },
    ]
    if untrusted_mutator:
        rules.append({
            "sid": "S-1-5-32-545",
            "access_type": "Allow",
            "inherited": False,
            "can_mutate": True,
        })
    return {
        "protected": True,
        "owner_sid": "S-1-5-32-544",
        "rules": rules,
    }


def publication_capability(
    *,
    phase: int,
    result_bytes: bytes,
    upstream_sha256: str,
):
    result_sha256 = hashlib.sha256(result_bytes).hexdigest()
    message = result_publication_auth_message(
        phase=phase,
        result_sha256=result_sha256,
        upstream_sha256=upstream_sha256,
    )
    auth_tag = hmac.new(
        EVIDENCE_KEY,
        message,
        hashlib.sha256,
    ).hexdigest()
    return authenticate_result_publication(
        phase=phase,
        result_bytes=result_bytes,
        upstream_sha256=upstream_sha256,
        auth_tag=auth_tag,
    )


def binding(*, runner_name="ac-ci-0123456789abcdef"):
    generation = "ac-pilot-0123456789abcdef"
    return PrivateCiPilotBinding(
        repository="oimus1976/example-private",
        pull_request_number=4,
        target_sha="1" * 40,
        controller_main_sha="a" * 40,
        controller_tree=r"C:\Users\c-admin\agent-controller-pilot-230",
        workflow_sha="2" * 40,
        workflow_path=".github/workflows/private-ci-windows-pilot.yml",
        runner_id=23,
        runner_name=runner_name,
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


def phase5_evidence(*, pilot_binding=None):
    b = pilot_binding or binding()
    return Phase5ResultEvidence(
        schema=PHASE5_RESULT_SCHEMA,
        binding=b,
        phase5_plan_sha256="1" * 64,
        phase4_result_sha256="2" * 64,
        human_approval_sha256="3" * 64,
        phase5_consumption_sha256="4" * 64,
        candidate_sha256="5" * 64,
        workflow_run_id=9001,
        workflow_run_attempt=1,
        job_id=7001,
        runner_id=b.runner_id,
        runner_name=b.runner_name,
        runner_label=b.runner_label,
        runner_process_id=8123,
        runner_process_owner=r"WOBBUFFET\ac-runner",
        runner_child_exit_code=0,
        security_probe_sha256="6" * 64,
        security_probe_result_sha256="7" * 64,
        security_probe_stdout_sha256="8" * 64,
        security_probe_stderr_sha256="9" * 64,
        runner_stdout_sha256="a" * 64,
        runner_stderr_sha256="b" * 64,
        status=PHASE5_RESULT_STATUS,
        completed_at="2026-09-22T12:00:00+00:00",
    )


class PrivateCiPhase7ClassifierRedTests(unittest.TestCase):
    def result_module(self):
        from agent_controller import private_ci_phase7_result
        return private_ci_phase7_result

    def phase6_module(self):
        from agent_controller import private_ci_phase6_result
        return private_ci_phase6_result

    def classifier_module(self):
        from agent_controller import private_ci_final_classifier
        return private_ci_final_classifier

    def clean_observation(self):
        m = self.result_module()
        return m.ZeroResidualObservation(
            runner_match_count=0,
            active_targetable_run_count=0,
            generation_exists=False,
            workspace_exists=False,
            process_count=0,
            service_count=0,
            task_count=0,
            credential_lifecycle_proven=True,
            target_binding_exact=True,
            github_readback_complete=True,
            local_readback_complete=True,
        )

    def phase6_evidence(
        self,
        *,
        pilot_binding=None,
        phase5_result_sha256="d" * 64,
    ):
        m = self.phase6_module()
        b = pilot_binding or binding()
        return m.Phase6CleanupResultEvidence(
            schema=m.PHASE6_RESULT_SCHEMA,
            binding=b,
            phase6_plan_sha256="c" * 64,
            phase5_result_sha256=phase5_result_sha256,
            human_approval_sha256="e" * 64,
            phase6_consumption_sha256="f" * 64,
            runner_deregistered=True,
            generation_removed=True,
            status=m.PHASE6_RESULT_STATUS,
            completed_at="2026-09-22T12:30:00+00:00",
        )

    def phase7_evidence(
        self,
        *,
        pilot_binding=None,
        phase6_result_sha256="3" * 64,
    ):
        m = self.result_module()
        return m.build_phase7_zero_residual_result(
            binding=pilot_binding or binding(),
            phase6_result_sha256=phase6_result_sha256,
            observation=self.clean_observation(),
        )

    def test_zero_residual_result_requires_every_postcondition(self):
        m = self.result_module()
        evidence = self.phase7_evidence()
        self.assertEqual(evidence.status, m.PHASE7_ZERO_RESIDUAL_STATUS)

        failures = (
            ("runner_match_count", 1, "RUNNER_RESIDUAL"),
            ("active_targetable_run_count", 1, "ACTIVE_JOB_RESIDUAL"),
            ("generation_exists", True, "GENERATION_RESIDUAL"),
            ("workspace_exists", True, "WORKSPACE_RESIDUAL"),
            ("process_count", 1, "PROCESS_RESIDUAL"),
            ("service_count", 1, "SERVICE_RESIDUAL"),
            ("task_count", 1, "TASK_RESIDUAL"),
            ("credential_lifecycle_proven", False, "CREDENTIAL_LIFECYCLE"),
            ("target_binding_exact", False, "TARGET_BINDING_DRIFT"),
            ("github_readback_complete", False, "GITHUB_READBACK"),
            ("local_readback_complete", False, "LOCAL_READBACK"),
        )
        for field, value, reason in failures:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, reason):
                    m.build_phase7_zero_residual_result(
                        binding=binding(),
                        phase6_result_sha256="3" * 64,
                        observation=replace(
                            self.clean_observation(),
                            **{field: value},
                        ),
                    )

    def test_zero_residual_evidence_roundtrips_canonically(self):
        m = self.result_module()
        evidence = self.phase7_evidence()
        raw = m.phase7_result_bytes(evidence)
        self.assertEqual(m.parse_phase7_result_bytes(raw), evidence)

    def test_phase6_result_roundtrips_and_requires_cleanup_pass(self):
        m = self.phase6_module()
        evidence = self.phase6_evidence()
        raw = m.phase6_result_bytes(evidence)
        self.assertEqual(m.parse_phase6_result_bytes(raw), evidence)

        with self.assertRaisesRegex(ValueError, "RUNNER_DEREGISTRATION"):
            m.phase6_result_bytes(
                replace(evidence, runner_deregistered=False)
            )
        with self.assertRaisesRegex(ValueError, "GENERATION_REMOVAL"):
            m.phase6_result_bytes(
                replace(evidence, generation_removed=False)
            )

    def test_final_classifier_owns_durable_single_use_publication(self):
        classifier = self.classifier_module()
        function = classifier.classify_final_private_ci_pilot
        self.assertEqual(
            tuple(inspect.signature(function).parameters),
            (
                "phase5_result_bytes",
                "phase6_result_bytes",
                "phase7_result_bytes",
            ),
        )
        source = inspect.getsource(function)
        self.assertNotIn("already_published", source)
        self.assertIn("consume_final_pass_publication", source)

    def test_final_classifier_requires_authoritative_phase6_phase7_provenance(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()

        self.assertTrue(hasattr(phase6, "validate_phase6_result_authority"))
        self.assertTrue(hasattr(phase7, "validate_phase7_result_authority"))

        source = inspect.getsource(
            classifier.classify_final_private_ci_pilot
        )
        self.assertIn("validate_phase6_result_authority", source)
        self.assertIn("validate_phase7_result_authority", source)

    def test_synthetic_phase6_phase7_bytes_without_authority_are_rejected(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()


        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = phase6.phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase7_raw = phase7.phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            from agent_controller import private_ci_result_authority

            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                Path(temporary_directory),
            ), patch(
                "agent_controller.private_ci_result_authority.read_consumption_acl_state",
                return_value=protected_acl(),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "authority marker missing or unreadable",
                ):
                    classifier.classify_final_private_ci_pilot(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=phase7_raw,
                    )

    def test_forged_phase6_phase7_results_cannot_self_publish_authority(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()


        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_evidence = self.phase6_evidence(
            phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
        )
        phase6_raw = phase6.phase6_result_bytes(phase6_evidence)
        phase7_raw = phase7.phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            from agent_controller import private_ci_final_publication
            from agent_controller import private_ci_result_authority

            authority_root = Path(temporary_directory)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ):
                with self.assertRaises((TypeError, ValueError)):
                    private_ci_result_authority.publish_phase6_result_authority(
                        phase6_raw,
                        phase6_consumption_sha256=(
                            phase6_evidence.phase6_consumption_sha256
                        ),
                    )
                    private_ci_result_authority.publish_phase7_result_authority(
                        phase7_raw,
                        phase6_result_sha256=hashlib.sha256(
                            phase6_raw
                        ).hexdigest(),
                    )
                    classifier.classify_final_private_ci_pilot(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=phase7_raw,
                    )

    def test_forged_result_publication_capability_is_rejected(self):
        phase6 = self.phase6_module()
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        evidence = self.phase6_evidence(
            phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
        )
        phase6_raw = phase6.phase6_result_bytes(evidence)

        with tempfile.TemporaryDirectory() as temporary_directory:
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                Path(temporary_directory),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "RESULT_PUBLICATION_UNKNOWN",
                ):
                    private_ci_result_authority.publish_phase6_result_authority(
                        phase6_raw,
                        phase6_consumption_sha256=(
                            evidence.phase6_consumption_sha256
                        ),
                        publication_capability=ResultPublicationCapability(
                            token="0" * 64
                        ),
                    )

    def test_authority_marker_primitives_require_protected_root_security(self):
        from agent_controller import private_ci_final_publication
        from agent_controller import private_ci_result_authority

        for module, functions in (
            (
                private_ci_result_authority,
                (
                    "_publish",
                    "_parse_and_validate",
                ),
            ),
            (
                private_ci_final_publication,
                ("consume_final_pass_publication",),
            ),
        ):
            with self.subTest(module=module.__name__):
                self.assertTrue(
                    hasattr(module, "_validate_authority_root_security"),
                    module.__name__,
                )
                validator_source = inspect.getsource(
                    module._validate_authority_root_security
                )
                self.assertIn(
                    "validate_consumption_container_acl_state",
                    validator_source,
                )
                self.assertIn("ReparsePoint", validator_source)
                for function_name in functions:
                    source = inspect.getsource(
                        getattr(module, function_name)
                    )
                    self.assertIn(
                        "_validate_authority_root_security",
                        source,
                    )

        self.assertTrue(
            hasattr(
                private_ci_result_authority,
                "_validate_authority_marker_security",
            )
        )
        marker_source = inspect.getsource(
            private_ci_result_authority._validate_authority_marker_security
        )
        self.assertIn("validate_consumption_acl_state", marker_source)
        self.assertIn("ReparsePoint", marker_source)
        self.assertIn(
            "_validate_authority_marker_security",
            inspect.getsource(
                private_ci_result_authority._parse_and_validate
            ),
        )

    def test_final_pass_requires_exact_phase5_phase6_phase7_success_chain(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()


        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = phase6.phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase7_raw = phase7.phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            from agent_controller import private_ci_final_publication
            from agent_controller import private_ci_result_authority

            authority_root = Path(temporary_directory)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ), patch.object(
                private_ci_final_publication,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ):
                phase6_consumption_sha256 = (
                    self.phase6_evidence(
                        phase5_result_sha256=hashlib.sha256(
                            phase5_raw
                        ).hexdigest()
                    ).phase6_consumption_sha256
                )
                private_ci_result_authority.publish_phase6_result_authority(
                    phase6_raw,
                    phase6_consumption_sha256=phase6_consumption_sha256,
                    publication_capability=publication_capability(
                        phase=6,
                        result_bytes=phase6_raw,
                        upstream_sha256=phase6_consumption_sha256,
                    ),
                )
                phase6_result_sha256 = hashlib.sha256(
                    phase6_raw
                ).hexdigest()
                private_ci_result_authority.publish_phase7_result_authority(
                    phase7_raw,
                    phase6_result_sha256=phase6_result_sha256,
                    publication_capability=publication_capability(
                        phase=7,
                        result_bytes=phase7_raw,
                        upstream_sha256=phase6_result_sha256,
                    ),
                )

                result = classifier.classify_final_private_ci_pilot(
                    phase5_result_bytes=phase5_raw,
                    phase6_result_bytes=phase6_raw,
                    phase7_result_bytes=phase7_raw,
                )
                self.assertEqual(result, "SELF_HOSTED_PRIVATE_CI_PASS")

                with self.assertRaisesRegex(
                    ValueError,
                    "already published",
                ):
                    classifier.classify_final_private_ci_pilot(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=phase7_raw,
                    )

    def test_final_classifier_rejects_cross_pilot_evidence(self):
        phase6 = self.phase6_module()
        phase7 = self.result_module()
        classifier = self.classifier_module()
        other = binding(runner_name="ac-ci-fedcba9876543210")


        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = phase6.phase6_result_bytes(
            self.phase6_evidence(
                pilot_binding=other,
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest(),
            )
        )
        phase7_raw = phase7.phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            from agent_controller import private_ci_result_authority

            authority_root = Path(temporary_directory)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ):
                phase6_consumption_sha256 = (
                    self.phase6_evidence(
                        pilot_binding=other,
                        phase5_result_sha256=hashlib.sha256(
                            phase5_raw
                        ).hexdigest(),
                    ).phase6_consumption_sha256
                )
                private_ci_result_authority.publish_phase6_result_authority(
                    phase6_raw,
                    phase6_consumption_sha256=phase6_consumption_sha256,
                    publication_capability=publication_capability(
                        phase=6,
                        result_bytes=phase6_raw,
                        upstream_sha256=phase6_consumption_sha256,
                    ),
                )
                phase6_result_sha256 = hashlib.sha256(
                    phase6_raw
                ).hexdigest()
                private_ci_result_authority.publish_phase7_result_authority(
                    phase7_raw,
                    phase6_result_sha256=phase6_result_sha256,
                    publication_capability=publication_capability(
                        phase=7,
                        result_bytes=phase7_raw,
                        upstream_sha256=phase6_result_sha256,
                    ),
                )
                with self.assertRaisesRegex(ValueError, "binding mismatch"):
                    classifier.classify_final_private_ci_pilot(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=phase7_raw,
                    )

    def test_omitted_or_failing_acl_readback_fails_closed(self):
        from agent_controller import private_ci_final_publication
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase6_consumption_sha = self.phase6_evidence().phase6_consumption_sha256

        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                side_effect=ValueError("ACL readback unavailable"),
            ), patch.object(
                private_ci_final_publication,
                "read_consumption_acl_state",
                side_effect=ValueError("ACL readback unavailable"),
            ):
                # 1. Publication fails closed when ACL readback fails
                with self.assertRaisesRegex(ValueError, "ACL readback unavailable"):
                    private_ci_result_authority.publish_phase6_result_authority(
                        phase6_raw,
                        phase6_consumption_sha256=phase6_consumption_sha,
                        publication_capability=publication_capability(
                            phase=6,
                            result_bytes=phase6_raw,
                            upstream_sha256=phase6_consumption_sha,
                        ),
                    )

                # 2. Validation fails closed when ACL readback fails
                with self.assertRaisesRegex(ValueError, "ACL readback unavailable"):
                    private_ci_result_authority.validate_phase6_result_authority_marker(
                        phase6_raw,
                        phase6_consumption_sha256=phase6_consumption_sha,
                    )

                # 3. Final PASS publication fails closed when ACL readback fails
                with self.assertRaisesRegex(ValueError, "ACL readback unavailable"):
                    private_ci_final_publication.consume_final_pass_publication(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=b"{}",
                    )

    def test_forged_caller_acl_payload_cannot_substitute_for_actual_readback(self):
        from agent_controller import private_ci_final_publication
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase6_consumption_sha = self.phase6_evidence().phase6_consumption_sha256

        # Callers cannot supply an ACL dictionary argument to bypass readback
        with self.assertRaises(TypeError):
            private_ci_result_authority.publish_phase6_result_authority(
                phase6_raw,
                phase6_consumption_sha256=phase6_consumption_sha,
                publication_capability=publication_capability(
                    phase=6,
                    result_bytes=phase6_raw,
                    upstream_sha256=phase6_consumption_sha,
                ),
                authority_container_acl_state=protected_acl(),
            )

        with self.assertRaises(TypeError):
            private_ci_final_publication.consume_final_pass_publication(
                phase5_result_bytes=phase5_raw,
                phase6_result_bytes=phase6_raw,
                phase7_result_bytes=b"{}",
                authority_container_acl_state=protected_acl(),
            )

        with self.assertRaises(TypeError):
            private_ci_result_authority.validate_phase6_result_authority_marker(
                phase6_raw,
                phase6_consumption_sha256=phase6_consumption_sha,
                marker_acl_state=protected_acl(),
            )

    def test_unprotected_real_root_blocks_publication_and_validation(self):
        if os.name != "nt":
            self.skipTest("real Windows ACL readback regression")

        from agent_controller import private_ci_final_publication
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase6_consumption_sha = self.phase6_evidence().phase6_consumption_sha256

        # Use an actual real Windows temporary directory without mocking read_consumption_acl_state
        with tempfile.TemporaryDirectory() as temp_dir:
            real_root = Path(temp_dir)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                real_root,
            ), patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                real_root,
            ):
                # Real Windows filesystem ACL readback of temp_dir has protected=False
                with self.assertRaisesRegex(
                    ValueError,
                    "consumption authority container ACL invalid",
                ):
                    private_ci_result_authority.publish_phase6_result_authority(
                        phase6_raw,
                        phase6_consumption_sha256=phase6_consumption_sha,
                        publication_capability=publication_capability(
                            phase=6,
                            result_bytes=phase6_raw,
                            upstream_sha256=phase6_consumption_sha,
                        ),
                    )

                with self.assertRaisesRegex(
                    ValueError,
                    "consumption authority container ACL invalid",
                ):
                    private_ci_final_publication.consume_final_pass_publication(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=b"{}",
                    )

    def test_untrusted_owner_or_mutating_principal_real_root_blocks(self):
        from agent_controller import private_ci_final_publication
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase6_consumption_sha = self.phase6_evidence().phase6_consumption_sha256

        # 1. Untrusted owner
        bad_owner_acl = protected_acl()
        bad_owner_acl["owner_sid"] = "S-1-5-21-4121720210-324024630-1488705960-1001"

        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                return_value=bad_owner_acl,
            ), patch.object(
                private_ci_final_publication,
                "read_consumption_acl_state",
                return_value=bad_owner_acl,
            ):
                with self.assertRaisesRegex(ValueError, "approval ACL owner is not trusted"):
                    private_ci_result_authority.publish_phase6_result_authority(
                        phase6_raw,
                        phase6_consumption_sha256=phase6_consumption_sha,
                        publication_capability=publication_capability(
                            phase=6,
                            result_bytes=phase6_raw,
                            upstream_sha256=phase6_consumption_sha,
                        ),
                    )

                with self.assertRaisesRegex(ValueError, "approval ACL owner is not trusted"):
                    private_ci_final_publication.consume_final_pass_publication(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=b"{}",
                    )

        # 2. Untrusted mutator
        untrusted_mutator_acl = protected_acl(untrusted_mutator=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                return_value=untrusted_mutator_acl,
            ):
                with self.assertRaisesRegex(ValueError, "grants mutation to untrusted principal"):
                    private_ci_result_authority.publish_phase6_result_authority(
                        phase6_raw,
                        phase6_consumption_sha256=phase6_consumption_sha,
                        publication_capability=publication_capability(
                            phase=6,
                            result_bytes=phase6_raw,
                            upstream_sha256=phase6_consumption_sha,
                        ),
                    )

    def test_result_authority_marker_with_bad_acl_blocks(self):
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase6_consumption_sha = self.phase6_evidence().phase6_consumption_sha256

        untrusted_mutator_acl = protected_acl(untrusted_mutator=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ):
                marker = private_ci_result_authority.publish_phase6_result_authority(
                    phase6_raw,
                    phase6_consumption_sha256=phase6_consumption_sha,
                    publication_capability=publication_capability(
                        phase=6,
                        result_bytes=phase6_raw,
                        upstream_sha256=phase6_consumption_sha,
                    ),
                )
                self.assertIsNotNone(marker)

            def bad_marker_readback(path_obj):
                if str(path_obj).endswith(".authority.json"):
                    return untrusted_mutator_acl
                return protected_acl()

            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                side_effect=bad_marker_readback,
            ):
                with self.assertRaisesRegex(ValueError, "grants mutation to untrusted principal"):
                    private_ci_result_authority.validate_phase6_result_authority_marker(
                        phase6_raw,
                        phase6_consumption_sha256=phase6_consumption_sha,
                    )

    def test_final_pass_marker_with_bad_acl_blocks(self):
        from agent_controller import private_ci_final_publication

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase7_raw = self.result_module().phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )

        untrusted_mutator_acl = protected_acl(untrusted_mutator=True)

        def bad_marker_readback(path_obj):
            if str(path_obj).endswith(".published.json"):
                return untrusted_mutator_acl
            return protected_acl()

        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "read_consumption_acl_state",
                side_effect=bad_marker_readback,
            ):
                with self.assertRaisesRegex(ValueError, "grants mutation to untrusted principal"):
                    private_ci_final_publication.consume_final_pass_publication(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=phase7_raw,
                    )

    def test_authority_root_and_marker_reject_reparse_points(self):
        from unittest.mock import MagicMock
        from agent_controller import private_ci_final_publication
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase6_consumption_sha = self.phase6_evidence().phase6_consumption_sha256

        mock_reparse_stat = MagicMock()
        mock_reparse_stat.st_mode = 0o040755
        mock_reparse_stat.st_file_attributes = 0x400

        mock_marker_reparse_stat = MagicMock()
        mock_marker_reparse_stat.st_mode = 0o100644
        mock_marker_reparse_stat.st_file_attributes = 0x400

        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ), patch.object(
                private_ci_final_publication,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ):
                # 1. Authority root reparse rejection for Phase 6 publication
                with patch.object(Path, "lstat", return_value=mock_reparse_stat):
                    with self.assertRaisesRegex(
                        ValueError,
                        "result authority root ReparsePoint blocked",
                    ):
                        private_ci_result_authority.publish_phase6_result_authority(
                            phase6_raw,
                            phase6_consumption_sha256=phase6_consumption_sha,
                            publication_capability=publication_capability(
                                phase=6,
                                result_bytes=phase6_raw,
                                upstream_sha256=phase6_consumption_sha,
                            ),
                        )
                    # 2. Authority root reparse rejection for Final PASS publication
                    with self.assertRaisesRegex(
                        ValueError,
                        "final PASS publication authority root ReparsePoint blocked",
                    ):
                        private_ci_final_publication.consume_final_pass_publication(
                            phase5_result_bytes=phase5_raw,
                            phase6_result_bytes=phase6_raw,
                            phase7_result_bytes=b"{}",
                        )

                # Now publish valid marker
                marker = private_ci_result_authority.publish_phase6_result_authority(
                    phase6_raw,
                    phase6_consumption_sha256=phase6_consumption_sha,
                    publication_capability=publication_capability(
                        phase=6,
                        result_bytes=phase6_raw,
                        upstream_sha256=phase6_consumption_sha,
                    ),
                )
                self.assertIsNotNone(marker)

                # 3. Authority marker reparse rejection during validation
                orig_lstat = Path.lstat
                def fake_lstat(self):
                    if str(self).endswith(".authority.json"):
                        return mock_marker_reparse_stat
                    return orig_lstat(self)

                with patch.object(Path, "lstat", autospec=True, side_effect=fake_lstat):
                    with self.assertRaisesRegex(
                        ValueError,
                        "result authority marker ReparsePoint blocked",
                    ):
                        private_ci_result_authority.validate_phase6_result_authority_marker(
                            phase6_raw,
                            phase6_consumption_sha256=phase6_consumption_sha,
                        )

    def test_valid_protected_root_and_marker_succeeds(self):
        from agent_controller import private_ci_final_publication
        from agent_controller import private_ci_result_authority

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase7_raw = self.result_module().phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )
        phase6_consumption_sha = self.phase6_evidence().phase6_consumption_sha256

        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_result_authority,
                "RESULT_AUTHORITY_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ), patch.object(
                private_ci_result_authority,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ), patch.object(
                private_ci_final_publication,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ):
                # 1. Publish Phase 6
                m6 = private_ci_result_authority.publish_phase6_result_authority(
                    phase6_raw,
                    phase6_consumption_sha256=phase6_consumption_sha,
                    publication_capability=publication_capability(
                        phase=6,
                        result_bytes=phase6_raw,
                        upstream_sha256=phase6_consumption_sha,
                    ),
                )
                self.assertIsNotNone(m6)

                # 2. Validate Phase 6
                v6 = private_ci_result_authority.validate_phase6_result_authority_marker(
                    phase6_raw,
                    phase6_consumption_sha256=phase6_consumption_sha,
                )
                self.assertEqual(v6.result_sha256, m6.result_sha256)

                # 3. Publish Phase 7
                phase6_sha = hashlib.sha256(phase6_raw).hexdigest()
                m7 = private_ci_result_authority.publish_phase7_result_authority(
                    phase7_raw,
                    phase6_result_sha256=phase6_sha,
                    publication_capability=publication_capability(
                        phase=7,
                        result_bytes=phase7_raw,
                        upstream_sha256=phase6_sha,
                    ),
                )
                self.assertIsNotNone(m7)

                # 4. Validate Phase 7
                v7 = private_ci_result_authority.validate_phase7_result_authority_marker(
                    phase7_raw,
                    phase6_result_sha256=phase6_sha,
                )
                self.assertEqual(v7.result_sha256, m7.result_sha256)

                # 5. Consume Final PASS
                fp = private_ci_final_publication.consume_final_pass_publication(
                    phase5_result_bytes=phase5_raw,
                    phase6_result_bytes=phase6_raw,
                    phase7_result_bytes=phase7_raw,
                )
                self.assertIsNotNone(fp)

    def test_final_pass_publication_replay_guard(self):
        from agent_controller import private_ci_final_publication

        phase5_raw = phase5_result_bytes(phase5_evidence())
        phase6_raw = self.phase6_module().phase6_result_bytes(
            self.phase6_evidence(
                phase5_result_sha256=hashlib.sha256(phase5_raw).hexdigest()
            )
        )
        phase7_raw = self.result_module().phase7_result_bytes(
            self.phase7_evidence(
                phase6_result_sha256=hashlib.sha256(phase6_raw).hexdigest()
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            authority_root = Path(temp_dir)
            with patch.object(
                private_ci_final_publication,
                "FINAL_PUBLICATION_ROOT",
                authority_root,
            ), patch.object(
                private_ci_final_publication,
                "read_consumption_acl_state",
                return_value=protected_acl(),
            ):
                m1 = private_ci_final_publication.consume_final_pass_publication(
                    phase5_result_bytes=phase5_raw,
                    phase6_result_bytes=phase6_raw,
                    phase7_result_bytes=phase7_raw,
                )
                self.assertIsNotNone(m1)
                with self.assertRaisesRegex(
                    ValueError,
                    "final PASS already published",
                ):
                    private_ci_final_publication.consume_final_pass_publication(
                        phase5_result_bytes=phase5_raw,
                        phase6_result_bytes=phase6_raw,
                        phase7_result_bytes=phase7_raw,
                    )


if __name__ == "__main__":
    unittest.main()
