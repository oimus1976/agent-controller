import inspect
import json
import unittest
from unittest.mock import MagicMock, patch

from agent_controller.remediation_request_mutator import (
    codex_remediation_request_body,
    codex_remediation_request_marker,
    post_codex_remediation_request,
)


HEAD = "a" * 40


class RemediationRequestMutatorTests(unittest.TestCase):
    def test_body_is_fixed_template_bound_to_source_head(self):
        self.assertEqual(
            "@codex address that feedback\n\n"
            f"<!-- agent-controller:codex-remediation-request source_head={HEAD} -->",
            codex_remediation_request_body(HEAD),
        )

    def test_invalid_sha_is_rejected(self):
        for value in ("", "A" * 40, "g" * 40, "a" * 39, None):
            with self.assertRaises((TypeError, ValueError)):
                codex_remediation_request_marker(value)

    def test_mutator_exposes_no_generic_comment_body_parameter(self):
        self.assertEqual(
            ["owner", "repo", "pr_number", "source_head_sha"],
            list(inspect.signature(post_codex_remediation_request).parameters),
        )

    @patch("agent_controller.remediation_request_mutator.urllib.request.urlopen")
    def test_posts_expected_fixed_comment(self, urlopen):
        response = MagicMock()
        response.read.return_value = json.dumps(
            {"id": 123, "body": codex_remediation_request_body(HEAD)}
        ).encode()
        urlopen.return_value.__enter__.return_value = response

        result = post_codex_remediation_request(
            "oimus1976", "agent-controller", 111, HEAD
        )

        self.assertEqual(123, result["id"])
        request = urlopen.call_args.args[0]
        payload = json.loads(urlopen.call_args.kwargs["data"].decode())
        self.assertEqual("POST", request.get_method())
        self.assertEqual(
            "https://api.github.com/repos/oimus1976/agent-controller/issues/111/comments",
            request.full_url,
        )
        self.assertEqual(codex_remediation_request_body(HEAD), payload["body"])

    def test_invalid_target_is_rejected_before_network(self):
        cases = [
            ("", "repo", 1, HEAD),
            ("owner", "", 1, HEAD),
            ("owner", "repo", 0, HEAD),
            ("owner", "repo", True, HEAD),
            ("owner", "repo", 1, "bad"),
        ]
        with patch(
            "agent_controller.remediation_request_mutator.urllib.request.urlopen"
        ) as urlopen:
            for args in cases:
                with self.assertRaises((TypeError, ValueError)):
                    post_codex_remediation_request(*args)
            urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
