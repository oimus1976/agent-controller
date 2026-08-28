import inspect
import json
import os
import unittest
from unittest.mock import MagicMock, patch

from agent_controller.review_request_mutator import (
    codex_review_request_body,
    codex_review_request_marker,
    get_authenticated_github_login,
    post_codex_review_request,
)


HEAD = "a" * 40


class ReviewRequestMutatorTests(unittest.TestCase):
    def test_body_is_fixed_template_bound_to_head(self):
        self.assertEqual(
            f"@codex review\n\n<!-- agent-controller:codex-review-request head={HEAD} -->",
            codex_review_request_body(HEAD),
        )

    def test_invalid_sha_is_rejected(self):
        for value in ("", "A" * 40, "g" * 40, "a" * 39, None):
            with self.assertRaises((TypeError, ValueError)):
                codex_review_request_marker(value)

    def test_mutator_exposes_no_generic_comment_body_parameter(self):
        params = inspect.signature(post_codex_review_request).parameters
        self.assertEqual(["owner", "repo", "pr_number", "head_sha"], list(params))

    @patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False)
    @patch("agent_controller.review_request_mutator.urllib.request.urlopen")
    def test_authenticated_login_uses_same_github_token_identity(self, urlopen):
        response = MagicMock()
        response.read.return_value = json.dumps({"login": "oimus1976"}).encode()
        urlopen.return_value.__enter__.return_value = response

        self.assertEqual("oimus1976", get_authenticated_github_login())
        request = urlopen.call_args.args[0]
        self.assertEqual("GET", request.get_method())
        self.assertEqual("https://api.github.com/user", request.full_url)
        self.assertEqual("Bearer token", request.get_header("Authorization"))

    @patch.dict(os.environ, {}, clear=True)
    @patch("agent_controller.review_request_mutator.urllib.request.urlopen")
    def test_authenticated_login_requires_token_before_network(self, urlopen):
        with self.assertRaises(RuntimeError):
            get_authenticated_github_login()
        urlopen.assert_not_called()

    @patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False)
    @patch("agent_controller.review_request_mutator.urllib.request.urlopen")
    def test_authenticated_login_rejects_malformed_response(self, urlopen):
        response = MagicMock()
        response.read.return_value = json.dumps({"login": ""}).encode()
        urlopen.return_value.__enter__.return_value = response
        with self.assertRaises(RuntimeError):
            get_authenticated_github_login()

    @patch("agent_controller.review_request_mutator.urllib.request.urlopen")
    def test_posts_expected_fixed_comment(self, urlopen):
        response = MagicMock()
        response.read.return_value = json.dumps({"id": 123, "body": codex_review_request_body(HEAD)}).encode()
        urlopen.return_value.__enter__.return_value = response

        result = post_codex_review_request("oimus1976", "agent-controller", 109, HEAD)

        self.assertEqual(123, result["id"])
        request = urlopen.call_args.args[0]
        payload = json.loads(urlopen.call_args.kwargs["data"].decode())
        self.assertEqual("POST", request.get_method())
        self.assertEqual(
            "https://api.github.com/repos/oimus1976/agent-controller/issues/109/comments",
            request.full_url,
        )
        self.assertEqual(codex_review_request_body(HEAD), payload["body"])

    def test_invalid_target_is_rejected_before_network(self):
        cases = [
            ("", "repo", 1, HEAD),
            ("owner", "", 1, HEAD),
            ("owner", "repo", 0, HEAD),
            ("owner", "repo", True, HEAD),
            ("owner", "repo", 1, "bad"),
        ]
        with patch("agent_controller.review_request_mutator.urllib.request.urlopen") as urlopen:
            for args in cases:
                with self.assertRaises((TypeError, ValueError)):
                    post_codex_review_request(*args)
            urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
