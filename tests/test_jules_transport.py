import unittest
import json
import os
import tempfile
import ast
from unittest.mock import patch, MagicMock

from agent_controller.jules_transport import (
    jules_start,
    jules_status,
    jules_approve_plan,
    jules_send,
    jules_wait,
    verify_github_artifact,
    _save_jules_state,
    _load_jules_state
)

class TestJulesTransport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, "jules_state.json")
        self.task_id = "task-123"
        self.owner = "testowner"
        self.repo = "testrepo"
        self.source = "sources/github/testowner/testrepo"
        self.starting_branch = "main"
        self.artifact_branch = "feature-branch"
        self.expected_starting_sha = "sha1111111111111111111111111111111111111"
        self.fake_api_key = "fake-secret-jules-key-xyz"

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Missing API key -> fail closed and no HTTP request
    @patch('agent_controller.jules_transport.urllib.request.urlopen')
    def test_missing_api_key_fail_closed(self, mock_urlopen):
        with patch.dict(os.environ, {}, clear=True):
            res = jules_start(
                self.task_id, self.owner, self.repo, self.source,
                self.starting_branch, self.expected_starting_sha, "Fix bug",
                state_file=self.state_file
            )
            self.assertEqual(res["status"], "BLOCKED")
            self.assertEqual(res["reason"], "JULES_API_KEY_MISSING")
            mock_urlopen.assert_not_called()

    # 2. GitHub starting SHA mismatch -> no Jules session creation
    @patch('agent_controller.jules_transport._jules_api_request')
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_starting_sha_mismatch_blocks(self, mock_get_head, mock_jules_req):
        mock_get_head.return_value = "different_sha_222222"

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_start(
                self.task_id, self.owner, self.repo, self.source,
                self.starting_branch, self.expected_starting_sha, "Fix bug",
                state_file=self.state_file
            )
            self.assertEqual(res["status"], "BLOCKED")
            self.assertIn("STARTING_SHA_MISMATCH", res["reason"])
            mock_jules_req.assert_not_called()

    # 3. Create session success -> session identity persisted atomically with sourceContext
    @patch('agent_controller.jules_transport._jules_api_request')
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_create_session_success_persisted(self, mock_get_head, mock_jules_req):
        mock_get_head.return_value = self.expected_starting_sha
        mock_jules_req.return_value = {
            "name": "sessions/sess-999",
            "url": "https://jules.googleapis.com/v1alpha/sessions/sess-999",
            "state": "QUEUED"
        }

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_start(
                self.task_id, self.owner, self.repo, self.source,
                self.starting_branch, self.expected_starting_sha, "Fix bug",
                state_file=self.state_file
            )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["reason"], "SESSION_CREATED")
            self.assertEqual(res["session"]["session_id"], "sess-999")

            # Check sourceContext in API request body
            mock_jules_req.assert_called_once()
            call_args = mock_jules_req.call_args
            req_body = call_args[1].get("body") or call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get("body")
            self.assertIn("sourceContext", req_body)
            self.assertEqual(req_body["sourceContext"]["source"], self.source)
            self.assertEqual(req_body["sourceContext"]["startingBranch"], self.starting_branch)

            state, corrupt = _load_jules_state(self.state_file)
            self.assertFalse(corrupt)
            self.assertEqual(state["session_id"], "sess-999")
            self.assertEqual(state["current_state"], "QUEUED")

    # 4. Retry after persisted create -> no duplicate session
    @patch('agent_controller.jules_transport._jules_api_request')
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_retry_after_persisted_create_no_duplicate(self, mock_get_head, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "source": self.source,
            "starting_branch": self.starting_branch,
            "expected_starting_sha": self.expected_starting_sha,
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "QUEUED"
        }
        _save_jules_state(self.state_file, initial_state)

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_start(
                self.task_id, self.owner, self.repo, self.source,
                self.starting_branch, self.expected_starting_sha, "Fix bug",
                state_file=self.state_file
            )
            self.assertEqual(res["status"], "EXISTS")
            self.assertEqual(res["reason"], "SESSION_ALREADY_EXISTS")
            mock_jules_req.assert_not_called()
            mock_get_head.assert_not_called()

    # 5. AWAITING_PLAN_APPROVAL -> explicit waiting state, no implicit approval
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_awaiting_plan_approval_state(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "PLANNING",
            "plan_approved": False
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.return_value = {
            "name": "sessions/sess-999",
            "state": "AWAITING_PLAN_APPROVAL"
        }

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_status(state_file=self.state_file)
            self.assertEqual(res["status"], "OK")
            self.assertEqual(res["session"]["current_state"], "AWAITING_PLAN_APPROVAL")
            self.assertFalse(res["session"]["plan_approved"])

    # 6. Approved exact session -> one approvePlan call + receipt
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_approve_plan_call_and_receipt(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "AWAITING_PLAN_APPROVAL",
            "plan_approved": False
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.return_value = {"state": "IN_PROGRESS"}

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_approve_plan(state_file=self.state_file)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertTrue(res["session"]["plan_approved"])
            self.assertEqual(res["session"]["current_state"], "IN_PROGRESS")
            mock_jules_req.assert_called_once_with("sessions/sess-999:approvePlan", method="POST", body={}, api_key_env="JULES_API_KEY")

    # 7. Repeated approval cycle -> no duplicate approval
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_repeated_approval_no_duplicate(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "IN_PROGRESS",
            "plan_approved": True
        }
        _save_jules_state(self.state_file, initial_state)

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_approve_plan(state_file=self.state_file)
            self.assertEqual(res["status"], "EXISTS")
            self.assertEqual(res["reason"], "PLAN_ALREADY_APPROVED")
            mock_jules_req.assert_not_called()

    # 8. sendMessage success with empty response -> receipt persisted
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_send_message_empty_response_receipt_persisted(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "IN_PROGRESS",
            "sent_messages": []
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.return_value = {} # empty body response

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_send("Please fix lint errors", state_file=self.state_file)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(len(res["session"]["sent_messages"]), 1)
            self.assertEqual(res["session"]["sent_messages"][0]["status"], "SUCCESS")

    # 9. Repeated send cycle -> no duplicate message
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_repeated_send_no_duplicate(self, mock_jules_req):
        import hashlib
        msg_hash = hashlib.sha256("Please fix lint errors".encode('utf-8')).hexdigest()
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "IN_PROGRESS",
            "sent_messages": [{"message_hash": msg_hash, "status": "SUCCESS"}]
        }
        _save_jules_state(self.state_file, initial_state)

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_send("Please fix lint errors", state_file=self.state_file)
            self.assertEqual(res["status"], "EXISTS")
            self.assertEqual(res["reason"], "MESSAGE_ALREADY_SENT")
            mock_jules_req.assert_not_called()

    # 10. Network uncertainty/error -> fail closed, no false success receipt
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_network_error_fail_closed(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "IN_PROGRESS",
            "sent_messages": []
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.side_effect = Exception("Connection timed out")

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_send("Please fix lint errors", state_file=self.state_file)
            self.assertEqual(res["status"], "BLOCKED")
            self.assertIn("JULES_API_SEND_FAILED", res["reason"])

            # Verify no receipt persisted
            state, _ = _load_jules_state(self.state_file)
            self.assertEqual(len(state["sent_messages"]), 0)

    # 11. Bounded polling across QUEUED/PLANNING/IN_PROGRESS -> deterministic terminal result
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_bounded_polling(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "QUEUED"
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.side_effect = [
            {"state": "PLANNING"},
            {"state": "IN_PROGRESS"},
            {"state": "COMPLETED"}
        ]

        fake_sleep = MagicMock()
        fake_clock = MagicMock()

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_wait(state_file=self.state_file, interval=1, max_attempts=5, clock=fake_clock, sleeper=fake_sleep)
            self.assertEqual(res["status"], "OK")
            self.assertEqual(res["session"]["current_state"], "COMPLETED")
            self.assertEqual(fake_sleep.call_count, 2)

    # 12. Unknown Jules state -> fail closed
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_unknown_jules_state_fails_closed(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "IN_PROGRESS"
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.return_value = {"state": "SOMETHING_SUPER_WEIRD"}

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_status(state_file=self.state_file)
            self.assertEqual(res["status"], "BLOCKED")
            self.assertIn("UNKNOWN_JULES_STATE", res["reason"])

    # 13. FAILED -> terminal failure status returned
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_terminal_failed_state(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "IN_PROGRESS"
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.return_value = {"state": "FAILED"}

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_status(state_file=self.state_file)
            self.assertEqual(res["status"], "FAILED")
            self.assertEqual(res["reason"], "JULES_SESSION_FAILED")
            self.assertEqual(res["session"]["current_state"], "FAILED")

    # 14. COMPLETED with outputs -> outputs parsed without trusting agent prose as authority
    @patch('agent_controller.jules_transport._jules_api_request')
    def test_completed_with_outputs_parsed(self, mock_jules_req):
        initial_state = {
            "task_id": self.task_id,
            "repo": f"{self.owner}/{self.repo}",
            "session_id": "sess-999",
            "session_name": "sessions/sess-999",
            "current_state": "IN_PROGRESS"
        }
        _save_jules_state(self.state_file, initial_state)

        mock_jules_req.return_value = {
            "state": "COMPLETED",
            "outputs": [
                {"type": "PR", "url": "https://github.com/testowner/testrepo/pull/12", "text": "I pushed commit sha222 and opened PR"}
            ]
        }

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_status(state_file=self.state_file)
            self.assertEqual(res["status"], "OK")
            self.assertEqual(res["session"]["current_state"], "COMPLETED")
            self.assertEqual(len(res["session"]["outputs"]), 1)

    # 15. COMPLETED but expected GitHub branch absent/unchanged -> GITHUB_ARTIFACT_NOT_PUBLISHED
    # Phase 4B incident test fixture: UI shows ready/COMPLETED, but PR head SHA unchanged
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_phase_4b_incident_github_artifact_not_published(self, mock_get_head):
        mock_get_head.return_value = self.expected_starting_sha

        res = verify_github_artifact(
            owner=self.owner,
            repo=self.repo,
            starting_branch=self.starting_branch,
            artifact_branch=self.artifact_branch,
            expected_starting_sha=self.expected_starting_sha
        )

        self.assertFalse(res["verified"])
        self.assertEqual(res["reason"], "GITHUB_ARTIFACT_NOT_PUBLISHED")

    # 16. Published branch with expected ancestry/files -> verified handoff candidate
    @patch('agent_controller.jules_transport._github_api_request')
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_published_branch_verified(self, mock_get_head, mock_github_req):
        new_head_sha = "sha2222222222222222222222222222222222222"
        mock_get_head.return_value = new_head_sha

        mock_github_req.return_value = {
            "status": "ahead",
            "files": [
                {"filename": "agent_controller/jules_transport.py", "status": "added"}
            ]
        }

        res = verify_github_artifact(
            owner=self.owner,
            repo=self.repo,
            starting_branch=self.starting_branch,
            artifact_branch=self.artifact_branch,
            expected_starting_sha=self.expected_starting_sha,
            allowed_paths=["agent_controller/*"]
        )

        self.assertTrue(res["verified"])
        self.assertEqual(res["reason"], "VERIFIED_SUCCESSFULLY")
        self.assertEqual(res["head_sha"], new_head_sha)

    # 17. Unexpected files/effects -> blocked/not-pass
    @patch('agent_controller.jules_transport._github_api_request')
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_unexpected_files_blocked(self, mock_get_head, mock_github_req):
        new_head_sha = "sha2222222222222222222222222222222222222"
        mock_get_head.return_value = new_head_sha

        mock_github_req.return_value = {
            "status": "ahead",
            "files": [
                {"filename": "agent_controller/jules_transport.py", "status": "added"},
                {"filename": "secret_config.ini", "status": "added"}
            ]
        }

        res = verify_github_artifact(
            owner=self.owner,
            repo=self.repo,
            starting_branch=self.starting_branch,
            artifact_branch=self.artifact_branch,
            expected_starting_sha=self.expected_starting_sha,
            allowed_paths=["agent_controller/*"]
        )

        self.assertFalse(res["verified"])
        self.assertIn("FILE_NOT_ALLOWLISTED", res["reason"])

    # 18. Local state corrupt -> fail closed
    def test_corrupt_local_state_fails_closed(self):
        with open(self.state_file, 'w') as f:
            f.write("corrupt non-json data {")

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_status(state_file=self.state_file)
            self.assertEqual(res["status"], "BLOCKED")
            self.assertEqual(res["reason"], "STATE_FILE_NOT_FOUND_OR_CORRUPT")

    # 19. Local state target mismatch -> fail closed
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_target_mismatch_fails_closed(self, mock_get_head):
        initial_state = {
            "task_id": "other-task-456",
            "repo": "otherowner/otherrepo",
            "starting_branch": self.starting_branch,
            "expected_starting_sha": self.expected_starting_sha,
            "session_id": "sess-999"
        }
        _save_jules_state(self.state_file, initial_state)

        with patch.dict(os.environ, {"JULES_API_KEY": self.fake_api_key}):
            res = jules_start(
                self.task_id, self.owner, self.repo, self.source,
                self.starting_branch, self.expected_starting_sha, "Fix bug",
                state_file=self.state_file
            )
            self.assertEqual(res["status"], "BLOCKED")
            self.assertEqual(res["reason"], "TARGET_MISMATCH")

    # 20. API key never appears in state/output/log fixtures
    @patch('agent_controller.jules_transport._jules_api_request')
    @patch('agent_controller.jules_transport.get_github_branch_head')
    def test_api_key_non_leakage(self, mock_get_head, mock_jules_req):
        mock_get_head.return_value = self.expected_starting_sha
        mock_jules_req.return_value = {
            "name": "sessions/sess-999",
            "state": "QUEUED"
        }

        secret_key = "TOP-SECRET-JULES-KEY-999"
        with patch.dict(os.environ, {"JULES_API_KEY": secret_key}):
            res = jules_start(
                self.task_id, self.owner, self.repo, self.source,
                self.starting_branch, self.expected_starting_sha, "Fix bug",
                state_file=self.state_file
            )

            res_str = json.dumps(res)
            self.assertNotIn(secret_key, res_str)

            with open(self.state_file, 'r') as f:
                file_content = f.read()
                self.assertNotIn(secret_key, file_content)

    # 21. Capability boundary check: jules_transport does not import write capabilities
    def test_capability_boundary_ast(self):
        with open("agent_controller/jules_transport.py", "r") as f:
            tree = ast.parse(f.read())

        imported_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_names.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported_names.add(alias.name)

        dangerous_capabilities = [
            "convert_pull_request_to_draft",
            "merge",
            "create_comment",
            "subprocess",
            "shutil"
        ]
        for cap in dangerous_capabilities:
            self.assertNotIn(cap, imported_names)

if __name__ == '__main__':
    unittest.main()
