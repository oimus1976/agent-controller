import unittest
import json
import os
import tempfile
from unittest.mock import patch, mock_open
from agent_controller.watcher import watch_pr_once

class TestWatcher(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.test_dir.name, "state.json")

    def tearDown(self):
        self.test_dir.cleanup()


    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_inspect_failure(self, mock_inspect):
        # inspect_pr raising/API failure -> explicit fail-closed observation/provenance
        initial_state = {
            'head_sha': 'sha1',
            'classification': 'REVIEW_READY',
            'draft': False,
            'merged': False,
            'state_enum': 'open',
            'graphql_error': False,
            'check_runs_error': False,
            'scope_status': 'SATISFIED'
        }
        with open(self.state_file, 'w') as f:
            json.dump(initial_state, f)

        mock_inspect.side_effect = Exception("API connection dropped")

        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertTrue(obs['transition'])
        self.assertIn('EVIDENCE_AVAILABILITY_CHANGED', obs['transition_reasons'])
        self.assertIn('CLASSIFICATION_CHANGED', obs['transition_reasons'])
        self.assertEqual(obs['current_classification'], 'NEEDS_REVIEW')
        self.assertEqual(obs['runtime_status'], 'EVIDENCE_UNAVAILABLE')
        self.assertEqual(obs['error_reason'], 'API connection dropped')

        # Verify state file retains safe fallback values
        with open(self.state_file, 'r') as f:
            state = json.load(f)
            self.assertEqual(state['classification'], 'NEEDS_REVIEW')
            self.assertEqual(state['head_sha'], 'sha1')
            self.assertTrue(state['graphql_error'])
            self.assertTrue(state['check_runs_error'])

    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_baseline(self, mock_inspect):
        # first observation creates baseline state with no false prior transition
        mock_inspect.return_value = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': False,
            'merged': False,
            'state': 'open',
            'graphql_error': False,
            'check_runs_error': False
        }

        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertFalse(obs['transition'])
        self.assertEqual(obs['transition_reasons'], [])
        self.assertEqual(obs['current_head_sha'], 'sha1')
        self.assertIsNone(obs['previous_head_sha'])

        # Verify state file written
        self.assertTrue(os.path.exists(self.state_file))
        with open(self.state_file, 'r') as f:
            state = json.load(f)
            self.assertEqual(state['head_sha'], 'sha1')

    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_idempotent(self, mock_inspect):
        # identical repeated observation is idempotent
        mock_inspect.return_value = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': False,
            'merged': False,
            'state': 'open',
            'graphql_error': False,
            'check_runs_error': False
        }

        # Write initial state
        watch_pr_once('owner', 'repo', 1, self.state_file)

        # Second run
        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertFalse(obs['transition'])
        self.assertEqual(obs['transition_reasons'], [])
        self.assertEqual(obs['previous_head_sha'], 'sha1')
        self.assertEqual(obs['current_head_sha'], 'sha1')

    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_head_changed(self, mock_inspect):
        # head SHA change emits HEAD_CHANGED
        initial_state = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': False,
            'merged': False,
            'state_enum': 'open', 'scope_status': 'UNKNOWN',
            'graphql_error': False, 'check_runs_error': False, 'scope_status': 'UNKNOWN'
        }
        with open(self.state_file, 'w') as f:
            json.dump(initial_state, f)

        mock_inspect.return_value = {
            'head_sha': 'sha2',
            'classification': 'NEEDS_REVIEW',
            'draft': False,
            'merged': False,
            'state': 'open',
            'graphql_error': False,
            'check_runs_error': False
        }

        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertTrue(obs['transition'])
        self.assertIn('HEAD_CHANGED', obs['transition_reasons'])
        self.assertEqual(obs['previous_head_sha'], 'sha1')
        self.assertEqual(obs['current_head_sha'], 'sha2')

    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_classification_changed(self, mock_inspect):
        # classification change emits CLASSIFICATION_CHANGED
        initial_state = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': False,
            'merged': False,
            'state_enum': 'open', 'scope_status': 'UNKNOWN',
            'graphql_error': False, 'check_runs_error': False, 'scope_status': 'UNKNOWN'
        }
        with open(self.state_file, 'w') as f:
            json.dump(initial_state, f)

        mock_inspect.return_value = {
            'head_sha': 'sha1',
            'classification': 'REVIEW_READY',
            'draft': False,
            'merged': False,
            'state': 'open',
            'graphql_error': False,
            'check_runs_error': False
        }

        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertTrue(obs['transition'])
        self.assertIn('CLASSIFICATION_CHANGED', obs['transition_reasons'])
        self.assertEqual(obs['previous_classification'], 'NEEDS_REVIEW')
        self.assertEqual(obs['current_classification'], 'REVIEW_READY')

    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_state_changed(self, mock_inspect):
        # Draft/open/merged change emits PR_STATE_CHANGED
        initial_state = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': True,
            'merged': False,
            'state_enum': 'open', 'scope_status': 'UNKNOWN',
            'graphql_error': False, 'check_runs_error': False, 'scope_status': 'UNKNOWN'
        }
        with open(self.state_file, 'w') as f:
            json.dump(initial_state, f)

        mock_inspect.return_value = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': False,  # Changed from True to False
            'merged': False,
            'state': 'open',
            'graphql_error': False,
            'check_runs_error': False
        }

        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertTrue(obs['transition'])
        self.assertIn('PR_STATE_CHANGED', obs['transition_reasons'])

    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_evidence_unavailable(self, mock_inspect):
        # evidence availability loss emits fail-closed transition/reason
        initial_state = {
            'head_sha': 'sha1',
            'classification': 'REVIEW_READY',
            'draft': False,
            'merged': False,
            'state_enum': 'open', 'scope_status': 'UNKNOWN',
            'graphql_error': False, 'check_runs_error': False, 'scope_status': 'UNKNOWN'
        }
        with open(self.state_file, 'w') as f:
            json.dump(initial_state, f)

        mock_inspect.return_value = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW', # Inspector correctly reclassifies to NEEDS_REVIEW when evidence fails
            'draft': False,
            'merged': False,
            'state': 'open',
            'graphql_error': True,  # Evidence loss
            'check_runs_error': False
        }

        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertTrue(obs['transition'])
        self.assertIn('EVIDENCE_AVAILABILITY_CHANGED', obs['transition_reasons'])
        self.assertIn('CLASSIFICATION_CHANGED', obs['transition_reasons'])

    @patch('agent_controller.watcher.inspect_pr')
    def test_watch_pr_once_corrupt_state(self, mock_inspect):
        # malformed/corrupt prior local state is handled safely and explicitly
        with open(self.state_file, 'w') as f:
            f.write("not valid json")

        mock_inspect.return_value = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': False,
            'merged': False,
            'state': 'open',
            'graphql_error': False,
            'check_runs_error': False
        }

        obs = watch_pr_once('owner', 'repo', 1, self.state_file)

        self.assertTrue(obs['transition'])
        self.assertIn('PRIOR_STATE_CORRUPT', obs['transition_reasons'])

        # File should be overwritten with valid json
        with open(self.state_file, 'r') as f:
            state = json.load(f)
            self.assertEqual(state['head_sha'], 'sha1')

    @patch('agent_controller.watcher.inspect_pr')
    @patch('os.replace')
    def test_watch_pr_once_atomic_write_fails(self, mock_replace, mock_inspect):
        # state file is replaced only after successful atomic observation write
        mock_replace.side_effect = OSError("Failed to replace")

        mock_inspect.return_value = {
            'head_sha': 'sha1',
            'classification': 'NEEDS_REVIEW',
            'draft': False,
            'merged': False,
            'state': 'open',
            'graphql_error': False,
            'check_runs_error': False
        }

        with self.assertRaises(OSError):
            watch_pr_once('owner', 'repo', 1, self.state_file)

        # Ensure temp file is cleaned up, or state file is not corrupted if it existed
        self.assertFalse(os.path.exists(self.state_file))
