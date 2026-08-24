import inspect
import unittest

from agent_controller.provider_clients import ProviderReadClient
from agent_controller.provider_contract import ProviderOperationRef


class OneMethodReadClient:
    def get_operation_raw(self, operation):
        return {
            "provider_operation_id": operation.provider_operation_id,
            "status": "fixture",
        }


class MissingReadMethodClient:
    pass


class TestProviderReadClient(unittest.TestCase):
    def make_operation(self):
        return ProviderOperationRef(
            provider="example-provider",
            provider_operation_id="provider-op-1",
            provider_url=None,
            controller_task_id="controller-task-1",
            operation_id="operation-1",
        )

    def test_one_read_method_is_sufficient(self):
        client = OneMethodReadClient()
        self.assertIsInstance(client, ProviderReadClient)
        self.assertEqual(
            client.get_operation_raw(self.make_operation())["provider_operation_id"],
            "provider-op-1",
        )

    def test_missing_read_method_does_not_satisfy_protocol(self):
        self.assertNotIsInstance(MissingReadMethodClient(), ProviderReadClient)

    def test_protocol_exposes_only_observation_read_surface(self):
        source = inspect.getsource(ProviderReadClient)
        self.assertIn("def get_operation_raw", source)
        forbidden_methods = (
            "approve",
            "authorize",
            "send",
            "message",
            "retry",
            "cancel",
            "dispatch",
            "create",
            "update",
            "delete",
            "merge",
            "deploy",
        )
        for method in forbidden_methods:
            self.assertNotIn(f"def {method}", source)


if __name__ == "__main__":
    unittest.main()
