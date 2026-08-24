from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from agent_controller.provider_contract import ProviderOperationRef


@runtime_checkable
class ProviderReadClient(Protocol):
    """Minimal read-only provider boundary for observation.

    Implementations may wrap an official SDK, CLI, Action result, or fixture.
    This protocol intentionally exposes no mutation, approval, retry, cancel,
    message-send, or dispatch capability.
    """

    def get_operation_raw(self, operation: ProviderOperationRef) -> Any:
        """Return the provider-native raw observation for one bound operation."""
        ...
