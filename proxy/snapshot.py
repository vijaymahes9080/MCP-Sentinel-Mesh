"""
MCP Sentinel Mesh - Pre-Execution State Snapshot & Compensation Rollback Engine
Captures pre-mutation state and executes automated compensatory transactions upon failure or security violation.
"""

from typing import Dict, Any, Optional, Callable
import time
import copy


class SnapshotError(Exception):
    pass


class StateSnapshotManager:
    """
    Manages pre-execution state capture and transaction rollback/compensation
    for stateful MCP tool executions.
    """

    def __init__(self):
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        self.compensation_handlers: Dict[str, Callable[[Dict[str, Any]], bool]] = {}

    def register_compensation_handler(self, action_type: str, handler: Callable[[Dict[str, Any]], bool]):
        """Registers a reverse transaction handler for a specific tool/action type."""
        self.compensation_handlers[action_type] = handler

    def capture_snapshot(self, transaction_id: str, resource_key: str, state_data: Any) -> str:
        """Saves a pre-execution deep copy of resource state before mutation."""
        self.snapshots[transaction_id] = {
            "resource_key": resource_key,
            "timestamp": time.time(),
            "state_data": copy.deepcopy(state_data),
            "status": "active"
        }
        return transaction_id

    def rollback(self, transaction_id: str, action_type: Optional[str] = None) -> bool:
        """
        Executes automated compensation rollback to revert mutated resource to snapshot state.
        """
        if transaction_id not in self.snapshots:
            raise SnapshotError(f"Cannot rollback: Transaction '{transaction_id}' snapshot not found.")

        snap = self.snapshots[transaction_id]
        if snap["status"] == "rolled_back":
            return True  # Already rolled back

        # If custom compensation handler registered, execute it
        if action_type and action_type in self.compensation_handlers:
            handler = self.compensation_handlers[action_type]
            success = handler(snap)
            if not success:
                raise SnapshotError(f"Compensation handler failed for action '{action_type}'.")

        snap["status"] = "rolled_back"
        return True

    def commit(self, transaction_id: str):
        """Finalizes transaction and marks snapshot as committed."""
        if transaction_id in self.snapshots:
            self.snapshots[transaction_id]["status"] = "committed"

    def get_snapshot(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        return self.snapshots.get(transaction_id)
