"""
Unit Tests for State Snapshot & Compensation Rollback Engine
"""

import pytest
from proxy.snapshot import StateSnapshotManager, SnapshotError


def test_snapshot_and_automated_rollback():
    manager = StateSnapshotManager()

    mock_db = {"users": [{"id": 1, "role": "viewer"}]}

    def rollback_user_table(snap_data: dict) -> bool:
        # Revert mock_db to original snapshot state
        mock_db["users"] = snap_data["state_data"]
        return True

    manager.register_compensation_handler("user_role_update", rollback_user_table)

    tx_id = "tx-999"
    manager.capture_snapshot(tx_id, "users_table", mock_db["users"])

    # Simulate rogue / accidental mutation
    mock_db["users"] = [{"id": 1, "role": "superadmin_injected"}]
    assert mock_db["users"][0]["role"] == "superadmin_injected"

    # Trigger rollback
    success = manager.rollback(tx_id, action_type="user_role_update")
    assert success is True

    # Validate state was completely restored to original
    assert mock_db["users"][0]["role"] == "viewer"

    snap = manager.get_snapshot(tx_id)
    assert snap["status"] == "rolled_back"


def test_snapshot_commit_lifecycle():
    manager = StateSnapshotManager()
    manager.capture_snapshot("tx-100", "cache", {"active": True})
    manager.commit("tx-100")

    snap = manager.get_snapshot("tx-100")
    assert snap["status"] == "committed"
