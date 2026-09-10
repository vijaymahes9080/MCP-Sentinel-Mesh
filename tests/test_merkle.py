"""
Unit Tests for Cryptographic Merkle Tree Audit Ledger
"""

import pytest
from proxy.merkle import MerkleAuditTree


def test_merkle_tree_single_and_multi_leaf():
    records = ["event_0: agent-alpha -> lookup_weather"]
    tree = MerkleAuditTree(records)
    root = tree.get_root_hex()
    assert root is not None
    assert len(root) == 64


def test_merkle_inclusion_proof_valid():
    records = [
        "event_0: agent-alpha -> lookup_weather",
        "event_1: agent-beta -> get_system_health",
        "event_2: agent-gamma -> sync_cache_store",
        "event_3: agent-delta -> read_file_safe",
    ]
    tree = MerkleAuditTree(records)
    root = tree.get_root_hex()

    # Generate proof for record 2
    proof = tree.get_inclusion_proof(2)
    assert len(proof) > 0

    # Verification must succeed
    is_valid = MerkleAuditTree.verify_proof(records[2], proof, root)
    assert is_valid is True


def test_merkle_inclusion_proof_tampered_record():
    records = [
        "event_0: action_a",
        "event_1: action_b",
        "event_2: action_c",
    ]
    tree = MerkleAuditTree(records)
    root = tree.get_root_hex()
    proof = tree.get_inclusion_proof(1)

    # Tamper with record text
    tampered_record = "event_1: MALICIOUS_ACTION_INJECTED"
    is_valid = MerkleAuditTree.verify_proof(tampered_record, proof, root)
    assert is_valid is False


def test_merkle_inclusion_proof_tampered_proof_hash():
    records = ["rec1", "rec2", "rec3", "rec4"]
    tree = MerkleAuditTree(records)
    root = tree.get_root_hex()
    proof = tree.get_inclusion_proof(0)

    # Corrupt proof hash
    proof[0]["hash"] = "0" * 64
    is_valid = MerkleAuditTree.verify_proof(records[0], proof, root)
    assert is_valid is False
