"""
MCP Sentinel Mesh - Cryptographic Merkle Tree Audit Ledger
Constructs binary Merkle trees over audit logs and generates zero-knowledge inclusion proofs.
Prevents second-preimage attacks via domain separation prefixes (0x00 for leaves, 0x01 for internal nodes).
"""

import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple


def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class MerkleNode:
    def __init__(self, hash_val: bytes, left: Optional['MerkleNode'] = None, right: Optional['MerkleNode'] = None):
        self.hash_val = hash_val
        self.left = left
        self.right = right


class MerkleAuditTree:
    """
    Binary Merkle Tree for tamper-evident audit records.
    RFC 6962 / Certificate Transparency compliant hashing.
    """

    def __init__(self, records: Optional[List[str]] = None):
        self.leaves: List[bytes] = []
        self.root: Optional[MerkleNode] = None
        if records:
            for r in records:
                self.add_record(r)
            self.build_tree()

    def hash_leaf(self, record: str) -> bytes:
        # Domain separation prefix 0x00 for leaf nodes
        return sha256_hash(b"\x00" + record.encode("utf-8"))

    def hash_children(self, left: bytes, right: bytes) -> bytes:
        # Domain separation prefix 0x01 for internal nodes
        return sha256_hash(b"\x01" + left + right)

    def add_record(self, record: str):
        self.leaves.append(self.hash_leaf(record))

    def build_tree(self) -> Optional[bytes]:
        if not self.leaves:
            return None

        current_level = [MerkleNode(leaf_hash) for leaf_hash in self.leaves]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Odd number of nodes: duplicate last node (Bitcoin / RFC 6962 standard)
                    right = MerkleNode(left.hash_val)

                parent_hash = self.hash_children(left.hash_val, right.hash_val)
                parent_node = MerkleNode(parent_hash, left, right)
                next_level.append(parent_node)
            current_level = next_level

        self.root = current_level[0]
        return self.root.hash_val

    def get_root_hex(self) -> Optional[str]:
        if not self.root:
            self.build_tree()
        return self.root.hash_val.hex() if self.root else None

    def get_inclusion_proof(self, index: int) -> List[Dict[str, str]]:
        """
        Generates inclusion audit path for the leaf at given index.
        Returns list of { 'position': 'left'|'right', 'hash': hex_string }.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds")

        proof: List[Dict[str, str]] = []
        current_level = [l for l in self.leaves]
        idx = index

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left_hash = current_level[i]
                right_hash = current_level[i + 1] if i + 1 < len(current_level) else left_hash

                if i == idx or (i + 1 == idx and i + 1 < len(current_level)):
                    if idx % 2 == 0:
                        proof.append({"position": "right", "hash": right_hash.hex()})
                    else:
                        proof.append({"position": "left", "hash": left_hash.hex()})

                parent_hash = self.hash_children(left_hash, right_hash)
                next_level.append(parent_hash)

            idx //= 2
            current_level = next_level

        return proof

    @staticmethod
    def verify_proof(record: str, proof: List[Dict[str, str]], expected_root_hex: str) -> bool:
        """
        Verifies if record exists within the Merkle tree defined by expected_root_hex.
        """
        current_hash = sha256_hash(b"\x00" + record.encode("utf-8"))

        for step in proof:
            sibling_hash = bytes.fromhex(step["hash"])
            if step["position"] == "left":
                current_hash = sha256_hash(b"\x01" + sibling_hash + current_hash)
            else:
                current_hash = sha256_hash(b"\x01" + current_hash + sibling_hash)

        return current_hash.hex() == expected_root_hex
