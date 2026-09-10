# Cryptographic Merkle Tree Audit Ledger

## Overview

MCP Sentinel Mesh implements a binary **Merkle Tree Audit Ledger** compliant with RFC 6962 (Certificate Transparency). Every tool invocation intercepted or mediated by the runtime proxy is cryptographically hashed and incorporated into a verifiable ledger.

## Why Merkle Trees for AI Agent Auditing?

Traditional database or JSON file audit logs suffer from major trust limitations:
1. **Insider Tampering**: A database administrator or compromised service can alter or delete past log entries without detection.
2. **Log Omission**: Attackers can erase records of unauthorized tool calls.
3. **Audit Verification Overhead**: Proving that a record exists traditionally requires exposing the entire log database.

Merkle trees solve this by:
- Creating a single, fixed-size 32-byte **Merkle Root Hash** representing the cryptographic integrity of all historical records.
- Generating compact $O(\log N)$ **Inclusion Proofs** allowing any external verifier to mathematically validate that a specific call was recorded, without exposing any other log entries.

## Domain Separation & Anti-Collision Standards

To protect against second-preimage attacks (where an attacker crafts an internal node payload that hashes to the same value as a leaf), MCP Sentinel Mesh implements strict RFC 6962 domain separation prefixes:

$$\text{Leaf Hash} = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} \text{Serialized Record})$$

$$\text{Internal Node Hash} = \text{SHA-256}(0\text{x}01 \mathbin{\Vert} \text{Left Child} \mathbin{\Vert} \text{Right Child})$$

## Verifying an Inclusion Proof in Python

```python
from proxy.merkle import MerkleAuditTree

# Initialize tree with audit log records
records = [
    "call-001: agent-alice -> get_weather(location='NYC')",
    "call-002: agent-bob -> drop_table(table='users')",
    "call-003: agent-carol -> search_docs(query='api')",
]

tree = MerkleAuditTree(records)
root_hex = tree.get_root_hex()
print(f"Merkle Root: {root_hex}")

# Generate inclusion proof for record at index 1
proof = tree.generate_inclusion_proof(1)

# Verify proof against the Merkle Root
is_valid = MerkleAuditTree.verify_inclusion_proof(
    record=records[1],
    leaf_index=1,
    proof=proof,
    expected_root_hex=root_hex
)

assert is_valid is True
print("[+] Proof verified successfully! Record is untampered.")
```
