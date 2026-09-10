"""
MCP Sentinel Mesh - Cryptographically Chained Audit Ledger
Maintains an append-only, tamper-evident SHA-256 hash-chained sequence of all proxy operations.
"""

import hashlib
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from backend.schemas.contracts import AuditEvent


class AuditLedger:
    """
    Append-only SHA-256 hash-chained audit ledger.
    Every event contains the SHA-256 hash of the previous event.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self):
        self.events: List[AuditEvent] = []
        self._last_hash = self.GENESIS_HASH
        self._sequence = 0

    def record_event(
        self,
        event_type: str,
        principal: str,
        action: str,
        decision: str,
        payload_summary: Any,
        latency_ms: float = 0.0
    ) -> AuditEvent:
        """Records a new audit event and calculates its cryptographic digest."""
        seq = self._sequence
        prev_hash = self._last_hash
        timestamp = datetime.utcnow()

        # Digest of payload to protect privacy while ensuring verification
        if isinstance(payload_summary, (dict, list)):
            digest_str = json.dumps(payload_summary, sort_keys=True)
        else:
            digest_str = str(payload_summary)
        payload_digest = hashlib.sha256(digest_str.encode("utf-8")).hexdigest()

        # Build raw string for hashing
        record_str = f"{seq}|{prev_hash}|{timestamp.isoformat()}|{event_type}|{principal}|{action}|{decision}|{payload_digest}|{latency_ms:.2f}"
        current_hash = hashlib.sha256(record_str.encode("utf-8")).hexdigest()

        event = AuditEvent(
            sequence_index=seq,
            previous_hash=prev_hash,
            current_hash=current_hash,
            timestamp=timestamp,
            event_type=event_type,
            principal=principal,
            action=action,
            decision=decision,
            payload_digest=payload_digest,
            latency_ms=latency_ms
        )

        self.events.append(event)
        self._last_hash = current_hash
        self._sequence += 1
        return event

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Walks the entire audit chain from genesis to head and verifies all cryptographic hashes.
        Returns: { 'is_valid': bool, 'events_verified': int, 'corrupted_at_index': Optional[int] }
        """
        expected_prev_hash = self.GENESIS_HASH

        for idx, ev in enumerate(self.events):
            if ev.sequence_index != idx:
                return {
                    "is_valid": False,
                    "events_verified": idx,
                    "error": f"Sequence discontinuity at index {idx}",
                    "corrupted_at_index": idx
                }

            if ev.previous_hash != expected_prev_hash:
                return {
                    "is_valid": False,
                    "events_verified": idx,
                    "error": f"Hash chain broken at index {idx}: expected {expected_prev_hash}, got {ev.previous_hash}",
                    "corrupted_at_index": idx
                }

            record_str = f"{ev.sequence_index}|{ev.previous_hash}|{ev.timestamp.isoformat()}|{ev.event_type}|{ev.principal}|{ev.action}|{ev.decision}|{ev.payload_digest}|{ev.latency_ms:.2f}"
            calculated_hash = hashlib.sha256(record_str.encode("utf-8")).hexdigest()

            if calculated_hash != ev.current_hash:
                return {
                    "is_valid": False,
                    "events_verified": idx,
                    "error": f"Event hash mismatch at index {idx}",
                    "corrupted_at_index": idx
                }

            expected_prev_hash = ev.current_hash

        return {
            "is_valid": True,
            "events_verified": len(self.events),
            "head_hash": self._last_hash
        }

    def get_recent(self, limit: int = 50) -> List[AuditEvent]:
        return self.events[-limit:]
