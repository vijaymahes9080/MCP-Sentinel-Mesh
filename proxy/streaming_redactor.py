"""
MCP Sentinel Mesh - Streaming Token-by-Token Secret Redactor
Buffers and sanitizes fragmented secrets streaming over WebSockets or Server-Sent Events (SSE).
"""

from typing import List, Generator
from proxy.redactor import OutputRedactor


class StreamingSecretRedactor:
    """
    Sliding window buffer for streaming LLM outputs.
    Guarantees secrets split across token boundaries are intercepted before delivery.
    """

    def __init__(self, window_size: int = 128):
        self.window_size = window_size
        self.buffer = ""
        self.redactions_count = 0

    def feed_token(self, token: str) -> str:
        """
        Feeds a single streaming token chunk.
        Returns the safe, sanitized string slice ready for immediate client emission.
        """
        self.buffer += token

        # If buffer is shorter than window, hold to inspect potential split secret
        if len(self.buffer) < self.window_size:
            return ""

        # Check for potential secrets in the leading portion
        slice_to_inspect = self.buffer[:-self.window_size]
        trailing_buffer = self.buffer[-self.window_size:]

        # Run redactor on leading slice
        sanitized_slice, count = OutputRedactor.sanitize_text(slice_to_inspect)
        self.redactions_count += count
        self.buffer = trailing_buffer

        return sanitized_slice

    def finish(self) -> str:
        """Flushes and sanitizes all remaining bytes in the buffer upon stream closure."""
        if not self.buffer:
            return ""
        sanitized_tail, count = OutputRedactor.sanitize_text(self.buffer)
        self.redactions_count += count
        self.buffer = ""
        return sanitized_tail
