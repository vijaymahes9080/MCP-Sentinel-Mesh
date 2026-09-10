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

        # Continuously sanitize the accumulated buffer so full matches are redacted immediately
        sanitized, count = OutputRedactor.sanitize_text(self.buffer)
        if count > 0:
            self.redactions_count += count
            self.buffer = sanitized

        # If buffer exceeds window_size, safely emit the leading portion older than window_size
        if len(self.buffer) > self.window_size:
            emit_len = len(self.buffer) - self.window_size
            to_emit = self.buffer[:emit_len]
            self.buffer = self.buffer[emit_len:]
            return to_emit

        return ""

    def finish(self) -> str:
        """Flushes and sanitizes all remaining bytes in the buffer upon stream closure."""
        if not self.buffer:
            return ""
        sanitized_tail, count = OutputRedactor.sanitize_text(self.buffer)
        if count > 0:
            self.redactions_count += count
            self.buffer = sanitized_tail
        tail = self.buffer
        self.buffer = ""
        return tail
