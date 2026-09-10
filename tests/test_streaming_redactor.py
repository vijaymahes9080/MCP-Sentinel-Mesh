"""
Unit Tests for Streaming Token-by-Token Secret Redactor
"""

import pytest
from proxy.streaming_redactor import StreamingSecretRedactor


def test_fragmented_secret_redaction_across_tokens():
    redactor = StreamingSecretRedactor(window_size=32)
    # Split token across small chunks
    tokens = ["Hello, ", "here is ", "your key: ", "sk-", "live-", "abcdef1234567890", "abcdef1234567890", ". Please ", "guard it."]
    emitted = []

    for t in tokens:
        out = redactor.feed_token(t)
        if out:
            emitted.append(out)

    emitted.append(redactor.finish())
    full_output = "".join(emitted)

    assert "sk-live" not in full_output
    assert "[REDACTED_API_KEY]" in full_output
    assert redactor.redactions_count >= 1
