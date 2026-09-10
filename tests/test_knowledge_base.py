"""
Unit and Integration Tests for RAG Security Knowledge Base
"""

import pytest
from knowledge_base import KnowledgeBaseEngine


@pytest.fixture
def kb():
    return KnowledgeBaseEngine()


def test_kb_initialization(kb):
    assert len(kb.chunks) > 0


def test_kb_semantic_search(kb):
    hits = kb.search("prompt injection directives in tool description", topic="prompt_injection")
    assert len(hits) > 0
    assert hits[0].confidence_score >= 0.40
    assert "LLM01" in hits[0].section or "Prompt Injection" in hits[0].source_title or "Trust Boundaries" in hits[0].section


def test_kb_weak_evidence_rejection(kb):
    # Completely nonsensical random characters query should yield zero citations
    hits = kb.search("zyxwvutsrqponmlkjihgfedcba9876543210", min_confidence=0.50)
    assert len(hits) == 0
