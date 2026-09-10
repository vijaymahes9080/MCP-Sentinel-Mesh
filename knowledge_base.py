"""
Knowledge Base Python Bridge
Allows importing `knowledge_base` cleanly in Python environments.
"""

import os
import sys
import importlib.util

_kb_engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge-base", "engine.py")
_spec = importlib.util.spec_from_file_location("knowledge_base_engine_internal", _kb_engine_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

KnowledgeBaseEngine = _mod.KnowledgeBaseEngine
KnowledgeChunk = _mod.KnowledgeChunk
CitationResult = _mod.CitationResult

__all__ = ["KnowledgeBaseEngine", "KnowledgeChunk", "CitationResult"]
