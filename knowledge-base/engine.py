"""
MCP Sentinel Mesh - RAG Security Knowledge Base Engine
Ingests cybersecurity advisories and provides grounded citations for remediation.
Used strictly for explanation and remediation support (never for primary gatekeeping).
"""

import os
import re
import hashlib
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class KnowledgeChunk(BaseModel):
    chunk_id: str
    source_title: str
    version: str
    local_path: str
    section: str
    page: int = 1
    publication_date: str
    content: str
    topics: List[str] = Field(default_factory=list)
    sha256_hash: str


class CitationResult(BaseModel):
    source_title: str
    section: str
    citation_text: str
    confidence_score: float
    local_path: str
    relevance_rationale: str


class KnowledgeBaseEngine:
    """
    RAG ingestion and passage citation engine.
    """

    def __init__(self, documents_dir: Optional[str] = None):
        self.documents_dir = documents_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "documents")
        self.chunks: List[KnowledgeChunk] = []
        self._ingest_all()

    def _ingest_all(self):
        if not os.path.exists(self.documents_dir):
            return

        for fname in os.listdir(self.documents_dir):
            if fname.endswith(".md") or fname.endswith(".txt"):
                fpath = os.path.join(self.documents_dir, fname)
                self._ingest_markdown_file(fpath)

    def _ingest_markdown_file(self, file_path: str):
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()

        file_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        # Parse header metadata
        title = "Security Reference"
        version = "1.0.0"
        pub_date = "2026-01-01"
        topics = ["general"]

        title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        if title_match:
            title = title_match.group(1).strip()

        ver_match = re.search(r"^Version:\s*(.+)$", text, re.MULTILINE)
        if ver_match:
            version = ver_match.group(1).strip()

        date_match = re.search(r"^Publication-Date:\s*(.+)$", text, re.MULTILINE)
        if date_match:
            pub_date = date_match.group(1).strip()

        topic_match = re.search(r"^Topic:\s*(.+)$", text, re.MULTILINE)
        if topic_match:
            topics = [t.strip() for t in topic_match.group(1).split(",")]

        # Split into sections by H2 headers
        sections = re.split(r"\n(?=##\s+)", text)
        for idx, sec in enumerate(sections):
            if not sec.strip():
                continue
            sec_title_match = re.search(r"^##\s+(.+)$", sec, re.MULTILINE)
            section_title = sec_title_match.group(1).strip() if sec_title_match else f"Section {idx+1}"

            chunk = KnowledgeChunk(
                chunk_id=f"{os.path.basename(file_path)}:sec-{idx+1}",
                source_title=title,
                version=version,
                local_path=file_path,
                section=section_title,
                page=1,
                publication_date=pub_date,
                content=sec.strip(),
                topics=topics,
                sha256_hash=file_hash
            )
            self.chunks.append(chunk)

    def search(
        self,
        query: str,
        topic: Optional[str] = None,
        min_confidence: float = 0.40,
        top_k: int = 3
    ) -> List[CitationResult]:
        """
        Retrieves matching passages with keyword scoring and confidence thresholding.
        Rejects matches below min_confidence.
        """
        query_terms = set(re.findall(r"\w+", query.lower()))
        scored_results = []

        for chunk in self.chunks:
            if topic and topic not in chunk.topics and topic != "all":
                continue

            chunk_text = f"{chunk.source_title} {chunk.section} {chunk.content}".lower()
            chunk_terms = set(re.findall(r"\w+", chunk_text))

            if not query_terms:
                continue

            # Jaccard + term presence score
            intersection = query_terms.intersection(chunk_terms)
            if not intersection:
                continue

            # Simple TF heuristic
            tf_score = sum(chunk_text.count(t) for t in intersection) / (len(chunk_terms) + 10)
            overlap_ratio = len(intersection) / len(query_terms)
            confidence = min(1.0, (overlap_ratio * 0.7) + (tf_score * 3.0))

            if confidence >= min_confidence:
                scored_results.append((confidence, chunk))

        # Sort descending by confidence
        scored_results.sort(key=lambda x: x[0], reverse=True)
        results: List[CitationResult] = []

        for conf, chunk in scored_results[:top_k]:
            results.append(CitationResult(
                source_title=chunk.source_title,
                section=chunk.section,
                citation_text=chunk.content[:400] + ("..." if len(chunk.content) > 400 else ""),
                confidence_score=round(conf, 2),
                local_path=chunk.local_path,
                relevance_rationale=f"Passage matches query concepts with {conf*100:.1f}% confidence."
            ))

        return results
