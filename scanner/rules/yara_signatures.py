"""
MCP Sentinel Mesh - Adversarial YARA Signatures & Token Smuggling Detector
Inspects tool inputs, schemas, and prompts for invisible Unicode, homoglyph evasion, BiDi Trojan Source, and markdown exfiltration.
"""

from typing import List, Dict, Any, Tuple
import re
import unicodedata


class AdversarialSignatureDetector:
    """
    Advanced heuristic and signature engine detecting covert LLM token smuggling and evasion.
    """

    # Invisible zero-width and control characters
    ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u00ad"]

    # BiDi directional override markers (Trojan Source attacks)
    BIDI_OVERRIDES = ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e"]

    # Markdown covert image / link exfiltration patterns
    MARKDOWN_EXFIL_PATTERN = r"!\[.*?\]\((https?:\/\/[^\s\)]+[\?&](?:token|key|secret|data|leak)=[^ \)]+)\)"

    # Base64 encoded dangerous command signatures
    BASE64_EXEC_PATTERNS = [
        (r"ZXhlY", "Base64 encoded 'exec' prefix"),
        (r"c2hlbGw=", "Base64 encoded 'shell'"),
        (r"YmFzaCAtaQ==", "Base64 encoded 'bash -i'"),
        (r"L2Jpbi9zaA==", "Base64 encoded '/bin/sh'"),
    ]

    @classmethod
    def scan_text(cls, text: str) -> List[Dict[str, Any]]:
        """Scans input text for token smuggling, invisible characters, and covert vectors."""
        findings = []

        # 1. Zero-width character smuggling
        zw_matches = [ch for ch in cls.ZERO_WIDTH_CHARS if ch in text]
        if zw_matches:
            findings.append({
                "signature": "SIG-UNICODE-ZERO-WIDTH",
                "severity": "HIGH",
                "description": f"Detected {len(zw_matches)} invisible zero-width characters used for token smuggling or watermark evasion.",
                "characters": [f"\\u{ord(c):04x}" for c in zw_matches]
            })

        # 2. BiDi override spoofing (Trojan Source)
        bidi_matches = [ch for ch in cls.BIDI_OVERRIDES if ch in text]
        if bidi_matches:
            findings.append({
                "signature": "SIG-UNICODE-BIDI-OVERRIDE",
                "severity": "CRITICAL",
                "description": "Detected Unicode Bidirectional Override characters (Trojan Source code obfuscation attack).",
                "characters": [f"\\u{ord(c):04x}" for c in bidi_matches]
            })

        # 3. Markdown covert exfiltration
        md_match = re.search(cls.MARKDOWN_EXFIL_PATTERN, text, re.IGNORECASE)
        if md_match:
            findings.append({
                "signature": "SIG-MARKDOWN-DATA-EXFIL",
                "severity": "HIGH",
                "description": "Detected markdown image covert data exfiltration channel.",
                "target_url": md_match.group(1)
            })

        # 4. Base64 encoded payload smuggling
        for b64_sub, label in cls.BASE64_EXEC_PATTERNS:
            if b64_sub in text:
                findings.append({
                    "signature": "SIG-BASE64-EXEC-SMUGGLING",
                    "severity": "HIGH",
                    "description": f"Detected potential obfuscated payload: {label}."
                })

        return findings

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> str:
        """
        Normalizes mixed-script Cyrillic/Greek homoglyphs into their canonical ASCII equivalents
        to prevent evasion of keyword filters (e.g. Cyrillic 'а' -> ASCII 'a').
        """
        # NFKD normalization decomposes characters into canonical base letters
        normalized = unicodedata.normalize('NFKD', text)
        # Custom substitution table for tricky lookalikes
        homoglyph_map = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
            'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X'
        }
        res = []
        for char in normalized:
            res.append(homoglyph_map.get(char, char))
        return "".join(res)
