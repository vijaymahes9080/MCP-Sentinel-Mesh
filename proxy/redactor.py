"""
MCP Sentinel Mesh - Runtime Output Redactor & Secret Filter
Sanitizes sensitive credentials, tokens, and PII from tool outputs before returning them to calling agents.
"""

import re
from typing import Any, Tuple, Dict, List


class OutputRedactor:
    """
    Deterministic pattern-based output redactor for tool responses.
    """

    REDACTION_RULES = [
        # AWS Access Keys
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
        # OpenAI / Anthropic API Keys
        (r"sk-[a-zA-Z0-9_-]{20,}", "[REDACTED_API_KEY]"),
        # GitHub Tokens
        (r"gh[pousr]_[a-zA-Z0-9]{36,}", "[REDACTED_GITHUB_TOKEN]"),
        # Slack Webhooks
        (r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]+", "[REDACTED_SLACK_WEBHOOK]"),
        # Private Keys (PEM)
        (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
        # JWT Tokens
        (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "[REDACTED_JWT_TOKEN]"),
        # Database URIs with Passwords
        (r"(mongodb(?:\+srv)?|postgres|postgresql|mysql|redis)://([^:]+):([^@]+)@", r"\1://\2:[REDACTED_PASSWORD]@"),
        # Credit Card Numbers (Luhn-style patterns)
        (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "[REDACTED_CREDIT_CARD]"),
        # US Social Security Numbers
        (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        # Generic Secret Keyword Bindings
        (r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]", r"\1='[REDACTED_SECRET]'"),
    ]

    @classmethod
    def sanitize_text(cls, text: str) -> Tuple[str, int]:
        """Sanitizes a single string, returning (cleaned_text, replacements_count)."""
        count = 0
        cleaned = text
        for pattern, replacement in cls.REDACTION_RULES:
            matches = len(re.findall(pattern, cleaned))
            if matches > 0:
                count += matches
                cleaned = re.sub(pattern, replacement, cleaned)
        return cleaned, count

    @classmethod
    def sanitize(cls, data: Any) -> Tuple[Any, int]:
        """Recursively traverses dictionaries, lists, and primitives to sanitize secrets."""
        if isinstance(data, str):
            return cls.sanitize_text(data)
        elif isinstance(data, dict):
            total_count = 0
            new_dict = {}
            for k, v in data.items():
                # Also sanitize key if it contains secret
                sanitized_val, c = cls.sanitize(v)
                new_dict[k] = sanitized_val
                total_count += c
            return new_dict, total_count
        elif isinstance(data, list):
            total_count = 0
            new_list = []
            for item in data:
                sanitized_item, c = cls.sanitize(item)
                new_list.append(sanitized_item)
                total_count += c
            return new_list, total_count
        else:
            return data, 0
