# OWASP Top 10 for Large Language Model Applications (2025/2026 Edition)
Version: 2.1.0
Publication-Date: 2026-01-15
Topic: prompt_injection, tool_permissions, secret_leakage

## LLM01: Direct & Indirect Prompt Injection
Direct prompt injections occur when user-crafted prompts alter the operational instructions of an LLM. Indirect prompt injections occur when an LLM accepts input from external sources (e.g., websites, files, MCP tool docstrings) that contain adversarial instructions.
Remediation: Constrain operational permissions, sandbox tools, and enforce strict input validation at the proxy mediation layer. Never allow retrieved content to override security policy.

## LLM02: Sensitive Information Disclosure
LLM applications can inadvertently reveal sensitive data, proprietary algorithms, API keys, and PII through tool outputs, error traces, or unredacted context windows.
Remediation: Implement deterministic runtime output redactors to sanitize API tokens, passwords, and PII before returning execution streams to caller models.

## LLM07: System Information Leakage
Detailed error messages, system prompts, or stack traces exposed to attackers facilitate reconnaissance and targeted exploitation.
Remediation: Sanitize internal exceptions; return generic error messages with opaque correlation IDs.

## LLM08: Excessive Agency & Unbounded Tool Use
Granting autonomous agents broad permissions, unconstrained tool access, or direct shell/database execution without human review enables catastrophic cascading failures.
Remediation: Enforce the Principle of Least Privilege, define granular permission scopes, and require human-in-the-loop approval for all mutating or destructive tool calls.
