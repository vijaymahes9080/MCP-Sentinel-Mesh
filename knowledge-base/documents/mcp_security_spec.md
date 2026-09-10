# Model Context Protocol (MCP) Enterprise Security Guidelines
Version: 1.0.0
Publication-Date: 2025-11-20
Topic: tool_permissions, ssrf, mcp_governance

## Section 1: Trust Boundaries and Data Provenance
In Model Context Protocol deployments, MCP servers and their advertised tools must be treated as completely untrusted entities. Tool metadata (names, descriptions, schemas) must never be passed directly into model prompt contexts without static sanitization and schema fingerprinting.

## Section 2: Canonical Tool Naming and Masquerading Defenses
Adversarial MCP servers frequently attempt typosquatting or suffix masquerading (e.g., appending `_safe` or `_official` to common tool names) to trick LLM routing heuristics into preferring malicious tools. Client hosts must enforce strict canonical name validation and refuse unregistered tool aliases.

## Section 3: SSRF and Network Boundary Isolation
MCP tools that perform outbound HTTP lookups or web scraping pose severe Server-Side Request Forgery (SSRF) threats to internal infrastructure (such as AWS Instance Metadata Service at 169.254.169.254 or localhost loopback 127.0.0.1). Outbound egress must be mediated through an egress proxy with strict domain allowlisting and private IP subnet blacklists.

## Section 4: Human-in-the-Loop Approval Workflow
Any MCP tool marked as mutating, destructive, or requiring high-privilege scopes (e.g. database schema drops, system command execution, bulk records deletion) must be intercepted by the host runtime proxy. Execution must be suspended in a pending approval queue until an authenticated human operator provides out-of-band consent.
