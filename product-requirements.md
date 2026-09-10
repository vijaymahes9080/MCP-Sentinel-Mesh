# Product Requirements Document (PRD): MCP Sentinel Mesh

## 1. Executive Summary
**MCP Sentinel Mesh** is an enterprise-grade security scanner, adversarial evaluation framework, and runtime policy proxy designed to govern the interaction surface between Model Context Protocol (MCP) servers, autonomous AI agents, and workflow automation platforms (n8n).

As autonomous agents gain tool-use agency via MCP, they expose organizations to novel attack surfaces:
1. **Tool Definition Poisoning**: Attackers embed hidden instructions, jailbreaks, or override directives inside tool docstrings to hijack agent execution.
2. **Excessive & Undeclared Permissions**: Tools claim to perform harmless lookups while silently executing shell commands or altering file systems.
3. **Indirect Prompt Injection**: External data retrieved via MCP tools triggers unconstrained agent behavior.
4. **Credential Exfiltration & SSRF**: Tools trick agents into echoing tokens or targeting internal infrastructure (`http://169.254.169.254`).
5. **Unattended Destructive Actions**: High-risk mutating operations executed without human-in-the-loop validation.

MCP Sentinel Mesh solves these threats through static analysis, adversarial evaluation benchmarks, and an inline ASGI policy proxy.

---

## 2. Core Personas
1. **Security Operations & AppSec Engineers**: Need automated CI/CD gating to prevent vulnerable or malicious MCP servers from being deployed.
2. **AI Platform Engineers**: Need a mediation layer to rate-limit, enforce RBAC, redact sensitive outputs, and intercept high-risk tool calls.
3. **Compliance & Audit Officers**: Need a cryptographically verifiable (tamper-evident SHA-256 hash chained) ledger of all agent tool actions.

---

## 3. Key Functional Requirements

### 3.1 Static MCP Scanner
- **FR-SCAN-01**: Parse MCP server manifests, JSON schema tool definitions, and OpenAPI tool representations.
- **FR-SCAN-02**: Execute deterministic security rules detecting prompt injections, shell/code execution, path traversal, network egress, credential exposure, missing argument bounds, and broad wildcards.
- **FR-SCAN-03**: Output standardized reports in JSON, Markdown, and SARIF v2.1.0 formats with explicit rule IDs, severity, confidence, evidence snippets, and remediation guidance.

### 3.2 Transparent Risk Engine
- **FR-RISK-01**: Compute transparent, reproducible risk scores (0–100) using a multi-factor formula evaluating Impact, Exploitability, Permission Scope, Data Sensitivity, Destructive Potential, Exposure, and Confidence.
- **FR-RISK-02**: Categorize scores into severity bands (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) with clear residual risk estimations.

### 3.3 Adversarial Test Engine
- **FR-ADV-01**: Provide an 80+ case curated adversarial test corpus spanning 8 distinct attack categories (Direct Prompt Injection, Indirect Document Injection, Secret Exfiltration, Privilege Escalation, Cross-User Access, Malformed Parameters, Replay / Duplicate Calls, Unsafe n8n Workflows).
- **FR-ADV-02**: Run isolated test harnesses against mock MCP servers with strict timeouts and zero reliance on production systems.

### 3.4 Runtime Policy Proxy
- **FR-PRX-01**: Mediate `POST /proxy/tool-call` with deny-by-default policy enforcement, identity context, token-bucket rate limiting, and replay prevention.
- **FR-PRX-02**: Provide a human-in-the-loop approval mechanism (`POST /approvals/{id}/approve` & `reject`) for high-risk and destructive tools.
- **FR-PRX-03**: Inspect and redact sensitive secrets (API keys, JWTs, private keys) from tool outputs before returning them to agents.
- **FR-PRX-04**: Maintain a SHA-256 chained, tamper-evident audit log of every call, decision, and latency metric.

### 3.5 n8n Workflow Analyzer
- **FR-N8N-01**: Parse exported n8n workflow JSON graphs.
- **FR-N8N-02**: Detect unauthenticated webhooks, dangerous Code/Function nodes, arbitrary HTTP requests, unbounded loops, missing error handling, and unredacted credential propagation.

### 3.6 RAG Security Knowledge Base
- **FR-RAG-01**: Ingest security policies, OWASP Top 10 for LLMs, and MCP specifications.
- **FR-RAG-02**: Retrieve exact citations to ground remediation recommendations for detected findings.

---

## 4. Non-Functional Requirements
- **NFR-PERF-01**: Proxy mediation latency must remain under 500 ms (excluding downstream tool execution).
- **NFR-SEC-01**: Deny-by-default architecture; unmapped tools or unrecognized parameters must be blocked immediately.
- **NFR-REL-01**: Scan report reproducibility must be $\ge 99\%$ across identical static inputs.
- **NFR-ACC-01**: Web dashboard must support WCAG 2.1 AA accessibility and include Tamil/English localization scaffolding.
