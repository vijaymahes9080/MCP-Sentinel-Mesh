# Evaluation Plan: MCP Sentinel Mesh

## 1. Objectives
The evaluation suite validates the empirical security guarantees, runtime performance, and accuracy of MCP Sentinel Mesh across synthetic MCP servers, agent interactions, and n8n workflows.

---

## 2. Key Performance Indicators & Target Thresholds

| Metric | Definition | Target Threshold | Validation Method |
| :--- | :--- | :--- | :--- |
| **Detection Precision** | True Positives / (True Positives + False Positives) | $\ge 90\%$ | Automated static scan against 50 known benign and vulnerable manifests |
| **Detection Recall** | True Positives / (True Positives + False Negatives) | $\ge 95\%$ | Adversarial test suite with 80 seeded vulnerability vectors |
| **False Positive Rate (FPR)** | False Positives / (False Positives + True Negatives) | $< 5\%$ | Standard benign tool library evaluation |
| **Unauthorized Call Prevention** | Percentage of policy-violating calls successfully blocked | $100\%$ ($0$ unauthorized calls permitted) | Negative authorization test matrix |
| **Secret Leakage Prevention** | Zero high-entropy keys or credentials permitted in proxy outputs | $100\%$ ($0$ leaks) | Redaction fuzzer injecting mock AWS, OpenAI, and DB credentials |
| **Proxy Mediation Latency** | Median overhead introduced by the proxy per tool invocation | $< 500\text{ ms}$ (Target: $< 35\text{ ms}$ for local checks) | 1,000 synthetic call load test |
| **Report Reproducibility** | Percentage of identical findings generated on repeated scans of fixed input | $\ge 99.9\%$ | Deterministic idempotency hash check |
| **Audit Verification** | Detection of retroactive alteration or record deletion in audit chain | $100\%$ detection | Cryptographic chain corruption test |

---

## 3. Adversarial Test Corpus Distribution
The adversarial test corpus contains 80+ isolated test vectors structured across 8 domains:
1. **Direct Prompt Injection (10 cases)**: System prompt leaks, roleplay escape, instruction overriding.
2. **Indirect Document Injection (10 cases)**: Markdown-embedded command execution, hidden HTML tag payloads, zero-width spaces.
3. **Secret Exfiltration (10 cases)**: Environment variable scraping, webhook callback exfiltration, token theft.
4. **Privilege Escalation (10 cases)**: Role spoofing, parameter tampering (`sudo: true`, `as_admin: 1`), permission circumvention.
5. **Cross-User Access (10 cases)**: Insecure direct object references (IDOR), tenant boundary hopping, header spoofing.
6. **Malformed Parameters (10 cases)**: JSON type confusion, deeply nested objects, buffer overflow strings, format strings.
7. **Replay & Duplicate Calls (10 cases)**: Nonce reuse, transaction replay, rapid-fire race condition simulation.
8. **Unsafe n8n Workflows (10 cases)**: Unauthenticated webhook triggers, arbitrary code nodes, credentials in query strings.

---

## 4. Evaluation Artifacts
The benchmark engine produces:
- `evaluation.json`: Machine-readable results and metrics.
- `evaluation.md`: Human-readable summary table and breakdown.
- Visual charts: Precision-Recall radar, latency distribution, and risk scoring distribution generated via Matplotlib.
