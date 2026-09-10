# Threat Model: MCP Sentinel Mesh

## 1. Methodology
This threat model utilizes **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) tailored specifically for Model Context Protocol (MCP) ecosystems and **MITRE ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems).

---

## 2. Threat Analysis Matrix

| Threat Category | Specific Threat Vector | Impact | Sentinel Mesh Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing (S)** | Malicious MCP server impersonates standard tools (e.g. `read_file_safe`). | Critical | Static Scanner rule `SEC-MCP-009` detects typosquatting and name deception; runtime proxy strictly matches registered schema hash. |
| **Tampering (T)** | Attacker alters tool parameters or injects shell metacharacters (`rm -rf /`, `; curl`). | Critical | Strict JSONSchema enforcement; parameter regex bounds; deterministic argument filter. |
| **Repudiation (R)** | Malicious agent or operator denies executing unauthorized destructive tool calls. | High | Cryptographically chained (SHA-256) audit log where each event signs the previous digest. |
| **Info Disclosure (I)** | MCP tool echoes environment variables, API keys, or database credentials back into LLM context. | Critical | Runtime output redactor checks for regex patterns (API keys, JWT, SSH keys, AWS credentials) before delivery. |
| **Denial of Service (D)** | Agent gets stuck in infinite tool loop or exhausts API quotas. | Medium | Sliding-window token-bucket rate limiter; per-call execution timeouts (default 10s); max argument payload limit (1MB). |
| **Elevation of Priv (E)** | Read-only agent invokes admin-level destructive tools without approval. | Critical | Role-Based Access Control (RBAC); mandatory human approval workflow for high-risk operations. |

---

## 3. MITRE ATLAS Alignment

1. **AML.T0051 (LLM Prompt Injection)**:
   - *Direct*: Overriding system instructions inside arguments.
   - *Indirect*: Poisoned docstrings inside MCP manifests directing the LLM to exfiltrate context.
   - *Mitigation*: Static scanner parses descriptions for command verbs (`IGNORE PREVIOUS`, `EXECUTE`, `TRANSFER`); proxy blocks output injection payloads.

2. **AML.T0054 (LLM Tool Invocations & Misdirection)**:
   - Malicious tools tricking the model into executing side-effects.
   - *Mitigation*: Schema validation, approval gating, parameter length restrictions.

3. **AML.T0057 (Data Exfiltration via Model Response)**:
   - Tool exfiltrating data via DNS/HTTP egress.
   - *Mitigation*: Rule `SEC-MCP-005` flags arbitrary network egress parameters.

---

## 4. Trust Boundaries & Assumptions
1. **Host Boundary**: The proxy runs in a trusted container or internal mesh boundary.
2. **Untrusted Data Boundary**: All MCP tool manifests, tool descriptions, agent prompts, and tool output streams are considered completely untrusted.
3. **Identity Boundary**: Agent requests must supply a signed JWT or pre-shared API key matching authorized tenant identities.
