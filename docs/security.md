# Security Hardening & Known Limitations

## 1. Security Hardening Checklist
- [x] **Deny by Default**: Unrecognized tools or parameters are rejected unconditionally.
- [x] **Zero Code Execution on Scanned Files**: Manifests and workflows are parsed via static AST and JSON parsing; no code is evaluated.
- [x] **Deterministic Output Redaction**: Regular expression patterns scrub AWS keys, OpenAI tokens, GitHub PATs, JWTs, and database credentials before returning results.
- [x] **Tamper-Evident SHA-256 Audit Trail**: Chained hashes detect retroactive tampering or deletion of event records.
- [x] **Replay & DoS Protection**: Call IDs are tracked in a 300-second cache; sliding-window rate limiters cap request frequency.
- [x] **Strict HTTP Security Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`.

---

## 2. Known Limitations & Scope Boundaries
1. **Zero-Day Obfuscated Prompt Injections**: Sophisticated multilingual linguistic ciphers or novel token-smuggling techniques may evade static keyword/regex rules; defense-in-depth relies on runtime parameter bounds and least privilege.
2. **Dynamic In-Memory MCP Modifications**: If an external MCP server dynamically mutates its tool capabilities after proxy registration without re-registering, the schema hash check will flag divergence; however, network-level inspection is required to catch socket-level drift.
3. **Local Inference Independence**: MCP Sentinel Mesh deliberately relies on deterministic rules for all security-critical decisions. Local LLMs (Ollama) are optional and restricted to narrative remediation advice.

---

## 3. Reporting Vulnerabilities
Direct security advisories to:
- **Vijay Mahes**: [Vijaypradhap2004@gmail.com](mailto:Vijaypradhap2004@gmail.com)
