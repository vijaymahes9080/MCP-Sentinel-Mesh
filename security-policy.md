# Security Policy: MCP Sentinel Mesh

## 1. Security Invariants
MCP Sentinel Mesh enforces the following non-negotiable security invariants across all subsystems:

1. **Deny by Default**: Any tool, argument, principal, or action not explicitly permitted by a loaded policy is rejected.
2. **Never Execute Scanned Code**: Static scanning operates strictly on schema parsing, AST inspection, and deterministic regex/heuristic analysis. No scanned manifest or script is ever executed.
3. **No Unsanitized Secret Reflection**: All tool responses pass through deterministic pattern-matching redactors before leaving the proxy boundary.
4. **Mandatory Human-in-the-Loop for Destructive Operations**: Any tool flagged with `is_destructive=True` or matching high-risk risk bands requires explicit out-of-band operator approval.
5. **Tamper-Evident Audit Integrity**: Audit events are cryptographically sequenced. If any historical log entry is modified, deleted, or inserted, the verification algorithm fails immediately.

---

## 2. Vulnerability Disclosure & Reporting
If you discover a security vulnerability within MCP Sentinel Mesh, please do not open a public issue. Send your report directly to:
- **Lead Security Maintainer**: Vijay Mahes
- **Email**: [Vijaypradhap2004@gmail.com](mailto:Vijaypradhap2004@gmail.com)
- **Response SLA**: Initial triage within 24 hours; patch and advisory release within 7 days.

---

## 3. Supported Versions

| Version | Supported | Security Updates |
| :--- | :--- | :--- |
| `1.0.x` | Yes | Active |
| `< 1.0.0` | No | End of Life |

---

## 4. Secure Defaults Checklist
- [x] CORS restricted to configured dashboard domains.
- [x] Hardened HTTP headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).
- [x] TLS 1.3 / HTTPS enforced in production deployment profiles.
- [x] Maximum request body size capped at 2MB.
- [x] JWT tokens verified with HMAC-SHA256 / RS256 with 1-hour expiration.
- [x] Database queries parameterized via SQLAlchemy ORM.
