# Runtime Proxy & Policy Engine Guide

## 1. Mediation Pipeline
Every incoming `ToolCall` dispatched through `POST /proxy/tool-call` undergoes the following verification stages:

```
[Agent ToolCall]
      │
      ▼
1. Replay & Nonce Cache Check (Reject if duplicate in 300s)
      │
      ▼
2. Tool Registration Check (Deny by default if unregistered)
      │
      ▼
3. JSONSchema & Bounds Check (Types, maxLength, pattern)
      │
      ▼
4. Argument Injection Filters (Reject path traversal / prompt injection strings)
      │
      ▼
5. Sliding-Window Rate Limiter (Default: 60 req/min per principal)
      │
      ▼
6. Priority Policy Rules Evaluation
      ├──> [DENY] ───> Audit Event ───> 403 Forbidden Response
      ├──> [REQUIRE_APPROVAL] ───> Approval Request Created ───> 200 PENDING
      └──> [ALLOW] ───> Dispatch to Adapter ───> Redactor ───> Audit ───> 200 SUCCESS
```

---

## 2. Policy Rule Declaration
Policy rules are defined via declarative Pydantic schemas:
```json
{
  "rule_id": "POL-CUSTOM-001",
  "name": "Require Approval on Customer DB Mutate",
  "effect": "REQUIRE_APPROVAL",
  "priority": 15,
  "match_principals": ["*"],
  "match_tools": ["update_customer_*", "delete_customer_*"],
  "requires_approval_if_destructive": true
}
```

---

## 3. Cryptographic Audit Hashing
Audit records are sequenced in a monotonic chain:
$$\text{CurrentHash} = \text{SHA256}(\text{Seq} \parallel \text{PrevHash} \parallel \text{Timestamp} \parallel \text{Type} \parallel \text{Principal} \parallel \text{Action} \parallel \text{Decision} \parallel \text{PayloadDigest} \parallel \text{Latency})$$
Audit integrity can be verified at any moment via `GET /audit` or `audit_ledger.verify_integrity()`.
