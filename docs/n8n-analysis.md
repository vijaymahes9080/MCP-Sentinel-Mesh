# n8n Workflow Security Analysis Guide

## 1. Overview
Automated orchestration workflows created in n8n frequently bridge public webhooks with internal database partitions. When configured insecurely, they introduce severe privilege escalation and data exfiltration paths.

---

## 2. Analyzed Security Hazards

1. **Unauthenticated Webhooks (N8N-001)**:
   Trigger nodes without header authorization allow arbitrary external actors to dispatch workflow jobs.
2. **Dynamic Eval & Env Scraping in Code Nodes (N8N-002)**:
   Custom JavaScript nodes reading `process.env` leak master keys; executing `eval()` permits Remote Code Execution.
3. **Internal SSRF (N8N-003C)**:
   HTTP nodes targeting `127.0.0.1` or `169.254.169.254` allow attackers to query private services.
4. **Missing Human-in-the-Loop Gates (N8N-006)**:
   Workflows executing `DELETE` or `POST` requests without a manual review step.

---

## 3. Sample Workflows
- `n8n-samples/vulnerable_crm_sync.json`: Demonstrates all 4 security hazards, scoring 100/100 CRITICAL risk.
- `n8n-samples/hardened_crm_sync.json`: Implements Header Auth, input sanitization, 5000ms timeouts, and error triggers, scoring 0/100 CLEAN.
