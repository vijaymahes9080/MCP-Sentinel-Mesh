# n8n Workflow Automation Hardening Standards
Version: 1.2.0
Publication-Date: 2026-02-10
Topic: n8n_governance, secret_leakage, ssrf

## Standard 1: Webhook Trigger Authentication
All external Webhook trigger nodes in production n8n workflows must require authentication. Supported authentication models include Header Auth (API token check), Basic Auth, or cryptographic HMAC-SHA256 signature verification. Workflows configured with `authentication: none` are vulnerable to unauthenticated abuse and distributed denial of service.

## Standard 2: Secure Code Node Execution
Custom JavaScript code nodes (`n8n-nodes-base.code`) must never access global Node.js runtime objects like `process.env`, `eval()`, or `child_process`. Database credentials and secret keys must be referenced via n8n's encrypted credential manager rather than inlined in scripts.

## Standard 3: Outbound HTTP Timeouts and Certificate Validation
Every HTTP Request node must define an explicit timeout (recommended: 5000 ms to 10000 ms). Disabling SSL/TLS certificate verification (`allowUnauthorizedCerts: true`) in production workflows is strictly prohibited, as it exposes workflow data to active Man-in-the-Middle eavesdropping.
