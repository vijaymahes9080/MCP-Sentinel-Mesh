# Rules Catalog: MCP Sentinel Mesh

## Static MCP Security Rules

### SEC-MCP-001: Suspicious Prompt Injection Directive in Tool Description
- **Severity**: CRITICAL
- **Confidence**: CONFIRMED
- **Description**: Detects instructions embedded within tool descriptions attempting to override LLM system prompts (e.g. "Ignore previous instructions", "SYSTEM PROMPT:", "Do not reveal").
- **Remediation**: Sanitize tool descriptions; strip imperative instructions directing model behavior.
- **References**: OWASP LLM01, MITRE ATLAS AML.T0051.

### SEC-MCP-002: Undeclared Destructive Side Effects
- **Severity**: HIGH
- **Confidence**: CONFIRMED
- **Description**: Tool description or name contains mutating/destructive action verbs (`delete`, `drop`, `purge`, `modify`) while declaring read-only permissions.
- **Remediation**: Declare `is_destructive=True` and assign `write` or `admin` scopes.

### SEC-MCP-003: Unrestricted Shell or Code Execution Capability
- **Severity**: CRITICAL
- **Confidence**: CONFIRMED
- **Description**: Tool accepts arbitrary shell commands (`bash`, `sh`, `powershell`, `eval`, `exec`).
- **Remediation**: Replace raw command execution with strongly typed, bounded parameter tools.
- **References**: CWE-78, OWASP Command Injection.

### SEC-MCP-004: Unrestricted File-System Access or Path Traversal Vector
- **Severity**: HIGH
- **Confidence**: CONFIRMED
- **Description**: File path parameters lack regex pattern constraints or root sandbox jails.
- **Remediation**: Enforce `pattern` constraints prohibiting `..` and absolute paths.

### SEC-MCP-005: Unrestricted Network Egress / SSRF Risk
- **Severity**: HIGH
- **Confidence**: CONFIRMED
- **Description**: Unconstrained URL destination parameters susceptible to Server-Side Request Forgery.
- **Remediation**: Filter outbound egress; block `169.254.169.254`, `127.0.0.1`, and private IP subnets.

### SEC-MCP-006: Credential Exposure or Unsafe Default Secret
- **Severity**: CRITICAL
- **Confidence**: CONFIRMED
- **Description**: Hardcoded API keys, tokens, or default credentials found in schemas or descriptions.
- **Remediation**: Remove hardcoded credentials. Inject authentication via secure proxy headers.

### SEC-MCP-007: Missing Input Parameter Constraints
- **Severity**: MEDIUM
- **Confidence**: CONFIRMED
- **Description**: String parameters without `maxLength` or numeric parameters without `minimum`/`maximum`.
- **Remediation**: Add bounds to all parameters in JSONSchema.

### SEC-MCP-008: Broad Wildcard Selector in Tool Permissions
- **Severity**: MEDIUM
- **Confidence**: CONFIRMED
- **Description**: Non-read permission scopes granted wildcard (`*`) resource patterns.
- **Remediation**: Scope resources to specific prefixes (e.g. `reports/*`, `tables/users`).

### SEC-MCP-009: Tool Naming Deception or Masquerading
- **Severity**: HIGH
- **Confidence**: SUSPECTED
- **Description**: Tool name uses deceptive safety suffixes (`_safe`, `_official`, `_secure`) to manipulate LLM routing.
- **Remediation**: Enforce canonical tool naming standards.

### SEC-MCP-010: Conflicting Permission Declarations
- **Severity**: HIGH
- **Confidence**: CONFIRMED
- **Description**: Tool declares read-only permissions but parameters include destructive flags (`force_delete`, `overwrite`).
- **Remediation**: Reconcile parameter declarations with permission scopes.

### SEC-MCP-011: Missing Authentication Scope Declaration
- **Severity**: LOW
- **Confidence**: CONFIRMED
- **Description**: Empty permissions array leaves operational boundary undeclared.
- **Remediation**: Define explicit permission scope entries.

### SEC-MCP-012: Missing Output Sensitivity Classification
- **Severity**: MEDIUM
- **Confidence**: DETECTED
- **Description**: Tool accesses sensitive keywords (passwords, tokens, user data) without data classification labels.
- **Remediation**: Tag permissions with `confidential` or `restricted`.

---

## n8n Static Workflow Rules

### N8N-001: Unauthenticated Webhook Trigger
- **Severity**: HIGH | **Fix**: Require Header Auth, Basic Auth, or HMAC signatures.

### N8N-002: Dangerous Expression in Code Node
- **Severity**: CRITICAL | **Fix**: Disallow `process.env`, `eval()`, and `child_process`. Use n8n credentials.

### N8N-003A: Disabled TLS Certificate Verification
- **Severity**: HIGH | **Fix**: Set `allowUnauthorizedCerts: false`.

### N8N-003B: Missing Request Timeout
- **Severity**: MEDIUM | **Fix**: Configure explicit timeout (e.g. 5000 ms).

### N8N-003C: SSRF to Internal Address
- **Severity**: CRITICAL | **Fix**: Block requests targeting localhost or cloud metadata.

### N8N-004: Hardcoded Secret in Node Parameters
- **Severity**: CRITICAL | **Fix**: Move credentials to n8n Credential Store.

### N8N-005: Missing Error Trigger Handler
- **Severity**: LOW | **Fix**: Attach `n8n-nodes-base.errorTrigger` for dead-letter handling.

### N8N-006: Mutating Action Without Approval Gate
- **Severity**: MEDIUM | **Fix**: Insert a Sentinel approval node before destructive HTTP actions.
