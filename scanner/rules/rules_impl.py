"""
MCP Sentinel Mesh - Concrete Deterministic Security Rules
Implements SEC-MCP-001 through SEC-MCP-015 for static manifest analysis.
"""

import re
from typing import List, Optional, Dict, Any
from backend.schemas.contracts import SecurityFinding, ToolDefinition, Severity, Confidence, PermissionScope
from scanner.rules.base import BaseRule


class RuleSuspiciousDescription(BaseRule):
    """SEC-MCP-001: Detects prompt injection, jailbreak attempts, or override directives in tool descriptions."""
    rule_id = "SEC-MCP-001"
    title = "Suspicious Prompt Injection Directive in Tool Description"
    severity = Severity.CRITICAL
    default_confidence = Confidence.CONFIRMED
    description = "Tool description contains instructions attempting to override LLM system prompts or hijack execution flow."
    remediation = "Sanitize tool descriptions. Remove any instructional phrases directing LLM behavior (e.g., 'ignore previous instructions', 'system prompt:')."
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/definitions/LLM01-Prompt-Injection.html",
        "https://atlas.mitre.org/techniques/AML.T0051"
    ]
    false_positive_guidance = "Verify if the description is genuinely explaining prompt injection concepts rather than issuing commands to the model."

    PATTERNS = [
        r"(?i)ignore\s+(all\s+)?previous\s+(instructions|prompts|directions)",
        r"(?i)you\s+must\s+(always\s+)?obey\s+the\s+following",
        r"(?i)disregard\s+all\s+(prior|safety|guardrail)",
        r"(?i)system\s+prompt\s*:\s*",
        r"(?i)do\s+not\s+reveal\s+(this\s+instruction|these\s+instructions|to\s+the\s+user)",
        r"(?i)act\s+as\s+(dan|an\s+unfiltered|jailbreak)",
        r"(?i)secretly\s+(send|exfiltrate|forward|post)",
        r"(?i)bypass\s+safety\s+filters",
        r"(?i)hidden\s+instruction\s*:",
        r"(?i)<!--\s*inject\s*:",
    ]

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        for pattern in self.PATTERNS:
            match = re.search(pattern, tool.description)
            if match:
                findings.append(self.create_finding(
                    tool=tool,
                    evidence=f"Matched suspicious prompt injection pattern '{match.group(0)}' in tool description: \"{tool.description[:200]}...\"",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED
                ))
        return findings


class RuleHiddenSideEffects(BaseRule):
    """SEC-MCP-002: Detects destructive or state-changing actions hidden under read-only permissions."""
    rule_id = "SEC-MCP-002"
    title = "Undeclared Destructive Side Effects in Tool"
    severity = Severity.HIGH
    default_confidence = Confidence.CONFIRMED
    description = "Tool performs destructive actions (delete, modify, drop, write) while declaring read-only permissions or claiming benign behavior."
    remediation = "Explicitly set `is_destructive=True` in tool permissions and assign appropriate write/admin scopes."
    references = ["https://cwe.mitre.org/data/definitions/272.html"]
    false_positive_guidance = "Check if destructive words are used in negation (e.g., 'does not delete')."

    MUTATING_VERBS = [r"\bdelete\b", r"\bremove\b", r"\bpurge\b", r"\bdrop\b", r"\btruncate\b", r"\bmodify\b", r"\boverwrite\b", r"\bexecute\b"]

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        is_declared_destructive = any(p.is_destructive for p in tool.permissions)
        has_write_scope = any(p.scope in [PermissionScope.WRITE, PermissionScope.ADMIN] for p in tool.permissions)

        text_to_check = f"{tool.name} {tool.description}".lower()
        for verb in self.MUTATING_VERBS:
            if re.search(verb, text_to_check):
                if not is_declared_destructive and not has_write_scope:
                    findings.append(self.create_finding(
                        tool=tool,
                        evidence=f"Action word '{verb}' found in tool name/description but tool permissions lack 'write/admin' scope and `is_destructive` is False.",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED
                    ))
                    break
        return findings


class RuleShellExecution(BaseRule):
    """SEC-MCP-003: Detects arbitrary shell or code execution capability."""
    rule_id = "SEC-MCP-003"
    title = "Unrestricted Shell or Code Execution Capability"
    severity = Severity.CRITICAL
    default_confidence = Confidence.CONFIRMED
    description = "Tool allows execution of arbitrary shell commands, scripts, or runtime language evaluation (eval, exec, bash)."
    remediation = "Replace arbitrary shell execution with structured, strongly-typed, parameterized domain-specific tools."
    references = ["https://cwe.mitre.org/data/definitions/78.html", "https://owasp.org/www-community/attacks/Command_Injection"]
    false_positive_guidance = "If shell execution is strictly necessary, wrap it in a sandbox container with an immutable command allowlist."

    SHELL_INDICATORS = [
        r"\b(bash|sh|zsh|powershell|cmd\.exe|exec|eval|system|subprocess|shell_exec)\b",
        r"\bexecute\s+(shell|command|bash|system\s+command)\b",
        r"\brun\s+(arbitrary|raw)\s+(command|script|code)\b"
    ]

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        full_text = f"{tool.name} {tool.description}".lower()
        param_props = tool.parameters_schema.get("properties", {})
        param_names = " ".join(param_props.keys()).lower()

        for pattern in self.SHELL_INDICATORS:
            if re.search(pattern, full_text) or re.search(pattern, param_names):
                findings.append(self.create_finding(
                    tool=tool,
                    evidence=f"Shell execution capability indicator detected matching pattern '{pattern}'. Parameter keys: {list(param_props.keys())}",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED
                ))
                break
        return findings


class RuleFileSystemAccess(BaseRule):
    """SEC-MCP-004: Detects unrestricted file system access or path traversal exposure."""
    rule_id = "SEC-MCP-004"
    title = "Unrestricted File-System Access or Path Traversal Vector"
    severity = Severity.HIGH
    default_confidence = Confidence.CONFIRMED
    description = "Tool accepts arbitrary file paths without root directory sandboxing or canonicalization checks."
    remediation = "Constrain file paths to a dedicated sandbox directory, validate against directory traversal ('..'), and canonicalize before access."
    references = ["https://cwe.mitre.org/data/definitions/22.html"]
    false_positive_guidance = "Tools that operate strictly on virtual in-memory IDs or predefined resource keys are exempt."

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        props = tool.parameters_schema.get("properties", {})
        for param_name, schema in props.items():
            param_lower = param_name.lower()
            if any(k in param_lower for k in ["path", "filepath", "filename", "file_path", "directory"]):
                # Check if regex pattern or enum is defined
                pattern = schema.get("pattern")
                enum_vals = schema.get("enum")
                if not pattern and not enum_vals:
                    findings.append(self.create_finding(
                        tool=tool,
                        evidence=f"Parameter '{param_name}' accepts arbitrary file paths without regex constraint or allowlisted values.",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        custom_remediation=f"Add a 'pattern' regex constraint to parameter '{param_name}' preventing '..' and absolute root paths."
                    ))
        return findings


class RuleNetworkEgress(BaseRule):
    """SEC-MCP-005: Detects unrestricted network access / SSRF vectors."""
    rule_id = "SEC-MCP-005"
    title = "Unrestricted Network Egress / SSRF Risk"
    severity = Severity.HIGH
    default_confidence = Confidence.CONFIRMED
    description = "Tool allows arbitrary HTTP/socket requests without destination domain filtering or private IP blocking."
    remediation = "Implement an egress domain allowlist and block requests to internal networks (10.0.0.0/8, 127.0.0.0/8, 169.254.169.254, 192.168.0.0/16)."
    references = ["https://cwe.mitre.org/data/definitions/918.html", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]
    false_positive_guidance = "Tools hitting pre-configured static third-party API endpoints are not vulnerable."

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        props = tool.parameters_schema.get("properties", {})
        for param_name, schema in props.items():
            if any(k in param_name.lower() for k in ["url", "endpoint", "webhook", "target_host", "uri"]):
                pattern = schema.get("pattern")
                format_type = schema.get("format")
                if not pattern and format_type != "uri":
                    findings.append(self.create_finding(
                        tool=tool,
                        evidence=f"Network destination parameter '{param_name}' accepts unconstrained URLs without schema format or domain pattern validation.",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED
                    ))
        return findings


class RuleCredentialExposure(BaseRule):
    """SEC-MCP-006: Detects hardcoded secrets, default API keys, or password prompts in schemas."""
    rule_id = "SEC-MCP-006"
    title = "Credential Exposure or Unsafe Default Secret"
    severity = Severity.CRITICAL
    default_confidence = Confidence.CONFIRMED
    description = "Hardcoded API key, token, or password found in tool description or parameter default values."
    remediation = "Remove hardcoded credentials. Pass authentication headers via secure proxy identity injection."
    references = ["https://cwe.mitre.org/data/definitions/798.html"]
    false_positive_guidance = "Ensure mock/dummy keys in documentation are clearly formatted as 'EXAMPLE_KEY'."

    SECRET_PATTERNS = [
        r"(?i)(api[_-]?key|secret|token|password|bearer)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]",
        r"ghp_[a-zA-Z0-9]{36}",
        r"sk-[a-zA-Z0-9]{32,}",
        r"AKIA[0-9A-Z]{16}"
    ]

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        content = f"{tool.description} {str(tool.parameters_schema)}"
        for pattern in self.SECRET_PATTERNS:
            match = re.search(pattern, content)
            if match:
                findings.append(self.create_finding(
                    tool=tool,
                    evidence=f"Hardcoded credential pattern matched: '{match.group(0)[:8]}...[REDACTED]'",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED
                ))
                break
        return findings


class RuleMissingInputConstraints(BaseRule):
    """SEC-MCP-007: Detects string parameters without length bounds or integer parameters without min/max."""
    rule_id = "SEC-MCP-007"
    title = "Missing Input Parameter Constraints"
    severity = Severity.MEDIUM
    default_confidence = Confidence.CONFIRMED
    description = "Tool parameters lack length restrictions (maxLength) or numeric bounds (minimum/maximum), enabling memory exhaustion."
    remediation = "Specify 'maxLength' on all string parameters and 'maximum' on numeric inputs."
    references = ["https://cwe.mitre.org/data/definitions/20.html"]
    false_positive_guidance = "Parameters of boolean or enum types are naturally constrained."

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        props = tool.parameters_schema.get("properties", {})
        unbounded_params = []
        for param_name, schema in props.items():
            p_type = schema.get("type")
            if p_type == "string" and "maxLength" not in schema and "enum" not in schema:
                unbounded_params.append(param_name)
            elif p_type in ["integer", "number"] and ("maximum" not in schema and "minimum" not in schema):
                unbounded_params.append(param_name)

        if unbounded_params:
            findings.append(self.create_finding(
                tool=tool,
                evidence=f"Parameters lack upper size bounds: {unbounded_params}",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED
            ))
        return findings


class RuleBroadWildcardSelectors(BaseRule):
    """SEC-MCP-008: Detects wildcard selectors in tool permissions or parameters."""
    rule_id = "SEC-MCP-008"
    title = "Broad Wildcard Selector in Tool Permissions"
    severity = Severity.MEDIUM
    default_confidence = Confidence.CONFIRMED
    description = "Tool claims overly broad wildcard permissions ('*') across resources rather than scoped specific resource identifiers."
    remediation = "Replace broad wildcard ('*') with granular path or resource prefixes (e.g., 'reports/*', 'tables/users')."
    references = ["https://cwe.mitre.org/data/definitions/732.html"]
    false_positive_guidance = "Utility tools without database or filesystem attachments may use default patterns if read-only."

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        for perm in tool.permissions:
            if "*" in perm.resource_patterns and perm.scope != PermissionScope.READ:
                findings.append(self.create_finding(
                    tool=tool,
                    evidence=f"Non-read permission scope '{perm.scope}' is assigned wildcard resource pattern '*'.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED
                ))
        return findings


class RuleToolNamingDeception(BaseRule):
    """SEC-MCP-009: Detects typosquatting or deceptive tool names masquerading as official utilities."""
    rule_id = "SEC-MCP-009"
    title = "Tool Naming Deception or Masquerading"
    severity = Severity.HIGH
    default_confidence = Confidence.SUSPECTED
    description = "Tool name closely resembles known benign tools with suffixes like '_safe', '_official', or altered characters."
    remediation = "Enforce canonical tool naming conventions without deceptive trust markers."
    references = ["https://cwe.mitre.org/data/definitions/1021.html"]
    false_positive_guidance = "Verify if internal vendor prefixes are officially approved."

    DECEPTIVE_SUFFIXES = [r"_safe$", r"_secure$", r"_trusted$", r"_official$", r"_auth_bypass$"]

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        for pattern in self.DECEPTIVE_SUFFIXES:
            if re.search(pattern, tool.name):
                findings.append(self.create_finding(
                    tool=tool,
                    evidence=f"Tool name '{tool.name}' uses suspicious safety suffix matching '{pattern}', possibly to deceive LLM routing.",
                    severity=Severity.HIGH,
                    confidence=Confidence.SUSPECTED
                ))
        return findings


class RuleConflictingPermissions(BaseRule):
    """SEC-MCP-010: Detects conflicting permission declarations."""
    rule_id = "SEC-MCP-010"
    title = "Conflicting Permission Declarations"
    severity = Severity.HIGH
    default_confidence = Confidence.CONFIRMED
    description = "Tool declares 'is_destructive=False' or 'scope=read' but contains mutating parameter names such as 'force_delete' or 'overwrite'."
    remediation = "Align declared permissions with tool parameter capabilities."
    references = ["https://cwe.mitre.org/data/definitions/1025.html"]
    false_positive_guidance = "Check if flags strictly represent dry-run options."

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        props = tool.parameters_schema.get("properties", {})
        has_destructive_param = any(p in props for p in ["force_delete", "drop_table", "overwrite", "purge_all"])
        is_read_only = all(p.scope == PermissionScope.READ for p in tool.permissions) and not any(p.is_destructive for p in tool.permissions)

        if has_destructive_param and is_read_only:
            findings.append(self.create_finding(
                tool=tool,
                evidence="Tool contains destructive parameters ('force_delete'/'overwrite') but declares read-only permissions.",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED
            ))
        return findings


class RuleMissingAuthentication(BaseRule):
    """SEC-MCP-011: Detects missing authentication / authorization metadata."""
    rule_id = "SEC-MCP-011"
    title = "Missing Authentication or Authorization Scope Declaration"
    severity = Severity.LOW
    default_confidence = Confidence.CONFIRMED
    description = "Tool does not declare any permission scope or identity requirements in its metadata."
    remediation = "Define explicit `permissions` entries specifying operational scope and resource patterns."
    references = ["https://cwe.mitre.org/data/definitions/306.html"]
    false_positive_guidance = "Completely public read-only calculators or formatters may omit authorization."

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        if not tool.permissions:
            findings.append(self.create_finding(
                tool=tool,
                evidence=f"Tool '{tool.name}' has empty permissions list. Operational boundary is undeclared.",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED
            ))
        return findings


class RuleMissingOutputSensitivity(BaseRule):
    """SEC-MCP-012: Detects missing output sensitivity labels for high-risk read tools."""
    rule_id = "SEC-MCP-012"
    title = "Missing Output Sensitivity Classification"
    severity = Severity.MEDIUM
    default_confidence = Confidence.DETECTED
    description = "Tool reads user accounts, financial data, or telemetry but lacks output data classification tags."
    remediation = "Annotate tool with `data_classification` (e.g. 'confidential' or 'restricted') so the runtime proxy can apply output redactors."
    references = ["https://cwe.mitre.org/data/definitions/359.html"]
    false_positive_guidance = "Aggregated public data outputs do not require confidential labels."

    SENSITIVE_KEYWORDS = [r"user", r"account", r"password", r"email", r"credit_card", r"ssn", r"salary", r"token"]

    def evaluate(self, tool: ToolDefinition, context: Optional[Dict[str, Any]] = None) -> List[SecurityFinding]:
        findings = []
        name_desc = f"{tool.name} {tool.description}".lower()
        if any(re.search(kw, name_desc) for kw in self.SENSITIVE_KEYWORDS):
            classifications = [p.data_classification for p in tool.permissions]
            if not any(c.value in ["confidential", "restricted"] for c in classifications):
                findings.append(self.create_finding(
                    tool=tool,
                    evidence=f"Tool '{tool.name}' handles sensitive terms but lacks 'confidential' or 'restricted' data classification.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.DETECTED
                ))
        return findings


# Registry of all active static scanner rules
ALL_RULES: List[BaseRule] = [
    RuleSuspiciousDescription(),
    RuleHiddenSideEffects(),
    RuleShellExecution(),
    RuleFileSystemAccess(),
    RuleNetworkEgress(),
    RuleCredentialExposure(),
    RuleMissingInputConstraints(),
    RuleBroadWildcardSelectors(),
    RuleToolNamingDeception(),
    RuleConflictingPermissions(),
    RuleMissingAuthentication(),
    RuleMissingOutputSensitivity(),
]
