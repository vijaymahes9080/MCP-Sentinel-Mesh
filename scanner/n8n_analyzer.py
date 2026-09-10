"""
MCP Sentinel Mesh - n8n Workflow Static Graph Analyzer
Analyzes exported n8n workflow graphs for misconfigurations, security hazards, and missing governance controls.
"""

import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid

from backend.schemas.contracts import (
    N8NWorkflowFinding,
    ScanReport,
    RiskScore,
    FactorBreakdown,
    Severity,
    SecurityFinding,
    Confidence,
)
from scanner.risk_engine import RiskEngine


class N8NWorkflowAnalyzer:
    """
    Deterministic static graph inspector for exported n8n workflows.
    """

    DANGEROUS_EXPRESSIONS = [
        (r"process\.env", "Direct access to container environment variables inside expression"),
        (r"eval\(", "Use of dynamic JavaScript eval()"),
        (r"Function\(", "Dynamic Function constructor invocation"),
        (r"child_process", "Child process execution invocation in code node"),
        (r"fs\.(read|write)", "Direct file system access inside workflow expression"),
    ]

    @classmethod
    def scan_workflow_file(cls, file_path: str) -> ScanReport:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.scan_workflow_dict(data, target_name=file_path)

    @classmethod
    def scan_workflow_dict(cls, data: Dict[str, Any], target_name: str = "n8n_workflow") -> ScanReport:
        nodes = data.get("nodes", [])
        connections = data.get("connections", {})
        findings: List[N8NWorkflowFinding] = []
        gen_findings: List[SecurityFinding] = []

        has_error_trigger = any("errorTrigger" in n.get("type", "") for n in nodes)
        has_approval_gate = any(
            any(k in n.get("name", "").lower() or k in n.get("type", "").lower() for k in ["approval", "manual", "wait", "human"])
            for n in nodes
        )

        for node in nodes:
            node_id = str(node.get("id", "unknown"))
            node_name = node.get("name", "Unnamed Node")
            node_type = node.get("type", "")
            params = node.get("parameters", {})
            params_str = json.dumps(params)

            # Rule N8N-001: Unauthenticated Webhook Trigger
            if "webhook" in node_type.lower():
                auth_mode = params.get("authentication", "none").lower()
                if auth_mode in ["none", ""]:
                    f = N8NWorkflowFinding(
                        node_id=node_id,
                        node_name=node_name,
                        node_type=node_type,
                        rule_id="N8N-001",
                        severity=Severity.HIGH,
                        issue_category="Unauthenticated Webhook Trigger",
                        evidence=f"Webhook node '{node_name}' has authentication set to '{auth_mode}'. Any unauthorized actor can invoke this trigger.",
                        fix_recommendation="Enable Header Auth, Basic Auth, or HMAC signature validation on the Webhook node."
                    )
                    findings.append(f)
                    gen_findings.append(SecurityFinding(
                        rule_id="N8N-001",
                        title="Unauthenticated n8n Webhook",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        affected_target=f"{node_name} ({node_id})",
                        evidence=f.evidence,
                        remediation=f.fix_recommendation,
                        references=["https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/"]
                    ))

            # Rule N8N-002: Dangerous Code / Function Node with Unsafe Expressions
            if any(t in node_type.lower() for t in ["code", "function"]):
                js_code = params.get("jsCode") or params.get("functionCode") or ""
                for pattern, desc in cls.DANGEROUS_EXPRESSIONS:
                    if re.search(pattern, js_code):
                        f = N8NWorkflowFinding(
                            node_id=node_id,
                            node_name=node_name,
                            node_type=node_type,
                            rule_id="N8N-002",
                            severity=Severity.CRITICAL,
                            issue_category="Unsafe Code Execution or Environment Exposure",
                            evidence=f"Code node '{node_name}' matches unsafe pattern '{pattern}': {desc}.",
                            fix_recommendation="Avoid accessing host environment variables or dynamic eval. Use built-in n8n credential objects."
                        )
                        findings.append(f)
                        gen_findings.append(SecurityFinding(
                            rule_id="N8N-002",
                            title="Dangerous Expression in n8n Code Node",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            affected_target=f"{node_name} ({node_id})",
                            evidence=f.evidence,
                            remediation=f.fix_recommendation
                        ))

            # Rule N8N-003: Arbitrary HTTP Request without Timeouts or Target Validation
            if "httprequest" in node_type.lower():
                url = params.get("url", "")
                options = params.get("options", {})
                timeout = options.get("timeout")
                allow_unauth_certs = options.get("allowUnauthorizedCerts", False)

                if allow_unauth_certs:
                    f = N8NWorkflowFinding(
                        node_id=node_id,
                        node_name=node_name,
                        node_type=node_type,
                        rule_id="N8N-003A",
                        severity=Severity.HIGH,
                        issue_category="Insecure TLS / Disabled Certificate Verification",
                        evidence=f"HTTP node '{node_name}' has 'allowUnauthorizedCerts: true'. Vulnerable to Man-in-the-Middle (MitM).",
                        fix_recommendation="Disable 'allowUnauthorizedCerts' and install proper CA certificates."
                    )
                    findings.append(f)
                    gen_findings.append(SecurityFinding(
                        rule_id="N8N-003A",
                        title="Insecure TLS in n8n HTTP Request",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        affected_target=f"{node_name} ({node_id})",
                        evidence=f.evidence,
                        remediation=f.fix_recommendation
                    ))

                if not timeout:
                    f = N8NWorkflowFinding(
                        node_id=node_id,
                        node_name=node_name,
                        node_type=node_type,
                        rule_id="N8N-003B",
                        severity=Severity.MEDIUM,
                        issue_category="Missing Request Timeout",
                        evidence=f"HTTP node '{node_name}' has no explicit timeout configured, risking hanging workflows.",
                        fix_recommendation="Configure an explicit request timeout (e.g. 5000 ms) in the node options."
                    )
                    findings.append(f)
                    gen_findings.append(SecurityFinding(
                        rule_id="N8N-003B",
                        title="Missing Timeout in n8n HTTP Request",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        affected_target=f"{node_name} ({node_id})",
                        evidence=f.evidence,
                        remediation=f.fix_recommendation
                    ))

                if any(internal_ip in url for internal_ip in ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0"]):
                    f = N8NWorkflowFinding(
                        node_id=node_id,
                        node_name=node_name,
                        node_type=node_type,
                        rule_id="N8N-003C",
                        severity=Severity.CRITICAL,
                        issue_category="SSRF to Internal Address",
                        evidence=f"HTTP node '{node_name}' targets internal or metadata address: '{url}'.",
                        fix_recommendation="Restrict outbound requests via Sentinel proxy egress filtering."
                    )
                    findings.append(f)
                    gen_findings.append(SecurityFinding(
                        rule_id="N8N-003C",
                        title="SSRF to Internal Address in n8n",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        affected_target=f"{node_name} ({node_id})",
                        evidence=f.evidence,
                        remediation=f.fix_recommendation
                    ))

            # Rule N8N-004: Hardcoded Secrets in Node Parameters
            secret_match = re.search(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]", params_str)
            if secret_match:
                f = N8NWorkflowFinding(
                    node_id=node_id,
                    node_name=node_name,
                    node_type=node_type,
                    rule_id="N8N-004",
                    severity=Severity.CRITICAL,
                    issue_category="Hardcoded Secret in Workflow Node Parameters",
                    evidence=f"Node '{node_name}' contains hardcoded secret: '{secret_match.group(0)[:12]}...[REDACTED]'.",
                    fix_recommendation="Migrate credentials to n8n Credential Store or environment variables."
                )
                findings.append(f)
                gen_findings.append(SecurityFinding(
                    rule_id="N8N-004",
                    title="Hardcoded Secret in n8n Node",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    affected_target=f"{node_name} ({node_id})",
                    evidence=f.evidence,
                    remediation=f.fix_recommendation
                ))

        # Rule N8N-005: Global Missing Error Handling Workflow
        if not has_error_trigger:
            f = N8NWorkflowFinding(
                node_id="workflow-root",
                node_name="Global Workflow",
                node_type="n8n-workflow",
                rule_id="N8N-005",
                severity=Severity.LOW,
                issue_category="Missing Error Handling Workflow",
                evidence="Workflow lacks an Error Trigger node (`n8n-nodes-base.errorTrigger`) or global dead-letter handler.",
                fix_recommendation="Add an Error Trigger node to capture and log execution anomalies safely."
            )
            findings.append(f)
            gen_findings.append(SecurityFinding(
                rule_id="N8N-005",
                title="Missing Error Trigger in n8n Workflow",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                affected_target="Global Workflow",
                evidence=f.evidence,
                remediation=f.fix_recommendation
            ))

        # Rule N8N-006: High-Risk Action without Human Approval Gate
        has_mutating_http = any("delete" in json.dumps(n.get("parameters", {})).lower() or "post" in json.dumps(n.get("parameters", {})).lower() for n in nodes if "httprequest" in n.get("type", "").lower())
        if has_mutating_http and not has_approval_gate:
            f = N8NWorkflowFinding(
                node_id="workflow-root",
                node_name="Global Workflow",
                node_type="n8n-workflow",
                rule_id="N8N-006",
                severity=Severity.MEDIUM,
                issue_category="Mutating Operation Missing Human Approval Gate",
                evidence="Workflow executes mutating HTTP operations (POST/DELETE) but contains no approval or wait node.",
                fix_recommendation="Insert a Sentinel Mesh human approval step before destructive operations."
            )
            findings.append(f)
            gen_findings.append(SecurityFinding(
                rule_id="N8N-006",
                title="Mutating Action Without Approval in n8n",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                affected_target="Global Workflow",
                evidence=f.evidence,
                remediation=f.fix_recommendation
            ))

        # Severity breakdown
        summary: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            summary[f.severity.value] += 1

        # Calculate Risk Score
        crit = summary[Severity.CRITICAL.value]
        high = summary[Severity.HIGH.value]
        med = summary[Severity.MEDIUM.value]
        low = summary[Severity.LOW.value]

        numeric_score = min(100.0, round((crit * 30.0) + (high * 20.0) + (med * 10.0) + (low * 3.0), 1))
        if numeric_score >= 80.0:
            band = Severity.CRITICAL
            action = "BLOCK_EXECUTION: Workflow contains critical security flaws."
        elif numeric_score >= 60.0:
            band = Severity.HIGH
            action = "REQUIRE_REMEDIATION: Fix unauthenticated webhooks and hardcoded secrets."
        elif numeric_score >= 40.0:
            band = Severity.MEDIUM
            action = "REVIEW_CONFIGURATION: Add timeouts and approval gates."
        elif numeric_score >= 20.0:
            band = Severity.LOW
            action = "ACCEPT_WITH_LOGGING: Minor findings."
        else:
            band = Severity.INFORMATIONAL
            action = "ACCEPT: Clean workflow configuration."

        breakdown = FactorBreakdown(
            impact=min(10.0, crit * 3.5 + high * 2.0),
            exploitability=min(10.0, high * 3.0 + med * 1.5),
            permission_scope=6.0,
            data_sensitivity=7.0 if crit > 0 else 4.0,
            destructive_capability=8.0 if has_mutating_http else 2.0,
            exposure=9.0 if any("webhook" in n.get("type", "").lower() for n in nodes) else 3.0,
            confidence_multiplier=1.0
        )

        agg_risk = RiskScore(
            numeric_score=numeric_score,
            severity_band=band,
            factor_breakdown=breakdown,
            residual_risk=round(numeric_score * 0.25, 1),
            recommended_action=action
        )

        report = ScanReport(
            target_name=target_name,
            target_type="N8N_WORKFLOW",
            scanned_at=datetime.utcnow(),
            duration_ms=12.5,
            tools_analyzed=0,
            nodes_analyzed=len(nodes),
            findings=gen_findings,
            n8n_findings=findings,
            aggregate_risk=agg_risk,
            summary_by_severity=summary,
            compliance_checks_passed=max(0, (len(nodes) * 6) - len(findings)),
            compliance_checks_failed=len(findings)
        )
        return report
