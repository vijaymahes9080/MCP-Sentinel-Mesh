"""
MCP Sentinel Mesh - Markdown & JSON Formatters
Generates rich executive terminal & documentation outputs.
"""

import json
from typing import Dict, Any
from backend.schemas.contracts import ScanReport, Severity


class MarkdownFormatter:
    """Formats ScanReport into GitHub Flavored Markdown."""

    SEVERITY_BADGES = {
        Severity.CRITICAL: "🔴 **CRITICAL**",
        Severity.HIGH: "🟠 **HIGH**",
        Severity.MEDIUM: "🟡 **MEDIUM**",
        Severity.LOW: "🔵 **LOW**",
        Severity.INFORMATIONAL: "⚪ **INFO**",
    }

    @classmethod
    def format(cls, report: ScanReport) -> str:
        lines = []
        lines.append(f"# 🛡️ MCP Sentinel Mesh — Security Scan Report")
        lines.append("")
        lines.append(f"- **Target Name**: `{report.target_name}`")
        lines.append(f"- **Target Type**: `{report.target_type}`")
        lines.append(f"- **Scanned At**: `{report.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`")
        lines.append(f"- **Tools Analyzed**: `{report.tools_analyzed}`")
        lines.append(f"- **Duration**: `{report.duration_ms:.2f} ms`")
        lines.append(f"- **Aggregate Risk Score**: **{report.aggregate_risk.numeric_score}/100** ({cls.SEVERITY_BADGES[report.aggregate_risk.severity_band]})")
        lines.append(f"- **Residual Risk (with Sentinel Proxy)**: `{report.aggregate_risk.residual_risk}/100`")
        lines.append(f"- **Recommended Policy Action**: `{report.aggregate_risk.recommended_action}`")
        lines.append("")

        # Severity Summary Table
        lines.append("## 📊 Executive Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count | Status |")
        lines.append("| :--- | :---: | :--- |")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]:
            count = report.summary_by_severity.get(sev.value, 0)
            status = "⚠️ Action Required" if count > 0 and sev in [Severity.CRITICAL, Severity.HIGH] else "✅ Pass"
            lines.append(f"| {cls.SEVERITY_BADGES[sev]} | {count} | {status} |")
        lines.append("")

        # Findings Section
        lines.append("## 🔍 Security Findings Details")
        lines.append("")
        if not report.findings and not report.n8n_findings:
            lines.append("> ✅ **Zero vulnerabilities detected.** All evaluated deterministic security rules passed.")
            lines.append("")
        else:
            for idx, finding in enumerate(report.findings, 1):
                lines.append(f"### {idx}. [{finding.rule_id}] {finding.title}")
                lines.append(f"- **Severity**: {cls.SEVERITY_BADGES[finding.severity]}")
                lines.append(f"- **Confidence**: `{finding.confidence.value}`")
                lines.append(f"- **Affected Target**: `{finding.affected_target}`")
                lines.append(f"- **Evidence**:")
                lines.append(f"  ```text\n  {finding.evidence}\n  ```")
                lines.append(f"- **Remediation**:\n  > {finding.remediation}")
                if finding.references:
                    lines.append(f"- **References**: {', '.join(finding.references)}")
                if finding.false_positive_guidance:
                    lines.append(f"- **False Positive Guidance**: *{finding.false_positive_guidance}*")
                lines.append("")

            for idx, n8n_f in enumerate(report.n8n_findings, len(report.findings) + 1):
                lines.append(f"### {idx}. [n8n::{n8n_f.rule_id}] {n8n_f.issue_category} in `{n8n_f.node_name}`")
                lines.append(f"- **Severity**: {cls.SEVERITY_BADGES[n8n_f.severity]}")
                lines.append(f"- **Node ID / Type**: `{n8n_f.node_id}` (`{n8n_f.node_type}`)")
                lines.append(f"- **Evidence**:")
                lines.append(f"  ```text\n  {n8n_f.evidence}\n  ```")
                lines.append(f"- **Fix Recommendation**:\n  > {n8n_f.fix_recommendation}")
                lines.append("")

        lines.append("---")
        lines.append("*Generated automatically by [MCP Sentinel Mesh](https://github.com/vijaymahes9080/MCP-Sentinel-Mesh)*")
        return "\n".join(lines)


class JsonFormatter:
    """Formats ScanReport into standard JSON."""

    @classmethod
    def format(cls, report: ScanReport, indent: int = 2) -> str:
        return json.dumps(report.model_dump(mode="json"), indent=indent)
