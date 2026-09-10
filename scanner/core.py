"""
MCP Sentinel Mesh - Core Static Scanner & CLI Engine
Executes deterministic security rules against MCP manifests, tools, and n8n workflows.
"""

import os
import sys
import json
import time
import argparse
from typing import List, Dict, Any, Optional
from datetime import datetime

from backend.schemas.contracts import (
    ToolDefinition,
    ToolPermission,
    PermissionScope,
    DataClassification,
    SecurityFinding,
    RiskScore,
    ScanReport,
    Severity,
)
from scanner.rules import ALL_RULES
from scanner.risk_engine import RiskEngine
from scanner.formatters import SarifFormatter, MarkdownFormatter, JsonFormatter


class SentinelScanner:
    """Core scanning engine for MCP manifests and tool definitions."""

    def __init__(self, rules: Optional[List[Any]] = None):
        self.rules = rules or ALL_RULES

    def parse_manifest(self, data: Any) -> List[ToolDefinition]:
        """Parses various tool manifest formats (MCP stdio, JSON schema list, etc.) into ToolDefinition objects."""
        tools: List[ToolDefinition] = []

        if isinstance(data, dict):
            # Format A: Standard MCP capabilities { "tools": [...] }
            raw_tools = data.get("tools", [])
            if not raw_tools and "name" in data and ("parameters" in data or "inputSchema" in data or "description" in data):
                raw_tools = [data]
        elif isinstance(data, list):
            raw_tools = data
        else:
            raise ValueError("Unsupported manifest payload format: must be JSON object or list.")

        for item in raw_tools:
            name = item.get("name", "unnamed_tool")
            desc = item.get("description", "")
            params = item.get("parameters_schema") or item.get("inputSchema") or item.get("parameters") or {}
            ret_schema = item.get("return_schema") or item.get("outputSchema")
            annotations = item.get("annotations") or {}
            version = item.get("version", "1.0.0")

            # Parse permissions if explicitly declared, else deduce
            perms_raw = item.get("permissions", [])
            permissions: List[ToolPermission] = []
            for p in perms_raw:
                if isinstance(p, dict):
                    scope_val = p.get("scope", "read").lower()
                    try:
                        scope = PermissionScope(scope_val)
                    except ValueError:
                        scope = PermissionScope.READ
                    classification_val = p.get("data_classification", "internal").lower()
                    try:
                        classification = DataClassification(classification_val)
                    except ValueError:
                        classification = DataClassification.INTERNAL
                    permissions.append(ToolPermission(
                        scope=scope,
                        resource_patterns=p.get("resource_patterns", ["*"]),
                        data_classification=classification,
                        is_destructive=p.get("is_destructive", False)
                    ))

            # Default permission if none declared
            if not permissions:
                permissions = [ToolPermission(
                    scope=PermissionScope.READ,
                    resource_patterns=["*"],
                    data_classification=DataClassification.INTERNAL,
                    is_destructive=False
                )]

            tools.append(ToolDefinition(
                name=name,
                description=desc,
                parameters_schema=params,
                return_schema=ret_schema,
                permissions=permissions,
                annotations=annotations,
                source_version=version,
                mcp_server_id=item.get("server_id")
            ))

        return tools

    def scan_manifest_file(self, file_path: str) -> ScanReport:
        """Loads and scans an MCP manifest from a file path."""
        start_time = time.time()
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Check if file is an n8n workflow
        if isinstance(data, dict) and "nodes" in data and "connections" in data:
            from scanner.n8n_analyzer import N8NWorkflowAnalyzer
            return N8NWorkflowAnalyzer.scan_workflow_dict(data, target_name=file_path)

        tools = self.parse_manifest(data)
        return self.scan_tools(tools, target_name=file_path, start_time=start_time)

    def scan_tools(self, tools: List[ToolDefinition], target_name: str = "memory", start_time: Optional[float] = None) -> ScanReport:
        """Executes rules and calculates risk against a list of ToolDefinition objects."""
        if start_time is None:
            start_time = time.time()

        all_findings: List[SecurityFinding] = []
        tool_scores: List[RiskScore] = []
        severity_summary: Dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFORMATIONAL.value: 0,
        }

        for tool in tools:
            tool_findings: List[SecurityFinding] = []
            for rule in self.rules:
                findings = rule.evaluate(tool)
                for f in findings:
                    tool_findings.append(f)
                    all_findings.append(f)
                    severity_summary[f.severity.value] += 1

            score = RiskEngine.calculate_tool_risk(tool, tool_findings)
            tool_scores.append(score)

        aggregate_risk = RiskEngine.calculate_aggregate_risk(tool_scores)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        report = ScanReport(
            target_name=target_name,
            target_type="MCP_MANIFEST",
            scanned_at=datetime.utcnow(),
            duration_ms=duration_ms,
            tools_analyzed=len(tools),
            findings=all_findings,
            aggregate_risk=aggregate_risk,
            summary_by_severity=severity_summary,
            compliance_checks_passed=max(0, (len(tools) * len(self.rules)) - len(all_findings)),
            compliance_checks_failed=len(all_findings)
        )

        report.sarif_output = SarifFormatter.format(report)
        return report


def main():
    """CLI Entrypoint: sentinel scan <target> --format <format>"""
    # Configure UTF-8 stdout if needed
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="MCP Sentinel Mesh - Enterprise Security Scanner for MCP Servers and Agents"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    scan_parser = subparsers.add_parser("scan", help="Scan MCP tool manifest or n8n workflow")
    scan_parser.add_argument("target", help="Path to MCP manifest JSON file or n8n workflow JSON")
    scan_parser.add_argument(
        "--format", "-f",
        choices=["markdown", "json", "sarif"],
        default="markdown",
        help="Output report format (default: markdown)"
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Optional output file path to write report"
    )
    scan_parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with non-zero code if CRITICAL or HIGH findings exist"
    )

    args = parser.parse_args()

    if args.command == "scan":
        scanner = SentinelScanner()
        try:
            report = scanner.scan_manifest_file(args.target)
        except Exception as e:
            sys.stderr.write(f"Error during scan: {e}\n")
            sys.exit(2)

        if args.format == "markdown":
            output_content = MarkdownFormatter.format(report)
        elif args.format == "json":
            output_content = JsonFormatter.format(report)
        elif args.format == "sarif":
            output_content = json.dumps(report.sarif_output or SarifFormatter.format(report), indent=2)
        else:
            output_content = MarkdownFormatter.format(report)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_content)
            print(f"Report written to: {args.output}")
        else:
            print(output_content)

        if args.fail_on_high:
            crit = report.summary_by_severity.get(Severity.CRITICAL.value, 0)
            high = report.summary_by_severity.get(Severity.HIGH.value, 0)
            if crit > 0 or high > 0:
                sys.exit(1)
        sys.exit(0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
