"""
MCP Sentinel Mesh - SARIF v2.1.0 Formatter
Generates OASIS Static Analysis Results Format for GitHub Code Scanning integration.
"""

from typing import Dict, Any, List
from backend.schemas.contracts import ScanReport, Severity


class SarifFormatter:
    """Formats ScanReport into standard SARIF v2.1.0 JSON schema."""

    SEVERITY_TO_SARIF_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFORMATIONAL: "note",
    }

    @classmethod
    def format(cls, report: ScanReport) -> Dict[str, Any]:
        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for finding in report.findings:
            rule_id = finding.rule_id
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": f"{finding.title}. {finding.remediation}"},
                    "defaultConfiguration": {
                        "level": cls.SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
                    },
                    "help": {
                        "text": f"Remediation: {finding.remediation}\nReferences: {', '.join(finding.references)}"
                    },
                    "properties": {
                        "precision": finding.confidence.value.lower(),
                        "security-severity": "9.0" if finding.severity == Severity.CRITICAL else "7.0"
                    }
                }

            result_item = {
                "ruleId": rule_id,
                "level": cls.SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": f"[{finding.severity.value}] {finding.title} in '{finding.affected_target}': {finding.evidence}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": report.target_name
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence.value,
                    "remediation": finding.remediation
                }
            }
            results.append(result_item)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MCP Sentinel Mesh",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/vijaymahes9080/MCP-Sentinel-Mesh",
                            "rules": list(rules_map.values())
                        }
                    },
                    "results": results
                }
            ]
        }
        return sarif_doc
