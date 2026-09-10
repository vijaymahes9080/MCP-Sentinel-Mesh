"""
Unit and Integration Tests for n8n Static Workflow Analyzer
"""

import os
import pytest
from scanner.n8n_analyzer import N8NWorkflowAnalyzer
from backend.schemas.contracts import Severity


def test_vulnerable_workflow_analysis():
    vulnerable_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "n8n-samples", "vulnerable_crm_sync.json"
    )
    report = N8NWorkflowAnalyzer.scan_workflow_file(vulnerable_path)
    assert report.target_type == "N8N_WORKFLOW"
    assert report.aggregate_risk.severity_band == Severity.CRITICAL
    rule_ids = [f.rule_id for f in report.n8n_findings]
    assert "N8N-001" in rule_ids  # Unauthenticated webhook
    assert "N8N-002" in rule_ids  # Dangerous code node (process.env / eval)
    assert "N8N-003C" in rule_ids  # Internal SSRF
    assert "N8N-003A" in rule_ids  # Disabled cert checks


def test_hardened_workflow_analysis():
    hardened_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "n8n-samples", "hardened_crm_sync.json"
    )
    report = N8NWorkflowAnalyzer.scan_workflow_file(hardened_path)
    assert report.target_type == "N8N_WORKFLOW"
    assert report.aggregate_risk.numeric_score == 0.0
    assert len(report.n8n_findings) == 0
