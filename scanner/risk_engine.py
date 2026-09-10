"""
MCP Sentinel Mesh - Transparent Risk Scoring Engine
Calculates multi-factor risk scores according to the documented formula.
"""

from typing import List, Optional
from backend.schemas.contracts import (
    SecurityFinding,
    RiskScore,
    FactorBreakdown,
    Severity,
    Confidence,
    ToolDefinition,
    PermissionScope,
    DataClassification,
)


class RiskEngine:
    """
    Transparent Risk Scoring Engine

    Formula:
    ---------------------------------------------------------
    RawScore = min(100.0, (
        w_impact       * Impact +
        w_exploit      * Exploitability +
        w_scope        * PermissionScope +
        w_destruct     * DestructiveCapability +
        w_sensitivity  * DataSensitivity +
        w_exposure     * Exposure
    )) * ConfidenceMultiplier

    Weights (Sum of max weighted base = 100):
    - w_impact: 2.5 (Max Impact = 10.0 -> 25 points)
    - w_exploit: 2.0 (Max Exploitability = 10.0 -> 20 points)
    - w_scope: 1.5 (Max Scope = 10.0 -> 15 points)
    - w_destruct: 2.0 (Max Destructive = 10.0 -> 20 points)
    - w_sensitivity: 1.0 (Max Sensitivity = 10.0 -> 10 points)
    - w_exposure: 1.0 (Max Exposure = 10.0 -> 10 points)
    Total Max Base = 100.0

    Confidence Multiplier:
    - CONFIRMED:  1.0
    - DETECTED:   0.85
    - SUSPECTED:  0.70

    Residual Risk:
    ResidualRisk = max(0.0, RawScore * 0.25)
    (Assuming Sentinel runtime proxy, rate limiting, and output redactors are applied).

    Severity Bands:
    - 80.0 - 100.0: CRITICAL -> BLOCK
    - 60.0 -  79.9: HIGH     -> REQUIRE_APPROVAL
    - 40.0 -  59.9: MEDIUM   -> REQUIRE_APPROVAL (or audit monitor)
    - 20.0 -  39.9: LOW      -> ALLOW (with logging)
    -  0.0 -  19.9: INFORMATIONAL -> ALLOW
    """

    WEIGHT_IMPACT = 2.5
    WEIGHT_EXPLOIT = 2.0
    WEIGHT_SCOPE = 1.5
    WEIGHT_DESTRUCT = 2.0
    WEIGHT_SENSITIVITY = 1.0
    WEIGHT_EXPOSURE = 1.0

    CONFIDENCE_MAP = {
        Confidence.CONFIRMED: 1.0,
        Confidence.DETECTED: 0.85,
        Confidence.SUSPECTED: 0.70,
    }

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFORMATIONAL: 1.0,
    }

    @classmethod
    def calculate_tool_risk(
        cls,
        tool: ToolDefinition,
        findings: List[SecurityFinding]
    ) -> RiskScore:
        """Calculate risk score for a single tool based on its profile and discovered findings."""
        # 1. Base factors from tool definition
        # Scope
        has_admin = any(p.scope == PermissionScope.ADMIN for p in tool.permissions)
        has_write = any(p.scope in [PermissionScope.WRITE, PermissionScope.EXECUTE] for p in tool.permissions)
        has_network = any(p.scope == PermissionScope.NETWORK for p in tool.permissions)

        if has_admin:
            scope_val = 10.0
        elif has_write and has_network:
            scope_val = 8.5
        elif has_write:
            scope_val = 7.0
        elif has_network:
            scope_val = 5.0
        else:
            scope_val = 2.0

        # Destructive
        is_destructive = any(p.is_destructive for p in tool.permissions)
        destructive_val = 10.0 if is_destructive else 1.0

        # Data Sensitivity
        max_sensitivity = max(
            [p.data_classification for p in tool.permissions],
            default=DataClassification.INTERNAL
        )
        if max_sensitivity == DataClassification.RESTRICTED:
            sensitivity_val = 10.0
        elif max_sensitivity == DataClassification.CONFIDENTIAL:
            sensitivity_val = 7.5
        elif max_sensitivity == DataClassification.INTERNAL:
            sensitivity_val = 4.0
        else:
            sensitivity_val = 1.0

        # Exposure (default local tool vs network egress)
        exposure_val = 8.0 if has_network else 3.0

        # 2. Derive Impact & Exploitability from Findings
        if findings:
            max_finding_sev = max([cls.SEVERITY_WEIGHTS[f.severity] for f in findings])
            impact_val = max(3.0, max_finding_sev)
            # Count findings to calculate exploitability density
            exploit_val = min(10.0, 4.0 + (len(findings) * 1.5))
            # Average confidence
            conf_multiplier = sum(cls.CONFIDENCE_MAP.get(f.confidence, 0.8) for f in findings) / len(findings)
        else:
            impact_val = 2.0
            exploit_val = 1.5
            conf_multiplier = 1.0

        # Calculate weighted base sum
        base_sum = (
            (cls.WEIGHT_IMPACT * impact_val) +
            (cls.WEIGHT_EXPLOIT * exploit_val) +
            (cls.WEIGHT_SCOPE * scope_val) +
            (cls.WEIGHT_DESTRUCT * destructive_val) +
            (cls.WEIGHT_SENSITIVITY * sensitivity_val) +
            (cls.WEIGHT_EXPOSURE * exposure_val)
        )

        raw_score = min(100.0, base_sum) * conf_multiplier
        numeric_score = round(min(100.0, max(0.0, raw_score)), 1)

        # Assign Severity Band
        if numeric_score >= 80.0:
            severity_band = Severity.CRITICAL
            recommended_action = "BLOCK: High likelihood of compromise or severe destructive impact."
        elif numeric_score >= 60.0:
            severity_band = Severity.HIGH
            recommended_action = "REQUIRE_APPROVAL: Mutating or dangerous action requiring operator consent."
        elif numeric_score >= 40.0:
            severity_band = Severity.MEDIUM
            recommended_action = "REQUIRE_APPROVAL: Unbounded arguments or sensitive data access."
        elif numeric_score >= 20.0:
            severity_band = Severity.LOW
            recommended_action = "ALLOW: Permit execution with audit logging and rate limiting."
        else:
            severity_band = Severity.INFORMATIONAL
            recommended_action = "ALLOW: Read-only benign utility tool."

        # Compute Residual Risk with Sentinel Mesh proxy protections active
        mitigation_discount = 0.75 if is_destructive else 0.85
        residual_risk = round(numeric_score * (1.0 - mitigation_discount), 1)

        breakdown = FactorBreakdown(
            impact=round(impact_val, 1),
            exploitability=round(exploit_val, 1),
            permission_scope=round(scope_val, 1),
            data_sensitivity=round(sensitivity_val, 1),
            destructive_capability=round(destructive_val, 1),
            exposure=round(exposure_val, 1),
            confidence_multiplier=round(conf_multiplier, 2)
        )

        return RiskScore(
            numeric_score=numeric_score,
            severity_band=severity_band,
            factor_breakdown=breakdown,
            residual_risk=residual_risk,
            recommended_action=recommended_action
        )

    @classmethod
    def calculate_aggregate_risk(cls, tool_scores: List[RiskScore]) -> RiskScore:
        """Calculate overall aggregate risk for a manifest or MCP server."""
        if not tool_scores:
            breakdown = FactorBreakdown(
                impact=0.0,
                exploitability=0.0,
                permission_scope=0.0,
                data_sensitivity=0.0,
                destructive_capability=0.0,
                exposure=0.0,
                confidence_multiplier=1.0
            )
            return RiskScore(
                numeric_score=0.0,
                severity_band=Severity.INFORMATIONAL,
                factor_breakdown=breakdown,
                residual_risk=0.0,
                recommended_action="ALLOW: Empty manifest."
            )

        max_score = max(s.numeric_score for s in tool_scores)
        avg_score = sum(s.numeric_score for s in tool_scores) / len(tool_scores)
        # Blend max score (70%) and average score (30%)
        agg_score = round(min(100.0, (max_score * 0.7) + (avg_score * 0.3)), 1)

        if agg_score >= 80.0:
            band = Severity.CRITICAL
            action = "REJECT_DEPLOYMENT: Manifest contains critical vulnerabilities."
        elif agg_score >= 60.0:
            band = Severity.HIGH
            action = "CONDITIONAL_APPROVAL: Enforce strict human approval on high-risk tools."
        elif agg_score >= 40.0:
            band = Severity.MEDIUM
            action = "AUDITED_ACCEPTANCE: Monitor tools with Sentinel Proxy."
        elif agg_score >= 20.0:
            band = Severity.LOW
            action = "ACCEPT: Low risk profile."
        else:
            band = Severity.INFORMATIONAL
            action = "ACCEPT: Minimal risk profile."

        # Aggregate factor averages
        avg_breakdown = FactorBreakdown(
            impact=round(sum(s.factor_breakdown.impact for s in tool_scores) / len(tool_scores), 1),
            exploitability=round(sum(s.factor_breakdown.exploitability for s in tool_scores) / len(tool_scores), 1),
            permission_scope=round(sum(s.factor_breakdown.permission_scope for s in tool_scores) / len(tool_scores), 1),
            data_sensitivity=round(sum(s.factor_breakdown.data_sensitivity for s in tool_scores) / len(tool_scores), 1),
            destructive_capability=round(sum(s.factor_breakdown.destructive_capability for s in tool_scores) / len(tool_scores), 1),
            exposure=round(sum(s.factor_breakdown.exposure for s in tool_scores) / len(tool_scores), 1),
            confidence_multiplier=1.0
        )

        return RiskScore(
            numeric_score=agg_score,
            severity_band=band,
            factor_breakdown=avg_breakdown,
            residual_risk=round(agg_score * 0.2, 1),
            recommended_action=action
        )
