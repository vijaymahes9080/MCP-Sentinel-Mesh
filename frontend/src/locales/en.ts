export const en = {
  brand: "MCP Sentinel Mesh",
  tagline: "Enterprise Security Scanner & Runtime Policy Proxy for AI Agents & MCP",
  nav: {
    overview: "Overview",
    inventory: "Tool Inventory",
    scanner: "Static Scanner",
    runtime: "Runtime Events",
    approvals: "Approval Queue",
    policies: "Policy Editor",
    n8n: "n8n Analyzer",
    benchmarks: "Benchmarks"
  },
  stats: {
    securityPosture: "Security Posture Score",
    toolsMonitored: "Monitored MCP Tools",
    auditEvents: "Tamper-Evident Events",
    pendingApprovals: "Pending Approvals",
    benchmarkPassRate: "Adversarial Pass Rate",
    unauthorizedCalls: "Unauthorized Calls Permitted",
  },
  scanner: {
    title: "Static MCP & n8n Manifest Scanner",
    selectTarget: "Select Target to Scan",
    scanNow: "Run Security Scan",
    scanning: "Analyzing Manifest...",
    exportSarif: "Export SARIF v2.1.0",
    exportMarkdown: "Export Markdown",
    aggregateScore: "Aggregate Risk Score",
    findings: "Discovered Findings",
    evidence: "Evidence",
    remediation: "Remediation",
    noFindings: "Zero vulnerabilities detected in manifest."
  },
  approvals: {
    title: "Human-in-the-Loop Operator Queue",
    pendingSubtitle: "High-risk mutating actions requiring explicit human confirmation.",
    toolName: "Tool Name",
    callerAgent: "Calling Agent",
    riskScore: "Risk Score",
    arguments: "Arguments Payload",
    approve: "Authorize & Execute",
    reject: "Deny & Block",
    empty: "No pending approval requests. System operating nominally."
  },
  runtime: {
    title: "Live Runtime Tool Mediation Stream",
    subtitle: "Real-time decision stream: Allow, Block, Redact, and Audit.",
    chainIntegrity: "Cryptographic Audit Chain Integrity",
    verified: "SHA-256 Validated",
    corrupted: "Chain Corrupted",
    event: "Event",
    principal: "Principal",
    action: "Tool Action",
    decision: "Policy Decision",
    latency: "Latency"
  },
  n8n: {
    title: "n8n Workflow Security Inspector",
    subtitle: "Static graph analysis detecting unauthenticated triggers, SSRF, and dangerous code execution."
  }
};
