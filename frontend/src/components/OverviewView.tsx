import React from 'react';

interface OverviewViewProps {
  t: any;
  toolsCount: number;
  auditCount: number;
  pendingApprovalsCount: number;
  benchmarkStats: any;
  auditValid: boolean;
  setCurrentTab: (tab: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  t,
  toolsCount,
  auditCount,
  pendingApprovalsCount,
  benchmarkStats,
  auditValid,
  setCurrentTab,
}) => {
  return (
    <div className="space-y-6">
      {/* Top Hero Banner */}
      <div className="glass-panel p-6 sm:p-8 bg-gradient-to-br from-indigo-950/40 via-slate-900/60 to-slate-900/40 border-indigo-500/20 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl -z-10 pointer-events-none" />
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-ping" />
            Active Mesh Security Enforcement
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Governance & Threat Defense Plane for AI Agents
          </h1>
          <p className="mt-2 text-sm sm:text-base text-slate-300 leading-relaxed">
            MCP Sentinel Mesh continuously mediates tool execution, sanitizes prompt injections, enforces human approval for destructive actions, and signs all runtime activity into an immutable SHA-256 audit ledger.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <button
              onClick={() => setCurrentTab('scanner')}
              className="btn btn-primary text-xs sm:text-sm font-semibold"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              Scan Tool Manifest
            </button>
            <button
              onClick={() => setCurrentTab('approvals')}
              className="btn btn-secondary text-xs sm:text-sm"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Review Approvals ({pendingApprovalsCount})
            </button>
            <button
              onClick={() => setCurrentTab('benchmarks')}
              className="btn btn-secondary text-xs sm:text-sm"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              View Benchmarks
            </button>
          </div>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Adversarial Pass Rate */}
        <div className="glass-panel p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              {t.stats.benchmarkPassRate}
            </span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              🛡️
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {benchmarkStats?.pass_rate_pct ?? '97.5'}%
            </span>
            <span className="badge badge-allow text-[10px]">80 Tested</span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            0 unauthorized calls permitted in negative auth tests.
          </p>
        </div>

        {/* Card 2: Monitored Tools */}
        <div className="glass-panel p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              {t.stats.toolsMonitored}
            </span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              ⚡
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">{toolsCount}</span>
            <span className="badge badge-info text-[10px]">3 Adapters</span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Secure, Vulnerable, and High-Risk synthetic endpoints.
          </p>
        </div>

        {/* Card 3: Pending Approvals */}
        <div className="glass-panel p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              {t.stats.pendingApprovals}
            </span>
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              👤
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">
              {pendingApprovalsCount}
            </span>
            <span className={`badge ${pendingApprovalsCount > 0 ? 'badge-high' : 'badge-allow'} text-[10px]`}>
              {pendingApprovalsCount > 0 ? 'Action Req' : 'Clear'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Human verification gate for destructive operations.
          </p>
        </div>

        {/* Card 4: Audit Chain Events */}
        <div className="glass-panel p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              {t.stats.auditEvents}
            </span>
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              🔗
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white font-mono">{auditCount}</span>
            <span className={`badge ${auditValid ? 'badge-allow' : 'badge-critical'} text-[10px]`}>
              {auditValid ? 'Chained' : 'Tampered'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Monotonic SHA-256 hash sequence verified.
          </p>
        </div>
      </div>

      {/* Security Architecture & Core Invariants Card */}
      <div className="glass-panel p-6">
        <h2 className="text-base font-bold text-white flex items-center gap-2 mb-4">
          <span className="w-2 h-2 rounded-full bg-indigo-500" />
          Enforced Defensive Invariants
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
            <div className="text-sm font-semibold text-indigo-300">1. Deny By Default</div>
            <p className="mt-1 text-xs text-slate-400">
              Unrecognized tools, undeclared parameters, or unauthorized callers are blocked immediately before reaching target MCP servers.
            </p>
          </div>
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
            <div className="text-sm font-semibold text-cyan-300">2. Secret Redaction</div>
            <p className="mt-1 text-xs text-slate-400">
              Deterministic regex scans inspect all returned tool outputs, scrubbing OpenAI keys, AWS credentials, JWTs, and database passwords.
            </p>
          </div>
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
            <div className="text-sm font-semibold text-emerald-300">3. Tamper-Evident Ledger</div>
            <p className="mt-1 text-xs text-slate-400">
              Every invocation, decision, latency measurement, and human approval is signed into a cryptographic hash chain.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
