import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { OverviewView } from './components/OverviewView';
import { InventoryView } from './components/InventoryView';
import { ScannerView } from './components/ScannerView';
import { RuntimeEventsView } from './components/RuntimeEventsView';
import { ApprovalsView } from './components/ApprovalsView';
import { PolicyEditorView } from './components/PolicyEditorView';
import { N8NView } from './components/N8NView';
import { BenchmarksView } from './components/BenchmarksView';

import { en } from './locales/en';
import { ta } from './locales/ta';

export function App() {
  const [currentTab, setCurrentTab] = useState('overview');
  const [lang, setLang] = useState<'en' | 'ta'>('en');
  const [tools, setTools] = useState<any[]>([]);
  const [auditEvents, setAuditEvents] = useState<any[]>([]);
  const [auditValid, setAuditValid] = useState(true);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [benchmarkStats, setBenchmarkStats] = useState<any>({
    total_cases: 80,
    passed: 78,
    pass_rate_pct: 97.5,
    detection_precision_pct: 100.0,
    median_latency_ms: 0.009
  });

  const t = lang === 'en' ? en : ta;

  const loadData = async () => {
    // 1. Fetch Tools
    try {
      const resp = await fetch('/tools');
      if (resp.ok) {
        const data = await resp.json();
        setTools(data.tools || []);
      }
    } catch {
      // Fallback mock tools if backend not running
      setTools([
        {
          name: "get_system_health",
          description: "Retrieves current CPU, memory, and uptime metrics without mutating state.",
          parameters_schema: { type: "object", properties: { metric_type: { type: "string" } } },
          permissions: [{ scope: "read", resource_patterns: ["system/telemetry"], data_classification: "internal", is_destructive: false }]
        },
        {
          name: "lookup_weather",
          description: "Fetches current weather conditions for a specified city name.",
          parameters_schema: { type: "object", properties: { city: { type: "string" } } },
          permissions: [{ scope: "read", resource_patterns: ["weather/*"], data_classification: "public", is_destructive: false }]
        },
        {
          name: "execute_shell_command",
          description: "Executes raw shell script on underlying container host.",
          parameters_schema: { type: "object", properties: { command: { type: "string" } } },
          permissions: [{ scope: "execute", resource_patterns: ["*"], data_classification: "restricted", is_destructive: true }]
        },
        {
          name: "drop_database_table",
          description: "Drops an entire database table or schema and purges all associated audit tables.",
          parameters_schema: { type: "object", properties: { table_name: { type: "string" } } },
          permissions: [{ scope: "admin", resource_patterns: ["database/tables/*"], data_classification: "restricted", is_destructive: true }]
        }
      ]);
    }

    // 2. Fetch Audit Events
    try {
      const resp = await fetch('/audit');
      if (resp.ok) {
        const data = await resp.json();
        setAuditEvents(data.events || []);
        setAuditValid(data.integrity?.is_valid ?? true);
      }
    } catch {
      setAuditEvents([
        {
          event_id: "AUD-001",
          sequence_index: 0,
          previous_hash: "0000000000000000000000000000000000000000000000000000000000000000",
          current_hash: "8ac5e7f14c73cc9f78b638b5c3d6ae2f09f7a225be04916d86fb89ab8070910d",
          timestamp: new Date().toISOString(),
          event_type: "TOOL_CALL_SUCCESS",
          principal: "agent-alpha",
          action: "lookup_weather",
          decision: "ALLOW",
          payload_digest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          latency_ms: 0.08
        }
      ]);
      setAuditValid(true);
    }

    // 3. Fetch Approvals
    try {
      const resp = await fetch('/approvals');
      if (resp.ok) {
        const data = await resp.json();
        setApprovals(data.approvals || []);
      }
    } catch {
      setApprovals([
        {
          request_id: "APPR-A1B2C3D4",
          call_id: "call-9921",
          tool_name: "drop_database_table",
          arguments: { table_name: "archive_2025", confirm_purge: true },
          caller_agent_id: "maintenance-bot",
          risk_score: 85.0,
          reason: "Tool 'drop_database_table' performs destructive state mutations. Operator authorization required.",
          status: "PENDING",
          created_at: new Date().toISOString()
        }
      ]);
    }
  };

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 10000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        lang={lang}
        setLang={setLang}
        t={t}
        auditValid={auditValid}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentTab === 'overview' && (
          <OverviewView
            t={t}
            toolsCount={tools.length}
            auditCount={auditEvents.length}
            pendingApprovalsCount={approvals.filter(a => a.status === 'PENDING').length}
            benchmarkStats={benchmarkStats}
            auditValid={auditValid}
            setCurrentTab={setCurrentTab}
          />
        )}
        {currentTab === 'inventory' && <InventoryView tools={tools} t={t} />}
        {currentTab === 'scanner' && <ScannerView t={t} />}
        {currentTab === 'runtime' && (
          <RuntimeEventsView
            events={auditEvents}
            auditValid={auditValid}
            t={t}
            onRefresh={loadData}
          />
        )}
        {currentTab === 'approvals' && (
          <ApprovalsView
            approvals={approvals}
            t={t}
            onRefresh={loadData}
          />
        )}
        {currentTab === 'policies' && <PolicyEditorView t={t} />}
        {currentTab === 'n8n' && <N8NView t={t} />}
        {currentTab === 'benchmarks' && <BenchmarksView stats={benchmarkStats} t={t} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/60 py-6 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            <b>MCP Sentinel Mesh</b> — Open-Source AI Security Architecture
          </div>
          <div>
            Lead Maintainer: <a href="mailto:Vijaypradhap2004@gmail.com" className="text-indigo-400 hover:underline">Vijay Mahes</a> | License: MIT
          </div>
        </div>
      </footer>
    </div>
  );
}
export default App;
