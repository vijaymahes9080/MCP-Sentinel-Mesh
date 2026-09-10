import React, { useState } from 'react';

interface N8NViewProps {
  t: any;
}

export const N8NView: React.FC<N8NViewProps> = ({ t }) => {
  const [selectedSample, setSelectedSample] = useState<'vulnerable' | 'hardened'>('vulnerable');

  const vulnerableNodes = [
    { id: "node-1", name: "Public Lead Webhook", type: "n8n-nodes-base.webhook", status: "HIGH", issue: "Unauthenticated Webhook (auth: none)" },
    { id: "node-2", name: "Dynamic Expression Evaluator", type: "n8n-nodes-base.code", status: "CRITICAL", issue: "Direct process.env & eval() execution" },
    { id: "node-3", name: "Internal DB Purge Request", type: "n8n-nodes-base.httpRequest", status: "CRITICAL", issue: "SSRF to 127.0.0.1 & Disabled TLS Cert Checks" },
  ];

  const hardenedNodes = [
    { id: "sec-1", name: "Authenticated Intake Webhook", type: "n8n-nodes-base.webhook", status: "CLEAN", issue: "Header Auth enforced" },
    { id: "sec-2", name: "Input Sanitizer", type: "n8n-nodes-base.code", status: "CLEAN", issue: "Bounds checking, no eval or process.env" },
    { id: "sec-3", name: "Human Approval Gate", type: "n8n-nodes-base.wait", status: "CLEAN", issue: "Explicit human review gate" },
    { id: "sec-4", name: "Target CRM Dispatcher", type: "n8n-nodes-base.httpRequest", status: "CLEAN", issue: "5000ms timeout & strict TLS verification" },
    { id: "sec-5", name: "Error Trigger Handler", type: "n8n-nodes-base.errorTrigger", status: "CLEAN", issue: "Dead-letter and failure capture node" },
  ];

  const nodesToDisplay = selectedSample === 'vulnerable' ? vulnerableNodes : hardenedNodes;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">{t.n8n.title}</h2>
          <p className="text-xs text-slate-400 mt-1">{t.n8n.subtitle}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setSelectedSample('vulnerable')}
            className={`btn text-xs ${selectedSample === 'vulnerable' ? 'btn-danger' : 'btn-secondary'}`}
          >
            Vulnerable Sample Workflow
          </button>
          <button
            onClick={() => setSelectedSample('hardened')}
            className={`btn text-xs ${selectedSample === 'hardened' ? 'btn-success' : 'btn-secondary'}`}
          >
            Hardened Sentinel Workflow
          </button>
        </div>
      </div>

      {/* Workflow Nodes Visual Flow */}
      <div className="glass-panel p-6">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">
          Workflow Pipeline Topology ({selectedSample === 'vulnerable' ? '🔴 100/100 CRITICAL RISK' : '🟢 0/100 SECURE'})
        </h3>

        <div className="flex flex-col md:flex-row items-center justify-between gap-3 overflow-x-auto p-4 bg-slate-950/60 rounded-xl border border-slate-800">
          {nodesToDisplay.map((node, idx) => (
            <React.Fragment key={node.id}>
              <div className={`p-4 rounded-lg border min-w-[200px] text-center ${
                node.status === 'CRITICAL' ? 'bg-rose-950/20 border-rose-500/40 text-rose-300' :
                node.status === 'HIGH' ? 'bg-amber-950/20 border-amber-500/40 text-amber-300' :
                'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
              }`}>
                <span className={`badge ${
                  node.status === 'CRITICAL' ? 'badge-critical' :
                  node.status === 'HIGH' ? 'badge-high' : 'badge-allow'
                } text-[9px]`}>
                  {node.status}
                </span>
                <div className="font-bold text-xs mt-2 text-white">{node.name}</div>
                <div className="font-mono text-[10px] text-slate-400 truncate mt-0.5">{node.type}</div>
                <div className="mt-2 text-[11px] text-slate-300 font-sans border-t border-slate-800/80 pt-1.5">
                  {node.issue}
                </div>
              </div>

              {idx < nodesToDisplay.length - 1 && (
                <div className="hidden md:block text-slate-600 font-mono text-xl">➔</div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  );
};
