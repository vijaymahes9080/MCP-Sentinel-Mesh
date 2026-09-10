import React, { useState } from 'react';

interface AuditEventItem {
  event_id: string;
  sequence_index: number;
  previous_hash: string;
  current_hash: string;
  timestamp: string;
  event_type: string;
  principal: string;
  action: string;
  decision: string;
  payload_digest: string;
  latency_ms: number;
}

interface RuntimeEventsViewProps {
  events: AuditEventItem[];
  auditValid: boolean;
  t: any;
  onRefresh: () => void;
}

export const RuntimeEventsView: React.FC<RuntimeEventsViewProps> = ({
  events,
  auditValid,
  t,
  onRefresh,
}) => {
  const [filter, setFilter] = useState<'ALL' | 'ALLOW' | 'DENY' | 'PENDING_APPROVAL'>('ALL');

  const filteredEvents = events.filter((e) => {
    if (filter === 'ALL') return true;
    return e.decision === filter;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">{t.runtime.title}</h2>
          <p className="text-xs text-slate-400 mt-1">{t.runtime.subtitle}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={onRefresh} className="btn btn-secondary text-xs">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh Ledger
          </button>
        </div>
      </div>

      {/* Audit Integrity Banner */}
      <div className={`glass-panel p-4 flex items-center justify-between border ${
        auditValid ? 'border-emerald-500/30 bg-emerald-950/10' : 'border-rose-500/30 bg-rose-950/10'
      }`}>
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${auditValid ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
          <div>
            <div className="text-xs font-semibold text-white">
              {t.runtime.chainIntegrity}: <span className={auditValid ? 'text-emerald-400' : 'text-rose-400'}>
                {auditValid ? t.runtime.verified : t.runtime.corrupted}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              SHA-256 Chained Hash Sequence Verified Across {events.length} Historical Records.
            </p>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex gap-1.5 text-xs">
          {(['ALL', 'ALLOW', 'DENY', 'PENDING_APPROVAL'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setFilter(mode)}
              className={`px-2.5 py-1 rounded text-[11px] font-mono transition ${
                filter === mode
                  ? 'bg-indigo-600 text-white font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white'
              }`}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Events Table */}
      <div className="glass-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono">
              <tr>
                <th className="p-3">Seq #</th>
                <th className="p-3">Timestamp</th>
                <th className="p-3">{t.runtime.principal}</th>
                <th className="p-3">{t.runtime.action}</th>
                <th className="p-3">{t.runtime.decision}</th>
                <th className="p-3">{t.runtime.latency}</th>
                <th className="p-3">SHA-256 Digest</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEvents.map((ev) => (
                <tr key={ev.event_id} className="hover:bg-slate-900/40 transition">
                  <td className="p-3 text-slate-500">#{ev.sequence_index}</td>
                  <td className="p-3 text-slate-400 whitespace-nowrap">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-3 text-indigo-300 font-medium">{ev.principal}</td>
                  <td className="p-3 text-white font-semibold">{ev.action}</td>
                  <td className="p-3">
                    <span className={`badge ${
                      ev.decision === 'ALLOW' ? 'badge-allow' :
                      ev.decision === 'DENY' ? 'badge-deny' : 'badge-approval'
                    }`}>
                      {ev.decision}
                    </span>
                  </td>
                  <td className="p-3 text-slate-300">{ev.latency_ms} ms</td>
                  <td className="p-3 text-slate-500 truncate max-w-[140px]" title={ev.current_hash}>
                    {ev.current_hash.slice(0, 16)}...
                  </td>
                </tr>
              ))}

              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-400">
                    No runtime audit events matching filter "{filter}".
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
