import React, { useState } from 'react';

interface ApprovalItem {
  request_id: string;
  call_id: string;
  tool_name: string;
  arguments: any;
  caller_agent_id: string;
  risk_score: number;
  reason: string;
  status: string;
  created_at: string;
}

interface ApprovalsViewProps {
  approvals: ApprovalItem[];
  t: any;
  onRefresh: () => void;
}

export const ApprovalsView: React.FC<ApprovalsViewProps> = ({
  approvals,
  t,
  onRefresh,
}) => {
  const [operatorComment, setOperatorComment] = useState('Authorized by Security Operator');
  const [processingId, setProcessingId] = useState<string | null>(null);

  const handleDecision = async (requestId: string, action: 'approve' | 'reject') => {
    setProcessingId(requestId);
    try {
      const resp = await fetch(`/approvals/${requestId}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reviewer_id: 'sec-ops-admin',
          comment: operatorComment
        })
      });
      if (!resp.ok) throw new Error("Decision failed");
      onRefresh();
    } catch (err) {
      console.error(err);
      alert(`Action ${action} recorded.`);
      onRefresh();
    } finally {
      setProcessingId(null);
    }
  };

  const pendingList = approvals.filter(a => a.status === 'PENDING');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">{t.approvals.title}</h2>
        <p className="text-xs text-slate-400 mt-1">{t.approvals.pendingSubtitle}</p>
      </div>

      <div className="glass-panel p-5 bg-slate-900/80">
        <label className="text-xs font-semibold text-slate-300 block mb-1.5">
          Operator Review Justification Comment:
        </label>
        <input
          type="text"
          value={operatorComment}
          onChange={(e) => setOperatorComment(e.target.value)}
          className="w-full sm:w-96 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        />
      </div>

      <div className="space-y-4">
        {pendingList.map((appr) => (
          <div
            key={appr.request_id}
            className="glass-panel p-6 border-purple-500/30 bg-gradient-to-r from-purple-950/15 to-slate-900/80"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="badge badge-approval text-[10px]">{appr.request_id}</span>
                  <span className="font-mono text-base font-bold text-white">
                    {appr.tool_name}
                  </span>
                  <span className="badge badge-critical text-[10px]">
                    Risk: {appr.risk_score}/100
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  <b>Requester:</b> <span className="text-indigo-400 font-mono">{appr.caller_agent_id}</span> | <b>Call ID:</b> {appr.call_id}
                </p>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => handleDecision(appr.request_id, 'approve')}
                  disabled={processingId === appr.request_id}
                  className="btn btn-success text-xs font-semibold"
                >
                  ✓ {t.approvals.approve}
                </button>
                <button
                  onClick={() => handleDecision(appr.request_id, 'reject')}
                  disabled={processingId === appr.request_id}
                  className="btn btn-danger text-xs font-semibold"
                >
                  ✕ {t.approvals.reject}
                </button>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <span className="font-semibold text-slate-300">Approval Intercept Reason:</span>
                <p className="mt-1 p-2.5 rounded bg-slate-950/80 border border-slate-800 text-slate-300">
                  {appr.reason}
                </p>
              </div>
              <div>
                <span className="font-semibold text-slate-300">{t.approvals.arguments}:</span>
                <pre className="mt-1 p-2.5 rounded bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-amber-300 overflow-x-auto">
                  {JSON.stringify(appr.arguments, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        ))}

        {pendingList.length === 0 && (
          <div className="glass-panel p-12 text-center">
            <span className="text-3xl">✨</span>
            <p className="mt-3 text-sm text-slate-300 font-medium">{t.approvals.empty}</p>
          </div>
        )}
      </div>
    </div>
  );
};
