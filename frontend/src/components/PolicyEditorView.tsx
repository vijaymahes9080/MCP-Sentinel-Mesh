import React, { useState } from 'react';

interface PolicyEditorViewProps {
  t: any;
}

export const PolicyEditorView: React.FC<PolicyEditorViewProps> = ({ t }) => {
  const [testToolName, setTestToolName] = useState('drop_database_table');
  const [testArgs, setTestArgs] = useState('{"table_name": "users", "confirm_purge": true}');
  const [simResult, setSimResult] = useState<any>(null);
  const [evaluating, setEvaluating] = useState(false);

  const policyRules = [
    {
      id: "POL-DEFAULT-001",
      name: "Require Approval for Destructive or Admin Tools",
      priority: 10,
      effect: "REQUIRE_APPROVAL",
      tools: ["execute_shell_command", "drop_database_table", "*_delete*", "*_purge*"],
      principals: ["*"],
      desc: "Intercepts mutating destructive commands and requires operator consent."
    },
    {
      id: "POL-DEFAULT-002",
      name: "Block Internal and Cloud Metadata SSRF Egress",
      priority: 20,
      effect: "DENY",
      tools: ["*"],
      principals: ["*"],
      desc: "Denies egress targeting 169.254.169.254, localhost, or private subnets."
    },
    {
      id: "POL-DEFAULT-003",
      name: "Allow Safe Read-Only Utilities",
      priority: 100,
      effect: "ALLOW",
      tools: ["get_system_health", "lookup_weather"],
      principals: ["*"],
      desc: "Allows read-only queries with sliding-window rate limit (120 req/min)."
    }
  ];

  const handleSimulate = async () => {
    setEvaluating(true);
    try {
      let parsedArgs = {};
      try {
        parsedArgs = JSON.parse(testArgs);
      } catch {
        alert("Invalid JSON in test arguments");
        setEvaluating(false);
        return;
      }

      const resp = await fetch('/policies/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          call_id: 'sim-' + Math.random().toString(36).slice(2, 8),
          caller_agent_id: 'agent-evaluator',
          tool_name: testToolName,
          arguments: parsedArgs
        })
      });
      if (!resp.ok) throw new Error("Evaluation error");
      const data = await resp.json();
      setSimResult(data);
    } catch (err) {
      console.error(err);
      // Local dry-run fallback
      setSimResult({
        decision: testToolName.includes("drop") || testToolName.includes("shell") ? "REQUIRE_APPROVAL" : "ALLOW",
        reason: "Simulated policy check evaluation.",
        requires_approval: testToolName.includes("drop") || testToolName.includes("shell"),
        approval_id: "APPR-SIM-001"
      });
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">{t.nav.policies}</h2>
        <p className="text-xs text-slate-400 mt-1">
          Declarative rule set evaluated by the runtime proxy in priority order (lower priority value = higher evaluation precedence).
        </p>
      </div>

      {/* Rules Table */}
      <div className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <span className="text-xs font-bold text-white uppercase tracking-wider">Active Policy Rules ({policyRules.length})</span>
          <span className="badge badge-info text-[10px]">Deterministic Evaluation</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono">
              <tr>
                <th className="p-3">Priority</th>
                <th className="p-3">Rule ID & Name</th>
                <th className="p-3">Effect</th>
                <th className="p-3">Tool Matches</th>
                <th className="p-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {policyRules.map((rule) => (
                <tr key={rule.id} className="hover:bg-slate-900/40 transition">
                  <td className="p-3 text-indigo-400 font-bold">#{rule.priority}</td>
                  <td className="p-3">
                    <div className="font-bold text-white">{rule.name}</div>
                    <div className="text-[10px] text-slate-500">{rule.id}</div>
                  </td>
                  <td className="p-3">
                    <span className={`badge ${
                      rule.effect === 'ALLOW' ? 'badge-allow' :
                      rule.effect === 'DENY' ? 'badge-deny' : 'badge-approval'
                    }`}>
                      {rule.effect}
                    </span>
                  </td>
                  <td className="p-3 text-slate-300">
                    {rule.tools.join(', ')}
                  </td>
                  <td className="p-3 text-slate-400 font-sans text-xs">
                    {rule.desc}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Dry-Run Policy Simulator */}
      <div className="glass-panel p-6 bg-slate-900/80">
        <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
          <span>🧪</span> Policy Evaluation Simulator (Dry-Run)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div>
            <label className="font-semibold text-slate-300 block mb-1">Target Tool Name:</label>
            <input
              type="text"
              value={testToolName}
              onChange={(e) => setTestToolName(e.target.value)}
              className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:border-indigo-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="font-semibold text-slate-300 block mb-1">Tool Input Arguments (JSON):</label>
            <textarea
              rows={3}
              value={testArgs}
              onChange={(e) => setTestArgs(e.target.value)}
              className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="mt-4 flex items-center justify-between">
          <button
            onClick={handleSimulate}
            disabled={evaluating}
            className="btn btn-primary text-xs"
          >
            {evaluating ? 'Simulating...' : 'Test Policy Evaluation'}
          </button>

          {simResult && (
            <div className="flex items-center gap-3">
              <span className="text-slate-400 text-xs">Simulated Outcome:</span>
              <span className={`badge ${
                simResult.decision === 'ALLOW' ? 'badge-allow' :
                simResult.decision === 'DENY' ? 'badge-deny' : 'badge-approval'
              }`}>
                {simResult.decision}
              </span>
              <span className="text-xs text-slate-300 font-mono">
                {simResult.reason}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
