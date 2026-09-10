import React, { useState } from 'react';

interface ToolDef {
  name: string;
  description: string;
  parameters_schema: any;
  permissions: Array<{
    scope: string;
    resource_patterns: string[];
    data_classification: string;
    is_destructive: boolean;
  }>;
  source_version?: string;
}

interface InventoryViewProps {
  tools: ToolDef[];
  t: any;
}

export const InventoryView: React.FC<InventoryViewProps> = ({ tools, t }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTool, setSelectedTool] = useState<ToolDef | null>(null);

  const filteredTools = tools.filter(
    (tool) =>
      tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Search Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">{t.nav.inventory}</h2>
          <p className="text-xs text-slate-400 mt-1">
            Registered tools mediated by MCP Sentinel Mesh proxy with declared permission scopes.
          </p>
        </div>
        <div className="relative">
          <input
            type="text"
            placeholder="Search tools by name or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full sm:w-72 px-3.5 py-2 pl-9 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition"
          />
          <svg className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
      </div>

      {/* Tools Table / Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredTools.map((tool) => {
          const isDestructive = tool.permissions.some((p) => p.is_destructive);
          const scopes = tool.permissions.map((p) => p.scope);
          const classification = tool.permissions[0]?.data_classification || 'internal';

          return (
            <div
              key={tool.name}
              onClick={() => setSelectedTool(tool)}
              className="glass-panel p-5 glass-card-interactive flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <span className="font-mono text-sm font-bold text-indigo-300 truncate">
                    {tool.name}
                  </span>
                  {isDestructive ? (
                    <span className="badge badge-critical text-[9px]">Destructive</span>
                  ) : (
                    <span className="badge badge-allow text-[9px]">Read-Only</span>
                  )}
                </div>

                <p className="mt-2 text-xs text-slate-400 line-clamp-3 leading-relaxed">
                  {tool.description}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
                <div className="flex gap-1.5 flex-wrap">
                  {scopes.map((s, idx) => (
                    <span key={idx} className="badge badge-info text-[9px]">
                      {s}
                    </span>
                  ))}
                </div>
                <span className="text-slate-500 font-mono capitalize">
                  {classification}
                </span>
              </div>
            </div>
          );
        })}

        {filteredTools.length === 0 && (
          <div className="col-span-full glass-panel p-12 text-center">
            <p className="text-slate-400 text-sm">No tools matching "{searchTerm}".</p>
          </div>
        )}
      </div>

      {/* Schema Detail Modal */}
      {selectedTool && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="glass-panel max-w-2xl w-full p-6 bg-slate-900 border-indigo-500/30 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-base text-white">
                  {selectedTool.name}
                </span>
                <span className="badge badge-info text-[10px]">
                  v{selectedTool.source_version || '1.0.0'}
                </span>
              </div>
              <button
                onClick={() => setSelectedTool(null)}
                className="text-slate-400 hover:text-white p-1 rounded transition"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-4 text-xs">
              <div>
                <span className="font-semibold text-slate-300">Description:</span>
                <p className="mt-1 text-slate-400 leading-relaxed bg-slate-950/60 p-2.5 rounded border border-slate-800">
                  {selectedTool.description}
                </p>
              </div>

              <div>
                <span className="font-semibold text-slate-300">Declared Permissions:</span>
                <div className="mt-1 space-y-1.5">
                  {selectedTool.permissions.map((perm, idx) => (
                    <div key={idx} className="bg-slate-950/60 p-2 rounded border border-slate-800 font-mono text-[11px] flex justify-between">
                      <span>Scope: <b className="text-indigo-400">{perm.scope}</b> | Patterns: {perm.resource_patterns.join(', ')}</span>
                      <span>Classification: <b className="text-cyan-400">{perm.data_classification}</b></span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="font-semibold text-slate-300">Parameters Schema (JSONSchema):</span>
                <pre className="mt-1 bg-slate-950 p-3 rounded border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-48">
                  {JSON.stringify(selectedTool.parameters_schema, null, 2)}
                </pre>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button onClick={() => setSelectedTool(null)} className="btn btn-secondary text-xs">
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
