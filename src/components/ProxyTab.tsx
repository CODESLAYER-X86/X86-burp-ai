import React, { useState, useEffect } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { Radio, ArrowRight, Check, X, RefreshCw, Send, ShieldAlert, Cpu } from 'lucide-react';

interface InterceptedTx {
  id: string;
  timestamp: number;
  clientIp: string;
  originalRequest: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  modifiedRequest?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  modifications: Array<{
    parameter?: string;
    header?: string;
    oldValue: string;
    newValue: string;
    reason: string;
  }>;
  status: 'PENDING' | 'FORWARDED' | 'DROPPED';
  interceptedBy: 'human' | 'ai' | 'pass_through';
}

export const ProxyTab: React.FC = () => {
  const [proxyMode, setProxyMode] = useState<'PASS_THROUGH' | 'HUMAN_INTERCEPT' | 'AI_INTERCEPT'>('HUMAN_INTERCEPT');
  const [aiPolicy, setAiPolicy] = useState<'OFF' | 'OBSERVE_ONLY' | 'ASK_BEFORE_MODIFY' | 'AUTO_MODIFY_WITHIN_SCOPE'>('OBSERVE_ONLY');
  const [queue, setQueue] = useState<InterceptedTx[]>([]);
  const [history, setHistory] = useState<InterceptedTx[]>([]);
  const [selectedTx, setSelectedTx] = useState<InterceptedTx | null>(null);

  // Editable fields for intercepted request
  const [editUrl, setEditUrl] = useState('');
  const [editMethod, setEditMethod] = useState('GET');
  const [editHeaders, setEditHeaders] = useState('');
  const [editBody, setEditBody] = useState('');
  const [reason, setReason] = useState('Manual security parameter mutation');

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/proxy/status');
      if (res.ok) {
        const data = await res.json();
        setProxyMode(data.mode);
        setAiPolicy(data.aiPolicy);
      }
      const qRes = await fetch('/api/proxy/queue');
      if (qRes.ok) {
        const qData = await qRes.json();
        setQueue(qData.queue || []);
        if (qData.queue && qData.queue.length > 0 && !selectedTx) {
          loadTxForEditing(qData.queue[0]);
        }
      }
      const hRes = await fetch('/api/proxy/history');
      if (hRes.ok) {
        const hData = await hRes.json();
        setHistory(hData.history || []);
      }
    } catch {}
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  const loadTxForEditing = (tx: InterceptedTx) => {
    setSelectedTx(tx);
    const req = tx.modifiedRequest || tx.originalRequest;
    setEditUrl(req.url);
    setEditMethod(req.method);
    setEditHeaders(
      Object.entries(req.headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n')
    );
    setEditBody(req.body || '');
  };

  const handleUpdateMode = async (newMode: typeof proxyMode) => {
    setProxyMode(newMode);
    await fetch('/api/proxy/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: newMode, aiPolicy }),
    });
  };

  const handleUpdateAiPolicy = async (newPolicy: typeof aiPolicy) => {
    setAiPolicy(newPolicy);
    await fetch('/api/proxy/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: proxyMode, aiPolicy: newPolicy }),
    });
  };

  const handleForward = async () => {
    if (!selectedTx) return;
    // Parse headers
    const headerMap: Record<string, string> = {};
    editHeaders.split('\n').forEach((line) => {
      const idx = line.indexOf(':');
      if (idx !== -1) {
        headerMap[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    });

    const modifiedReq = {
      method: editMethod,
      url: editUrl,
      headers: headerMap,
      body: editBody,
    };

    await fetch('/api/proxy/forward', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: selectedTx.id,
        modifiedRequest: modifiedReq,
        reason,
      }),
    });

    setSelectedTx(null);
    fetchStatus();
  };

  const handleDrop = async () => {
    if (!selectedTx) return;
    await fetch('/api/proxy/drop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: selectedTx.id }),
    });
    setSelectedTx(null);
    fetchStatus();
  };

  const handleSimulateBrowserTraffic = async (samplePath: string) => {
    await fetch('/api/proxy/simulate-intercept', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'GET',
        url: `http://127.0.0.1:8080${samplePath}`,
        headers: {
          Host: '127.0.0.1:8080',
          'User-Agent': 'Mozilla/5.0 (Browser Client via Agentic Proxy)',
          Cookie: 'session=sess_user_alice_9912',
          'X-CSRF-Token': 'csrf_token_alice_849204',
        },
      }),
    });
    fetchStatus();
  };

  return (
    <div className="space-y-6">
      {/* Top Proxy Configuration Banner */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-white font-semibold text-base mb-1">
              <Radio className="h-4 w-4 text-red-400" />
              <span>Real Browser Intercepting Proxy (127.0.0.1:8081)</span>
            </div>
            <p className="text-xs text-neutral-400 max-w-3xl leading-relaxed">
              Configure your browser proxy to <code>127.0.0.1:8081</code>. Agentic-Burp intercepts incoming traffic before forwarding to the target, preserving immutable original copies and structured mutation diffs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Interception Mode Selector */}
            <div className="flex items-center gap-1 bg-neutral-950 p-1 rounded border border-neutral-800">
              <button
                onClick={() => handleUpdateMode('PASS_THROUGH')}
                className={`px-3 py-1 text-xs font-mono rounded font-medium transition-colors ${
                  proxyMode === 'PASS_THROUGH' ? 'bg-neutral-800 text-white' : 'text-neutral-400 hover:text-white'
                }`}
              >
                Pass-Through
              </button>
              <button
                onClick={() => handleUpdateMode('HUMAN_INTERCEPT')}
                className={`px-3 py-1 text-xs font-mono rounded font-medium transition-colors ${
                  proxyMode === 'HUMAN_INTERCEPT' ? 'bg-red-950 text-red-400 border border-red-800 font-bold' : 'text-neutral-400 hover:text-white'
                }`}
              >
                Intercept ON
              </button>
              <button
                onClick={() => handleUpdateMode('AI_INTERCEPT')}
                className={`px-3 py-1 text-xs font-mono rounded font-medium transition-colors ${
                  proxyMode === 'AI_INTERCEPT' ? 'bg-sky-950 text-sky-400 border border-sky-800 font-bold' : 'text-neutral-400 hover:text-white'
                }`}
              >
                AI Intercept
              </button>
            </div>

            {/* Simulate button for testing immediately */}
            <button
              onClick={() => handleSimulateBrowserTraffic('/api/orders?id=101')}
              className="px-3 py-1.5 text-xs font-mono font-medium rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 transition-colors"
            >
              + Simulate Browser Request
            </button>
          </div>
        </div>

        {/* AI Interception Policy Bar */}
        <div className="mt-4 pt-3 border-t border-neutral-800 flex flex-col sm:flex-row sm:items-center justify-between text-xs font-mono text-neutral-400 gap-2">
          <div className="flex items-center gap-2">
            <Cpu className="h-3.5 w-3.5 text-neutral-400" />
            <span>AI Policy (Section 20):</span>
            <select
              value={aiPolicy}
              onChange={(e) => handleUpdateAiPolicy(e.target.value as any)}
              className="bg-neutral-950 border border-neutral-800 rounded px-2 py-0.5 text-xs text-white focus:outline-none"
            >
              <option value="OBSERVE_ONLY">OBSERVE_ONLY (Default - Passive)</option>
              <option value="ASK_BEFORE_MODIFY">ASK_BEFORE_MODIFY (Hold in queue)</option>
              <option value="AUTO_MODIFY_WITHIN_SCOPE">AUTO_MODIFY_WITHIN_SCOPE (CTF Mode)</option>
              <option value="OFF">OFF (Disabled)</option>
            </select>
          </div>
          <div>Pending Queue: {queue.length} | Total Inspected: {history.length}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: Intercepted Request Editor */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-neutral-800 pb-2.5">
            <div className="flex items-center gap-2 font-mono text-xs font-semibold text-white uppercase">
              <span>Intercepted Request</span>
              {selectedTx && (
                <span className="text-red-400 bg-red-950 px-2 py-0.5 rounded border border-red-800">
                  {selectedTx.id}
                </span>
              )}
            </div>

            {selectedTx && (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleForward}
                  className="px-3 py-1 text-xs font-mono font-bold bg-emerald-600 hover:bg-emerald-500 text-white rounded transition-colors flex items-center gap-1"
                >
                  <Check className="h-3.5 w-3.5" />
                  <span>Forward</span>
                </button>
                <button
                  onClick={handleDrop}
                  className="px-2.5 py-1 text-xs font-mono bg-red-950 hover:bg-red-900 text-red-400 border border-red-800 rounded transition-colors flex items-center gap-1"
                >
                  <X className="h-3.5 w-3.5" />
                  <span>Drop</span>
                </button>
              </div>
            )}
          </div>

          {selectedTx ? (
            <div className="space-y-3">
              <div className="flex gap-2">
                <select
                  value={editMethod}
                  onChange={(e) => setEditMethod(e.target.value)}
                  className="bg-neutral-950 border border-neutral-800 rounded px-2.5 py-1 text-xs font-mono text-white"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
                <input
                  type="text"
                  value={editUrl}
                  onChange={(e) => setEditUrl(e.target.value)}
                  className="flex-1 bg-neutral-950 border border-neutral-800 rounded px-3 py-1 text-xs font-mono text-white focus:outline-none focus:border-red-500"
                />
              </div>

              <div>
                <label className="text-[11px] text-neutral-400 font-mono uppercase block mb-1">
                  HTTP Headers
                </label>
                <textarea
                  rows={5}
                  value={editHeaders}
                  onChange={(e) => setEditHeaders(e.target.value)}
                  className="w-full bg-neutral-950 border border-neutral-800 rounded p-2.5 text-xs font-mono text-neutral-300 focus:outline-none"
                />
              </div>

              {editMethod !== 'GET' && (
                <div>
                  <label className="text-[11px] text-neutral-400 font-mono uppercase block mb-1">
                    Request Body
                  </label>
                  <textarea
                    rows={3}
                    value={editBody}
                    onChange={(e) => setEditBody(e.target.value)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded p-2.5 text-xs font-mono text-neutral-300 focus:outline-none"
                  />
                </div>
              )}

              <div>
                <label className="text-[11px] text-neutral-400 font-mono uppercase block mb-1">
                  Audit Reason (Logged for AI / Human Diff)
                </label>
                <input
                  type="text"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full bg-neutral-950 border border-neutral-800 rounded px-3 py-1 text-xs font-mono text-neutral-300"
                />
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-xs font-mono text-neutral-400 border border-neutral-800/80 rounded bg-neutral-950/40">
              No request currently intercepted. Click "+ Simulate Browser Request" above or point your browser to 127.0.0.1:8081.
            </div>
          )}
        </div>

        {/* Right Column: Original vs Modified Diff (Section 4) */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-neutral-800 pb-2.5">
            <span className="font-mono text-xs font-semibold text-white uppercase">
              Immutable Original vs Modified Diff
            </span>
            <span className="text-xs text-neutral-400 font-mono">Section 4 Invariant</span>
          </div>

          {selectedTx ? (
            <div className="space-y-3">
              {/* Diff summary box */}
              <div className="rounded border border-neutral-800 bg-neutral-950 p-3 font-mono text-xs space-y-1.5">
                <div className="text-neutral-400">Original Target:</div>
                <div className="text-neutral-300 break-all">{selectedTx.originalRequest.url}</div>

                {editUrl !== selectedTx.originalRequest.url && (
                  <>
                    <div className="text-amber-400 pt-2">Modified Target:</div>
                    <div className="text-amber-300 break-all">{editUrl}</div>
                  </>
                )}
              </div>

              {selectedTx.modifications.length > 0 ? (
                <div className="space-y-2">
                  <div className="text-[11px] font-mono text-neutral-400 uppercase">Recorded Structural Mutations:</div>
                  {selectedTx.modifications.map((m, idx) => (
                    <div key={idx} className="p-2.5 rounded border border-neutral-800 bg-neutral-950 font-mono text-xs">
                      <div className="text-neutral-300 font-semibold">{m.parameter || m.header}:</div>
                      <div className="text-red-400 line-through">Old: {m.oldValue}</div>
                      <div className="text-emerald-400">New: {m.newValue}</div>
                      <div className="text-[11px] text-neutral-400 mt-1 italic">Reason: {m.reason}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 text-center text-xs font-mono text-neutral-400 border border-neutral-800/80 rounded bg-neutral-950/40">
                  Request matches original. Modifying URL, parameters, or headers will record an immutable diff.
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center text-xs font-mono text-neutral-400 border border-neutral-800/80 rounded bg-neutral-950/40">
              Select or intercept a request to inspect original vs modified representations.
            </div>
          )}
        </div>
      </div>

      {/* Intercept Queue & History Table */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 overflow-hidden">
        <div className="bg-neutral-950 px-4 py-2.5 border-b border-neutral-800 flex items-center justify-between">
          <span className="text-xs font-mono font-semibold text-white">
            Proxy Traffic History ({history.length} transactions)
          </span>
          <span className="text-xs font-mono text-neutral-400">
            Immutable Original Audits Available
          </span>
        </div>

        <div className="overflow-x-auto max-h-64 overflow-y-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-neutral-950/80 border-b border-neutral-800 text-neutral-400 text-[11px]">
              <tr>
                <th className="py-2 px-4">Tx ID</th>
                <th className="py-2 px-4">Method</th>
                <th className="py-2 px-4">URL</th>
                <th className="py-2 px-4">Status</th>
                <th className="py-2 px-4">Modified?</th>
                <th className="py-2 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/60 text-neutral-300">
              {history.map((tx) => (
                <tr key={tx.id} className="hover:bg-neutral-800/30">
                  <td className="py-2 px-4 text-neutral-400">{tx.id}</td>
                  <td className="py-2 px-4 font-semibold text-sky-400">{tx.originalRequest.method}</td>
                  <td className="py-2 px-4 text-white truncate max-w-xs">{tx.originalRequest.url}</td>
                  <td className="py-2 px-4">
                    <span className={`px-1.5 py-0.5 rounded ${tx.status === 'FORWARDED' ? 'text-emerald-400 bg-emerald-950/80' : 'text-red-400 bg-red-950/80'}`}>
                      {tx.status}
                    </span>
                  </td>
                  <td className="py-2 px-4 text-neutral-400">
                    {tx.modifications.length > 0 ? (
                      <span className="text-amber-400 font-semibold">{tx.modifications.length} diffs</span>
                    ) : (
                      'None'
                    )}
                  </td>
                  <td className="py-2 px-4 text-right">
                    <button
                      onClick={() => loadTxForEditing(tx)}
                      className="text-xs text-neutral-400 hover:text-white"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
