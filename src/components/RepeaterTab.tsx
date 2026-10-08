import React, { useState } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { RefreshCw, ArrowLeftRight, Check, AlertTriangle } from 'lucide-react';

interface RepeaterTabProps {
  engine: SecurityEngineService;
}

export const RepeaterTab: React.FC<RepeaterTabProps> = ({ engine }) => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('http://127.0.0.1:8080/api/profile?id=101');
  const [headers, setHeaders] = useState('User-Agent: Agentic-Burp/1.0\nAccept: application/json');
  const [body, setBody] = useState('');

  const [response, setResponse] = useState<any>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string>(engine.activeSessionId);

  const handleApplySessionTokens = (sessId: string) => {
    setSelectedSessionId(sessId);
    const session = engine.sessionProfiles.find(s => s.id === sessId);
    if (!session) return;

    // Automatically update the header text with the session's token and cookie
    let newHeaders = `User-Agent: Agentic-Burp/1.0\nAccept: application/json`;
    if (session.token) {
      newHeaders += `\nAuthorization: ${session.token}`;
    }
    if (session.cookie) {
      newHeaders += `\nCookie: ${session.cookie}`;
    }
    if (session.csrfToken) {
      newHeaders += `\nX-CSRF-Token: ${session.csrfToken}`;
    }
    setHeaders(newHeaders);
  };

  const handleSend = () => {
    // Parse headers
    const headerMap: Record<string, string> = {};
    headers.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx !== -1) {
        headerMap[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    });

    const res = engine.replayRequest(method, url, headerMap, body);
    setResponse(res);
  };

  const setPreset = (presetUrl: string, presetMethod: string = 'GET') => {
    setUrl(presetUrl);
    setMethod(presetMethod);
  };

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-white font-semibold text-base mb-1">
              <RefreshCw className="h-4 w-4 text-red-400" />
              <span>Burp-Style Request Repeater & Response Comparator</span>
            </div>
            <p className="text-xs text-neutral-400">
              Replay authorized requests with structured parameter mutations. Computes response similarity score and behavioral deviations deterministically.
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <button
              onClick={() => setPreset('http://127.0.0.1:8080/api/profile?id=101')}
              className="text-xs font-mono bg-neutral-950 px-2.5 py-1 rounded border border-neutral-800 text-neutral-300 hover:text-white"
            >
              Baseline ID 101
            </button>
            <button
              onClick={() => setPreset('http://127.0.0.1:8080/api/profile?id=102')}
              className="text-xs font-mono bg-neutral-950 px-2.5 py-1 rounded border border-neutral-800 text-neutral-300 hover:text-white"
            >
              IDOR Test (ID 102)
            </button>
            <button
              onClick={() => setPreset("http://127.0.0.1:8080/api/products?cat=items'")}
              className="text-xs font-mono bg-neutral-950 px-2.5 py-1 rounded border border-neutral-800 text-red-400 hover:text-red-300"
            >
              SQLi Quote Test
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Request Panel */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-neutral-800 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
                Request Editor
              </span>
              <span className="text-[11px] text-neutral-400 font-mono hidden sm:inline">·</span>
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-neutral-400 font-mono">Token / Identity:</span>
                <select
                  value={selectedSessionId}
                  onChange={(e) => handleApplySessionTokens(e.target.value)}
                  className="bg-neutral-950 border border-neutral-800 rounded px-2 py-0.5 text-xs font-mono text-amber-400 focus:outline-none"
                >
                  {engine.sessionProfiles.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <button
              onClick={handleSend}
              className="px-3.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded transition-colors whitespace-nowrap self-end sm:self-auto"
            >
              Send Request
            </button>
          </div>

          <div className="flex gap-2">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="bg-neutral-950 border border-neutral-800 rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1 bg-neutral-950 border border-neutral-800 rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-red-500"
            />
          </div>

          <div>
            <label className="text-[11px] text-neutral-400 uppercase font-mono block mb-1">
              Headers
            </label>
            <textarea
              rows={4}
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              className="w-full bg-neutral-950 border border-neutral-800 rounded p-2.5 text-xs font-mono text-neutral-300 focus:outline-none focus:border-neutral-700"
            />
          </div>

          {method !== 'GET' && (
            <div>
              <label className="text-[11px] text-neutral-400 uppercase font-mono block mb-1">
                Body
              </label>
              <textarea
                rows={3}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="w-full bg-neutral-950 border border-neutral-800 rounded p-2.5 text-xs font-mono text-neutral-300 focus:outline-none focus:border-neutral-700"
              />
            </div>
          )}
        </div>

        {/* Response & Comparator Panel */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
              Response Comparison
            </span>
            {response && (
              <span
                className={`text-xs font-mono font-semibold px-2 py-0.5 rounded ${
                  response.status_code === 200
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : response.status_code === 500
                    ? 'bg-red-950 text-red-400 border border-red-800'
                    : 'bg-neutral-800 text-neutral-300'
                }`}
              >
                HTTP {response.status_code} · {response.elapsed_ms}ms
              </span>
            )}
          </div>

          {response ? (
            <div className="space-y-3">
              {/* Diff Stats Banner */}
              <div className="rounded border border-neutral-800 bg-neutral-950 p-3 text-xs font-mono grid grid-cols-2 gap-3">
                <div>
                  <span className="text-neutral-400 block text-[11px]">Similarity Ratio</span>
                  <span className={`text-base font-bold ${response.similarity < 0.6 ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {(response.similarity * 100).toFixed(1)}%
                  </span>
                </div>
                <div>
                  <span className="text-neutral-400 block text-[11px]">Deviations Identified</span>
                  <span className="text-neutral-200">
                    {response.reasons.length > 0 ? response.reasons.join(', ') : 'None (Equivalent)'}
                  </span>
                </div>
              </div>

              <div>
                <label className="text-[11px] text-neutral-400 uppercase font-mono block mb-1">
                  Response Body
                </label>
                <pre className="w-full bg-neutral-950 border border-neutral-800 rounded p-3 text-xs font-mono text-neutral-200 overflow-x-auto max-h-56 leading-relaxed">
                  {response.body_text}
                </pre>
              </div>
            </div>
          ) : (
            <div className="rounded border border-neutral-800/80 bg-neutral-950/40 p-12 text-center text-xs text-neutral-400">
              Click 'Send Request' to execute through the Repeater engine and view response delta.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
