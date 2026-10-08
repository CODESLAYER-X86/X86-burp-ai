import React, { useState } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { Shield, ShieldAlert, Check, AlertCircle } from 'lucide-react';

interface ScopeTabProps {
  engine: SecurityEngineService;
}

export const ScopeTab: React.FC<ScopeTabProps> = ({ engine }) => {
  const [testUrl, setTestUrl] = useState('http://127.0.0.1:8080/api/profile?id=101');
  const [testMethod, setTestMethod] = useState('GET');
  const [validationResult, setValidationResult] = useState<{ allowed: boolean; reason: string } | null>(null);

  const [newTarget, setNewTarget] = useState('');

  const handleTestScope = () => {
    const res = engine.validateScope(testUrl, testMethod);
    setValidationResult(res);
  };

  const handleAddTarget = () => {
    if (newTarget && !engine.scopePolicy.targets.includes(newTarget)) {
      engine.scopePolicy.targets.push(newTarget);
      setNewTarget('');
      engine.logEvent('scope_updated', 'DISCOVERY', `Added authorized target: ${newTarget}`);
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="h-5 w-5 text-red-400" />
          <h2 className="text-base font-semibold text-white tracking-tight">
            Deterministic Scope Enforcement Gate
          </h2>
        </div>
        <p className="text-xs text-neutral-400 leading-relaxed max-w-3xl">
          All network requests pass through this deterministic validator before reaching outbound sockets.
          The LLM reasoning engine (Gemma 4 31B) cannot override, expand, or bypass these rules under any circumstance.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scope Policy Configuration */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white tracking-tight">
            Configured Authorized Scope Targets
          </h3>

          <div className="space-y-2">
            {engine.scopePolicy.targets.map((target, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2.5 rounded border border-neutral-800 bg-neutral-950 font-mono text-xs text-neutral-200"
              >
                <span>{target}</span>
                <span className="text-emerald-400 text-xs">AUTHORIZED</span>
              </div>
            ))}
          </div>

          <div className="flex items-center gap-2 pt-2">
            <input
              type="text"
              placeholder="https://authorized-lab.example"
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              className="flex-1 bg-neutral-950 border border-neutral-800 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-red-500"
            />
            <button
              onClick={handleAddTarget}
              className="px-3 py-1.5 text-xs font-medium text-white bg-neutral-800 hover:bg-neutral-700 rounded border border-neutral-700 transition-colors"
            >
              Add Target
            </button>
          </div>

          <div className="border-t border-neutral-800/80 pt-4 space-y-3">
            <div className="flex items-center justify-between text-xs text-neutral-300">
              <span>Allowed HTTP Methods:</span>
              <span className="font-mono text-neutral-400">
                {engine.scopePolicy.allowed_methods.join(', ')}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs text-neutral-300">
              <span>Allowed TCP Ports:</span>
              <span className="font-mono text-neutral-400">
                {engine.scopePolicy.allowed_ports.join(', ')}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs text-neutral-300">
              <span>Cloud Metadata SSRF Protection:</span>
              <span className="font-mono text-emerald-400">STRICT BLOCK</span>
            </div>
            <div className="flex items-center justify-between text-xs text-neutral-300">
              <span>Rate Limit Gate:</span>
              <span className="font-mono text-neutral-400">
                {engine.scopePolicy.max_requests_per_minute} requests / min
              </span>
            </div>
          </div>
        </div>

        {/* Live Scope Validator Tester */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white tracking-tight">
            Live URL Scope & SSRF Validator
          </h3>
          <p className="text-xs text-neutral-400 leading-relaxed">
            Test any URL against the deterministic gate to preview authorization decision and SSRF defense.
          </p>

          <div className="space-y-3">
            <div>
              <label className="text-xs text-neutral-400 block mb-1">Method</label>
              <select
                value={testMethod}
                onChange={(e) => setTestMethod(e.target.value)}
                className="w-full bg-neutral-950 border border-neutral-800 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none"
              >
                {engine.scopePolicy.allowed_methods.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
                <option value="CONNECT">CONNECT (Disallowed)</option>
              </select>
            </div>

            <div>
              <label className="text-xs text-neutral-400 block mb-1">Target URL</label>
              <input
                type="text"
                value={testUrl}
                onChange={(e) => setTestUrl(e.target.value)}
                className="w-full bg-neutral-950 border border-neutral-800 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-red-500"
              />
            </div>

            {/* Quick Preset Buttons */}
            <div className="flex flex-wrap gap-1.5 pt-1">
              <button
                onClick={() => setTestUrl('http://127.0.0.1:8080/api/profile?id=101')}
                className="text-xs text-neutral-400 bg-neutral-950 px-2 py-1 rounded border border-neutral-800 hover:text-white"
              >
                In-Scope Lab
              </button>
              <button
                onClick={() => setTestUrl('http://169.254.169.254/latest/meta-data/')}
                className="text-xs text-red-400 bg-neutral-950 px-2 py-1 rounded border border-neutral-800 hover:text-red-300"
              >
                Cloud Metadata (SSRF)
              </button>
              <button
                onClick={() => setTestUrl('https://evil-unauthorized.example/probe')}
                className="text-xs text-neutral-400 bg-neutral-950 px-2 py-1 rounded border border-neutral-800 hover:text-white"
              >
                External Host
              </button>
            </div>

            <button
              onClick={handleTestScope}
              className="w-full py-2 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded transition-colors"
            >
              Evaluate Scope Gate
            </button>

            {validationResult && (
              <div
                className={`p-3 rounded border text-xs font-mono mt-3 ${
                  validationResult.allowed
                    ? 'border-emerald-800/80 bg-emerald-950/40 text-emerald-300'
                    : 'border-red-800/80 bg-red-950/40 text-red-300'
                }`}
              >
                <div className="flex items-center gap-2 font-semibold">
                  {validationResult.allowed ? (
                    <>
                      <Check className="h-4 w-4" />
                      <span>GATEWAY STATUS: PERMITTED</span>
                    </>
                  ) : (
                    <>
                      <AlertCircle className="h-4 w-4" />
                      <span>GATEWAY STATUS: BLOCKED</span>
                    </>
                  )}
                </div>
                <div className="mt-1 text-xs opacity-90">{validationResult.reason}</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
