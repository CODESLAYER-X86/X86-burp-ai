import React from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { Cpu, ShieldCheck, Activity, RefreshCw } from 'lucide-react';

interface QuotaMonitorTabProps {
  engine: SecurityEngineService;
}

export const QuotaMonitorTab: React.FC<QuotaMonitorTabProps> = ({ engine }) => {
  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex items-center gap-3 mb-2">
          <Cpu className="h-5 w-5 text-red-400" />
          <h2 className="text-base font-semibold text-white tracking-tight">
            Gemma 4 31B Multi-Project Quota & API Rotation Layer
          </h2>
        </div>
        <p className="text-xs text-neutral-400 leading-relaxed max-w-3xl">
          Tracks sliding-window input tokens (rolling 60s window) and daily request limits per project credential.
          Selection routes to the project with the highest safe headroom. Quota errors (429) trigger bounded failover with exponential backoff cooldowns.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {engine.geminiProjects.map((p) => {
          const tpmPercent = Math.min(100, Math.round((p.rolling_tpm_used / p.input_tpm_limit) * 100));
          const dailyPercent = Math.min(100, Math.round((p.requests_today / p.daily_limit) * 100));

          return (
            <div
              key={p.project_id}
              className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-5 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-neutral-800/80 pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono">{p.project_id}</h3>
                  <span className="text-xs text-neutral-400 font-mono">model: {p.model}</span>
                </div>
                <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                  READY
                </span>
              </div>

              {/* Rolling Window TPM */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-neutral-400">Rolling Input TPM</span>
                  <span className="text-white tabular-nums">
                    {p.rolling_tpm_used} / {p.input_tpm_limit}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-neutral-950 rounded-full overflow-hidden border border-neutral-800">
                  <div
                    className={`h-full transition-all ${
                      tpmPercent > 80 ? 'bg-amber-400' : 'bg-red-500'
                    }`}
                    style={{ width: `${tpmPercent}%` }}
                  />
                </div>
                <span className="text-[11px] text-neutral-400 mt-1 block">
                  {16000 - p.rolling_tpm_used} tokens remaining this minute
                </span>
              </div>

              {/* Daily Request Count */}
              <div>
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-neutral-400">Daily Requests</span>
                  <span className="text-white tabular-nums">
                    {p.requests_today} / {p.daily_limit}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-neutral-950 rounded-full overflow-hidden border border-neutral-800">
                  <div
                    className="h-full bg-emerald-500 transition-all"
                    style={{ width: `${Math.max(2, dailyPercent)}%` }}
                  />
                </div>
              </div>

              <div className="border-t border-neutral-800/60 pt-3 flex items-center justify-between text-xs font-mono text-neutral-400">
                <span>Consecutive Errors:</span>
                <span className="text-neutral-200">{p.consecutive_errors}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Safety & Token Conservation Invariant Banner */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-4 text-xs font-mono text-neutral-400 space-y-1.5">
        <div className="font-semibold text-neutral-200">Token Efficiency Architecture Invariants:</div>
        <div>· High-volume HTTP parsing and hashing stays local and deterministic (0 tokens).</div>
        <div>· Raw 40KB+ HTML responses remain in SQLite storage; only compressed observations reach Gemma 4 31B.</div>
        <div>· In Low Budget mode, the agent automatically pivots to deterministic-heavy scanning rather than halting.</div>
      </div>
    </div>
  );
};
