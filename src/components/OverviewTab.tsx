import React from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { AssessmentPhase } from '../types';
import { CheckCircle2, AlertTriangle, ArrowRight, ShieldCheck, Terminal } from 'lucide-react';

interface OverviewTabProps {
  engine: SecurityEngineService;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ engine }) => {
  const phases: AssessmentPhase[] = [
    'DISCOVERY',
    'ANALYSIS',
    'INVESTIGATION',
    'VERIFICATION',
    'REPORTING',
    'COMPLETE',
  ];

  const currentPhaseIndex = phases.indexOf(engine.phase);
  const verifiedCount = engine.findings.filter(f => f.status === 'VERIFIED').length;
  const highSevCount = engine.findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length;

  return (
    <div className="space-y-6">
      {/* Target & Phase Header Card */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-neutral-800/80 pb-4 mb-4">
          <div>
            <div className="text-xs text-neutral-400 font-mono">
              Target Scope · Authorized Security Assessment
            </div>
            <h1 className="text-lg font-semibold text-white tracking-tight mt-0.5 font-mono">
              {engine.targetUrl}
            </h1>
          </div>
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <span>Mode: Assessment</span>
            <span>·</span>
            <span>Iteration: {engine.iteration} / {engine.maxIterations}</span>
            <span>·</span>
            <span className={`font-medium ${engine.isRunning ? 'text-emerald-400' : 'text-neutral-400'}`}>
              {engine.isRunning ? (engine.isPaused ? 'Paused' : 'Active Execution') : 'Idle'}
            </span>
          </div>
        </div>

        {/* Phase Stepper */}
        <div>
          <div className="text-xs text-neutral-400 mb-2 font-medium">Assessment Lifecycle Phase</div>
          <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
            {phases.map((p, idx) => {
              const isPast = idx < currentPhaseIndex;
              const isCurrent = idx === currentPhaseIndex;
              return (
                <div
                  key={p}
                  className={`px-3 py-2 rounded border text-xs font-mono transition-colors ${
                    isCurrent
                      ? 'border-red-500/80 bg-red-950/40 text-red-300 font-semibold shadow-sm'
                      : isPast
                      ? 'border-neutral-700 bg-neutral-800/60 text-neutral-300'
                      : 'border-neutral-800/60 bg-neutral-900/40 text-neutral-400'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span>{idx + 1}. {p}</span>
                    {isPast && <CheckCircle2 className="h-3 w-3 text-emerald-400" />}
                    {isCurrent && <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Metrics Row with tabular figures */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-4">
          <div className="text-xs text-neutral-400 uppercase tracking-wider">Outbound Requests</div>
          <div className="text-2xl font-bold font-mono text-white mt-1 tabular-nums">
            {engine.requestsExecuted}
            <span className="text-xs font-normal text-neutral-400 ml-1.5">/ {engine.maxRequests}</span>
          </div>
          <div className="text-xs text-neutral-400 mt-1">Rate limited at 60 req/min</div>
        </div>

        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-4">
          <div className="text-xs text-neutral-400 uppercase tracking-wider">Observations</div>
          <div className="text-2xl font-bold font-mono text-white mt-1 tabular-nums">
            {engine.observations.length}
          </div>
          <div className="text-xs text-neutral-400 mt-1">Compressed signals for LLM</div>
        </div>

        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-4">
          <div className="text-xs text-neutral-400 uppercase tracking-wider">Verified Findings</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1 tabular-nums">
            {verifiedCount}
          </div>
          <div className="text-xs text-neutral-400 mt-1">Backed by reproducible evidence</div>
        </div>

        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-4">
          <div className="text-xs text-neutral-400 uppercase tracking-wider">High / Critical</div>
          <div className="text-2xl font-bold font-mono text-red-400 mt-1 tabular-nums">
            {highSevCount}
          </div>
          <div className="text-xs text-neutral-400 mt-1">Actionable vulnerabilities</div>
        </div>
      </div>

      {/* Two-Column: Findings Preview & Activity Log */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Identified Vulnerabilities */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Identified Security Findings ({engine.findings.length})
            </h2>
            <span className="text-xs text-neutral-400">Strict evidence gate enforced</span>
          </div>

          {engine.findings.length === 0 ? (
            <div className="rounded border border-neutral-800/80 bg-neutral-950/40 p-8 text-center text-xs text-neutral-400">
              No vulnerabilities identified yet. Start the assessment to run discovery and security detectors.
            </div>
          ) : (
            <div className="space-y-3">
              {engine.findings.map((f) => (
                <div
                  key={f.id}
                  className="rounded border border-neutral-800 bg-neutral-950/60 p-3.5 hover:border-neutral-700 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="font-medium text-xs text-white truncate">{f.title}</span>
                    <span
                      className={`text-xs font-semibold px-2 py-0.5 rounded ${
                        f.severity === 'HIGH' || f.severity === 'CRITICAL'
                          ? 'bg-red-950/80 text-red-400 border border-red-800/50'
                          : 'bg-amber-950/80 text-amber-400 border border-amber-800/50'
                      }`}
                    >
                      {f.severity} · {f.status}
                    </span>
                  </div>
                  <div className="text-xs text-neutral-400 font-mono mb-1">
                    {f.method} {f.endpoint} {f.parameter ? `· param: ${f.parameter}` : ''}
                  </div>
                  <p className="text-xs text-neutral-400 line-clamp-2 leading-relaxed">
                    {f.description}
                  </p>
                  <div className="mt-2 text-xs text-neutral-400 font-mono">
                    Evidence: {f.evidence_ids.join(', ')}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Real-time Agent Decision & Activity Stream */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-neutral-400" />
              <h2 className="text-sm font-semibold text-white tracking-tight">
                Gemma 4 31B Activity Log
              </h2>
            </div>
            <span className="text-xs font-mono text-neutral-400">Structured decisions</span>
          </div>

          <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
            {engine.activityLogs.map((log) => (
              <div
                key={log.id}
                className="rounded border border-neutral-800/60 bg-neutral-950/40 p-2.5 text-xs font-mono"
              >
                <div className="flex items-center justify-between text-neutral-400 mb-1">
                  <span>[{log.phase}]</span>
                  <span className="tabular-nums">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div className="text-neutral-200 font-sans leading-relaxed">
                  {log.summary}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
