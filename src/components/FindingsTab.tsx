import React, { useState } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { Finding, FindingSeverity } from '../types';
import { ShieldAlert, CheckCircle, ExternalLink, X, FileText } from 'lucide-react';

interface FindingsTabProps {
  engine: SecurityEngineService;
}

export const FindingsTab: React.FC<FindingsTabProps> = ({ engine }) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');

  const filtered = engine.findings.filter((f) => {
    if (severityFilter === 'ALL') return true;
    return f.severity === severityFilter;
  });

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-white font-semibold text-base mb-1">
              <ShieldAlert className="h-4 w-4 text-red-400" />
              <span>Verified Security Findings & Evidence Trail</span>
            </div>
            <p className="text-xs text-neutral-400">
              Findings cannot transition to VERIFIED without deterministic, reproducible request and response evidence artifacts.
            </p>
          </div>

          <div className="flex items-center gap-1 bg-neutral-900 p-1 rounded border border-neutral-800">
            {(['ALL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
                  severityFilter === sev
                    ? 'bg-neutral-800 text-white shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="rounded-lg border border-neutral-800 bg-neutral-900/30 p-12 text-center text-xs text-neutral-400">
            No findings matching current filters. Run assessment to execute active detector checks.
          </div>
        ) : (
          filtered.map((f) => {
            const isHigh = f.severity === 'HIGH' || f.severity === 'CRITICAL';
            return (
              <div
                key={f.id}
                onClick={() => setSelectedFinding(f)}
                className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 hover:border-neutral-700 transition-colors cursor-pointer group"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded font-mono ${
                        isHigh
                          ? 'bg-red-950/80 text-red-400 border border-red-800/60'
                          : 'bg-amber-950/80 text-amber-400 border border-amber-800/60'
                      }`}
                    >
                      {f.severity}
                    </span>
                    <h3 className="text-sm font-semibold text-white group-hover:text-red-400 transition-colors">
                      {f.title}
                    </h3>
                  </div>

                  <div className="flex items-center gap-2 text-xs font-mono text-neutral-400">
                    <span className="text-emerald-400 font-semibold">{f.status}</span>
                    <span>·</span>
                    <span>Confidence: {f.confidence}</span>
                  </div>
                </div>

                <div className="text-xs text-neutral-400 font-mono mb-2">
                  {f.method} {f.endpoint} {f.parameter ? `· param: ${f.parameter}` : ''}
                </div>

                <p className="text-xs text-neutral-300 leading-relaxed line-clamp-2">
                  {f.description}
                </p>

                <div className="mt-3 flex items-center justify-between text-xs text-neutral-400 font-mono border-t border-neutral-800/60 pt-2.5">
                  <div>Evidence Artifacts: {f.evidence_ids.join(', ')}</div>
                  <div className="text-neutral-400 group-hover:text-white flex items-center gap-1">
                    <span>Inspect Evidence</span>
                    <ExternalLink className="h-3 w-3" />
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl rounded-lg border border-neutral-800 bg-neutral-900 p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-mono font-bold text-red-400 block mb-1">
                  {selectedFinding.finding_type} · {selectedFinding.severity} · {selectedFinding.status}
                </span>
                <h2 className="text-base font-bold text-white tracking-tight">
                  {selectedFinding.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1 rounded text-neutral-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="rounded border border-neutral-800 bg-neutral-950 p-3 font-mono text-xs text-neutral-300">
              <div>Affected Endpoint: {selectedFinding.method} {selectedFinding.endpoint}</div>
              {selectedFinding.parameter && <div>Vulnerable Parameter: {selectedFinding.parameter}</div>}
              <div>Detector: {selectedFinding.detector}</div>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-neutral-200 uppercase tracking-wider mb-1">
                Technical Description
              </h4>
              <p className="text-xs text-neutral-300 leading-relaxed">
                {selectedFinding.description}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-neutral-200 uppercase tracking-wider mb-1">
                Security Impact
              </h4>
              <p className="text-xs text-neutral-300 leading-relaxed">
                {selectedFinding.impact}
              </p>
            </div>

            <div className="rounded border border-neutral-800 bg-neutral-950/80 p-3.5">
              <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-1">
                Remediation & Fix Guidance
              </h4>
              <p className="text-xs text-neutral-300 leading-relaxed font-sans">
                {selectedFinding.remediation}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-1">
                Evidence Artifact References
              </h4>
              <div className="space-y-2">
                {selectedFinding.evidence_ids.map((evId) => (
                  <div
                    key={evId}
                    className="p-2.5 rounded border border-neutral-800 bg-neutral-950 text-xs font-mono text-neutral-300"
                  >
                    <span className="text-red-400 font-bold">{evId}</span>
                    <span className="text-neutral-400 ml-2">Verified reproducible network proof</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
