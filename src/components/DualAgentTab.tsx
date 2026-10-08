import React, { useState, useEffect } from 'react';
import { Cpu, Bot, Play, CheckCircle2, Flag, BookOpen, ArrowRight, ShieldCheck, Layers } from 'lucide-react';

interface DualExchange {
  iteration: number;
  timestamp: number;
  leaderPlan: {
    priority: string;
    mission: string;
    recommendedFocus: string;
    recommendedTools: string[];
    taskQueue: string[];
    reasoning: string;
  };
  gemmaDecision: {
    action: string;
    tool: string;
    arguments: Record<string, any>;
    hypothesis: string;
    reasoning: string;
    confidence: number;
  };
  knowledgeAdvisory: string;
  observationSummary: string;
}

export const DualAgentTab: React.FC = () => {
  const [activeGoal, setActiveGoal] = useState('Authorized CTF Assessment & Vulnerability Discovery');
  const [iteration, setIteration] = useState(1);
  const [recoveredFlag, setRecoveredFlag] = useState<string | null>(null);
  const [exchanges, setExchanges] = useState<DualExchange[]>([]);
  const [isStepping, setIsStepping] = useState(false);

  const fetchDualStatus = async () => {
    try {
      const res = await fetch('/api/agent/dual-status');
      if (res.ok) {
        const data = await res.json();
        setActiveGoal(data.activeGoal);
        setIteration(data.iteration);
        setRecoveredFlag(data.recoveredFlag);
        setExchanges(data.exchanges || []);
      }
    } catch {}
  };

  useEffect(() => {
    fetchDualStatus();
    const interval = setInterval(fetchDualStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleStep = async () => {
    setIsStepping(true);
    try {
      const res = await fetch('/api/agent/dual-step', { method: 'POST' });
      if (res.ok) {
        await fetchDualStatus();
      }
    } catch {} finally {
      setIsStepping(false);
    }
  };

  const latestExchange = exchanges[0];

  return (
    <div className="space-y-6">
      {/* Top Banner: Dual-Agent Mission & CTF Goal */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-white font-semibold text-base mb-1">
              <Bot className="h-5 w-5 text-red-400" />
              <span>Dual-Agent Architecture: Flash-Lite Leader + Gemma 4 31B Researcher</span>
            </div>
            <p className="text-xs text-neutral-400 max-w-3xl leading-relaxed">
              <strong>Team Leader (Gemini 3.5 Flash-Lite)</strong> decomposes the mission and guides strategic planning. <strong>Security Researcher (Gemma 4 31B)</strong> performs deep vulnerability reasoning and tool execution through Agentic-Burp.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleStep}
              disabled={isStepping}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-mono font-bold text-white bg-red-600 hover:bg-red-500 rounded transition-colors disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>{isStepping ? 'Executing Dual Step...' : 'Advance Investigation Step'}</span>
            </button>
          </div>
        </div>

        {/* CTF Flag Recovery Banner */}
        {recoveredFlag ? (
          <div className="mt-4 p-3 rounded border border-emerald-800 bg-emerald-950/40 text-xs font-mono flex items-center justify-between">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <Flag className="h-4 w-4" />
              <span>CTF FLAG RECOVERED & VALIDATED:</span>
              <span className="text-white bg-emerald-900/80 px-2.5 py-0.5 rounded border border-emerald-700">
                {recoveredFlag}
              </span>
            </div>
            <span className="text-emerald-400">STATUS: OBJECTIVE VERIFIED</span>
          </div>
        ) : (
          <div className="mt-4 pt-3 border-t border-neutral-800 flex items-center justify-between text-xs font-mono text-neutral-400">
            <span>Assessment Objective: {activeGoal}</span>
            <span>Iteration: {iteration}</span>
          </div>
        )}
      </div>

      {/* Dual Roles Live Cards (Side-by-Side) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Card 1: Team Leader (Gemini 3.5 Flash-Lite) */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-sky-400 animate-pulse" />
              <h3 className="text-sm font-semibold text-white font-mono">
                Team Leader: Gemini 3.5 Flash-Lite
              </h3>
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-sky-950/80 text-sky-400 border border-sky-800">
              STRATEGY & PLANNING
            </span>
          </div>

          {latestExchange ? (
            <div className="space-y-3 font-mono text-xs">
              <div>
                <span className="text-neutral-400 block text-[11px] uppercase">Current Strategic Mission:</span>
                <p className="text-white font-sans font-medium text-xs mt-0.5">
                  {latestExchange.leaderPlan.mission}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div className="bg-neutral-950 p-2.5 rounded border border-neutral-800">
                  <span className="text-neutral-400 text-[11px] block">Recommended Focus</span>
                  <span className="text-sky-300 font-bold">{latestExchange.leaderPlan.recommendedFocus}</span>
                </div>
                <div className="bg-neutral-950 p-2.5 rounded border border-neutral-800">
                  <span className="text-neutral-400 text-[11px] block">Priority Level</span>
                  <span className="text-amber-400 font-bold uppercase">{latestExchange.leaderPlan.priority}</span>
                </div>
              </div>

              <div>
                <span className="text-neutral-400 block text-[11px] uppercase mb-1">Decomposed Task Queue:</span>
                <div className="space-y-1">
                  {latestExchange.leaderPlan.taskQueue.map((t, idx) => (
                    <div key={idx} className="flex items-center gap-1.5 text-neutral-300">
                      <ArrowRight className="h-3 w-3 text-sky-400" />
                      <span>{t}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="text-[11px] text-neutral-400 pt-2 border-t border-neutral-800/80 italic">
                {latestExchange.leaderPlan.reasoning}
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-xs font-mono text-neutral-400">
              Awaiting Team Leader planning cycle.
            </div>
          )}
        </div>

        {/* Card 2: Security Researcher (Gemma 4 31B) */}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-red-400 animate-pulse" />
              <h3 className="text-sm font-semibold text-white font-mono">
                Security Researcher: Gemma 4 31B
              </h3>
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800">
              RESEARCH & EXPLOITATION
            </span>
          </div>

          {latestExchange ? (
            <div className="space-y-3 font-mono text-xs">
              <div>
                <span className="text-neutral-400 block text-[11px] uppercase">Formulated Security Hypothesis:</span>
                <p className="text-amber-300 font-sans text-xs mt-0.5 leading-relaxed">
                  "{latestExchange.gemmaDecision.hypothesis}"
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div className="bg-neutral-950 p-2.5 rounded border border-neutral-800">
                  <span className="text-neutral-400 text-[11px] block">Selected Tool</span>
                  <span className="text-red-300 font-bold">{latestExchange.gemmaDecision.tool}</span>
                </div>
                <div className="bg-neutral-950 p-2.5 rounded border border-neutral-800">
                  <span className="text-neutral-400 text-[11px] block">Confidence Level</span>
                  <span className="text-emerald-400 font-bold">
                    {(latestExchange.gemmaDecision.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>

              <div>
                <span className="text-neutral-400 block text-[11px] uppercase mb-1">Tool Arguments:</span>
                <pre className="p-2.5 rounded bg-neutral-950 border border-neutral-800 text-[11px] text-neutral-300 overflow-x-auto">
                  {JSON.stringify(latestExchange.gemmaDecision.arguments, null, 2)}
                </pre>
              </div>

              <div className="text-[11px] text-neutral-400 pt-2 border-t border-neutral-800/80 italic">
                {latestExchange.gemmaDecision.reasoning}
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-xs font-mono text-neutral-400">
              Awaiting Gemma reasoning decision.
            </div>
          )}
        </div>
      </div>

      {/* Advisory Knowledge Snippet & Observation */}
      {latestExchange && (
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-2 font-mono text-xs">
          <div className="flex items-center gap-2 text-neutral-400">
            <BookOpen className="h-4 w-4 text-amber-400" />
            <span className="font-semibold text-neutral-200">Retrieved Advisory Knowledge Reference (Section 15):</span>
          </div>
          <p className="text-neutral-300 leading-relaxed font-sans bg-neutral-950 p-3 rounded border border-neutral-800">
            {latestExchange.knowledgeAdvisory}
          </p>
          <div className="text-neutral-400 text-[11px] pt-1">
            Execution Observation: {latestExchange.observationSummary}
          </div>
        </div>
      )}

      {/* Historical Exchange Feed */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 overflow-hidden">
        <div className="bg-neutral-950 px-4 py-2.5 border-b border-neutral-800 flex items-center justify-between">
          <span className="text-xs font-mono font-semibold text-white">
            Dual-Agent Audit Log ({exchanges.length} cycles)
          </span>
          <span className="text-xs font-mono text-neutral-400">
            Leader ↔ Researcher Protocol
          </span>
        </div>

        <div className="divide-y divide-neutral-800/60 max-h-72 overflow-y-auto">
          {exchanges.map((ex, idx) => (
            <div key={idx} className="p-3.5 hover:bg-neutral-800/20 text-xs font-mono space-y-1">
              <div className="flex items-center justify-between text-neutral-400">
                <span className="text-sky-400 font-bold">Cycle #{ex.iteration}</span>
                <span>{new Date(ex.timestamp).toLocaleTimeString()}</span>
              </div>
              <div className="text-neutral-200">
                <span className="text-neutral-400">Mission:</span> {ex.leaderPlan.mission}
              </div>
              <div className="text-neutral-300 font-sans">
                <span className="text-neutral-400 font-mono">Action:</span> {ex.gemmaDecision.reasoning}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
