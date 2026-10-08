import React from 'react';
import { Play, Pause, Square, FileDown, Shield } from 'lucide-react';
import { SecurityEngineService } from '../services/securityEngine';

interface HeaderProps {
  engine: SecurityEngineService;
  activeTab: string;
  onTabChange: (tab: string) => void;
  onExportReport: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  engine,
  activeTab,
  onTabChange,
  onExportReport,
}) => {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'scope', label: 'Scope Gate' },
    { id: 'crawler', label: 'Crawler' },
    { id: 'repeater', label: 'Repeater' },
    { id: 'fuzzer', label: 'Fuzzer' },
    { id: 'sessions', label: 'Sessions & Tokens' },
    { id: 'findings', label: `Findings (${engine.findings.length})` },
    { id: 'quota', label: 'Quota & Projects' },
    { id: 'lab', label: 'Lab Target' },
  ];

  return (
    <header className="border-b border-neutral-800 bg-neutral-950 px-6 py-3.5">
      <div className="flex items-center justify-between">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-red-950/60 border border-red-800/60 text-red-400">
            <Shield className="h-4 w-4" />
          </div>
          <div>
            <span className="font-bold tracking-tight text-white text-base">
              Agentic-Burp
            </span>
            <span className="ml-2 text-xs text-neutral-400 font-mono">
              gemma-4-31b
            </span>
          </div>
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="hidden lg:flex items-center gap-1 bg-neutral-900/80 p-1 rounded-lg border border-neutral-800">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-neutral-800 text-white shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Assessment Actions */}
        <div className="flex items-center gap-2">
          {!engine.isRunning ? (
            <button
              onClick={() => engine.startAssessment()}
              className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-red-600 rounded hover:bg-red-500 transition-colors whitespace-nowrap"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>Start Assessment</span>
            </button>
          ) : (
            <div className="flex items-center gap-1.5">
              {engine.isPaused ? (
                <button
                  onClick={() => engine.resumeAssessment()}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-emerald-600 rounded hover:bg-emerald-500 transition-colors whitespace-nowrap"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>Resume</span>
                </button>
              ) : (
                <button
                  onClick={() => engine.pauseAssessment()}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-neutral-200 bg-neutral-800 border border-neutral-700 rounded hover:bg-neutral-700 transition-colors whitespace-nowrap"
                >
                  <Pause className="h-3.5 w-3.5" />
                  <span>Pause</span>
                </button>
              )}
              <button
                onClick={() => engine.stopAssessment()}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-red-400 bg-neutral-900 border border-red-900/60 rounded hover:bg-neutral-800 transition-colors"
                title="Stop assessment"
              >
                <Square className="h-3.5 w-3.5" />
              </button>
            </div>
          )}

          <button
            onClick={onExportReport}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-neutral-300 bg-neutral-900 border border-neutral-800 rounded hover:bg-neutral-800 transition-colors whitespace-nowrap"
          >
            <FileDown className="h-3.5 w-3.5" />
            <span>Report</span>
          </button>
        </div>
      </div>
    </header>
  );
};
