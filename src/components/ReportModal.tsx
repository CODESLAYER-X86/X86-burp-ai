import React, { useState } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { X, Copy, Check, Download, FileText, Code } from 'lucide-react';

interface ReportModalProps {
  engine: SecurityEngineService;
  onClose: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({ engine, onClose }) => {
  const [format, setFormat] = useState<'markdown' | 'json' | 'html'>('markdown');
  const [copied, setCopied] = useState(false);

  const generateReportContent = () => {
    if (format === 'json') {
      return JSON.stringify(
        {
          assessment: {
            target: engine.targetUrl,
            phase: engine.phase,
            iteration: engine.iteration,
            model: 'gemma-4-31b',
            timestamp: new Date().toISOString(),
          },
          scope: engine.scopePolicy,
          statistics: {
            total_findings: engine.findings.length,
            verified_findings: engine.findings.filter(f => f.status === 'VERIFIED').length,
            requests_executed: engine.requestsExecuted,
          },
          findings: engine.findings,
          evidence: engine.evidenceList,
        },
        null,
        2
      );
    } else if (format === 'markdown') {
      const verified = engine.findings.filter(f => f.status === 'VERIFIED');
      let md = `# Security Assessment Report — ${engine.targetUrl}\n\n`;
      md += `**Reasoning Engine**: Gemma 4 31B\n`;
      md += `**Date**: ${new Date().toLocaleDateString()}\n`;
      md += `**Verified Vulnerabilities**: ${verified.length} of ${engine.findings.length} findings\n\n`;
      md += `## Executive Summary\nThis authorized security assessment evaluated the target application under strict deterministic scope boundaries.\n\n`;
      md += `## Detailed Findings\n\n`;

      if (engine.findings.length === 0) {
        md += `No security vulnerabilities were identified.\n`;
      } else {
        engine.findings.forEach((f, idx) => {
          md += `### ${idx + 1}. ${f.title}\n`;
          md += `- **Severity**: ${f.severity} | **Confidence**: ${f.confidence} | **Status**: ${f.status}\n`;
          md += `- **Endpoint**: \`${f.method} ${f.endpoint}\` (param: \`${f.parameter || 'N/A'}\`)\n\n`;
          md += `**Description**:\n${f.description}\n\n`;
          md += `**Impact**:\n${f.impact}\n\n`;
          md += `**Remediation**:\n${f.remediation}\n\n`;
          md += `**Evidence Artifacts**: ${f.evidence_ids.join(', ')}\n\n---\n\n`;
        });
      }
      return md;
    } else {
      return `<!DOCTYPE html><html><head><title>Assessment Report</title></head><body style="font-family:sans-serif;padding:30px;background:#0f172a;color:#f8fafc;"><h1>Agentic-Burp Assessment Report</h1><p>Target: ${engine.targetUrl}</p><hr/><h2>Verified Findings (${engine.findings.length})</h2>${engine.findings.map(f => `<div style="background:#1e293b;padding:15px;margin:10px 0;border-radius:6px;"><h3>${f.title} (${f.severity})</h3><p>${f.description}</p><p><strong>Remediation:</strong> ${f.remediation}</p></div>`).join('')}</body></html>`;
    }
  };

  const reportText = generateReportContent();

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const ext = format === 'json' ? 'json' : (format === 'html' ? 'html' : 'md');
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agentic-burp-report.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-3xl rounded-lg border border-neutral-800 bg-neutral-900 p-6 shadow-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
          <div>
            <h2 className="text-base font-bold text-white tracking-tight">
              Export Security Assessment Report
            </h2>
            <span className="text-xs text-neutral-400 font-mono">
              Deterministic records from SQLite evidence store
            </span>
          </div>

          <button onClick={onClose} className="p-1 rounded text-neutral-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Format Selector */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1 bg-neutral-950 p-1 rounded border border-neutral-800">
            {(['markdown', 'json', 'html'] as const).map((fmt) => (
              <button
                key={fmt}
                onClick={() => setFormat(fmt)}
                className={`px-3 py-1 text-xs font-medium rounded uppercase font-mono transition-colors ${
                  format === fmt
                    ? 'bg-neutral-800 text-white shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                {fmt}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-neutral-200 bg-neutral-800 hover:bg-neutral-700 rounded border border-neutral-700 transition-colors"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Download</span>
            </button>
          </div>
        </div>

        {/* Code Preview */}
        <div className="rounded border border-neutral-800 bg-neutral-950 p-4 max-h-96 overflow-y-auto">
          <pre className="text-xs font-mono text-neutral-300 whitespace-pre-wrap leading-relaxed">
            {reportText}
          </pre>
        </div>
      </div>
    </div>
  );
};
