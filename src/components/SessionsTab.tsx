import React, { useState } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { SessionProfile, AutoTokenRule } from '../types';
import { KeyRound, Users, ToggleLeft, ToggleRight, Check, RefreshCw, Shield, Edit3 } from 'lucide-react';

interface SessionsTabProps {
  engine: SecurityEngineService;
}

export const SessionsTab: React.FC<SessionsTabProps> = ({ engine }) => {
  const [editingSessionId, setEditingSessionId] = useState<string | null>(null);
  const [editToken, setEditToken] = useState('');
  const [editCookie, setEditCookie] = useState('');
  const [editCsrf, setEditCsrf] = useState('');

  const activeSession = engine.getActiveSession();

  const handleStartEdit = (session: SessionProfile) => {
    setEditingSessionId(session.id);
    setEditToken(session.token);
    setEditCookie(session.cookie);
    setEditCsrf(session.csrfToken || '');
  };

  const handleSaveEdit = (sessionId: string) => {
    engine.updateSessionProfile(sessionId, {
      token: editToken,
      cookie: editCookie,
      csrfToken: editCsrf,
    });
    setEditingSessionId(null);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-white font-semibold text-base mb-1">
              <KeyRound className="h-4 w-4 text-red-400" />
              <span>Automated Session & Token Handling Engine</span>
            </div>
            <p className="text-xs text-neutral-400 max-w-3xl leading-relaxed">
              Dynamically injects, rotates, and swaps Authorization tokens, cookies, and CSRF nonces based on test situation. Enables automated multi-identity BOLA/IDOR detection by testing requests as User A, User B, or Unauthenticated.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-neutral-400">
              Active Identity:
            </span>
            <span className="text-xs font-mono font-bold text-red-400 bg-red-950/80 px-2.5 py-1 rounded border border-red-800/60">
              {activeSession.name}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Multi-Identity Profiles (2 cols wide on desktop) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
              <Users className="h-4 w-4 text-neutral-400" />
              <span>Multi-Identity Session Profiles</span>
            </h3>
            <span className="text-xs text-neutral-400 font-mono">
              {engine.sessionProfiles.length} Profiles Configured
            </span>
          </div>

          <div className="space-y-3">
            {engine.sessionProfiles.map((s) => {
              const isActive = s.id === engine.activeSessionId;
              const isEditing = editingSessionId === s.id;

              return (
                <div
                  key={s.id}
                  className={`rounded-lg border transition-colors p-4 ${
                    isActive
                      ? 'border-red-900/80 bg-red-950/20'
                      : 'border-neutral-800 bg-neutral-900/40'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-white">{s.name}</span>
                      <span
                        className={`text-[11px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${
                          s.role === 'primary'
                            ? 'bg-sky-950/80 text-sky-400 border border-sky-800/60'
                            : s.role === 'secondary'
                            ? 'bg-amber-950/80 text-amber-400 border border-amber-800/60'
                            : 'bg-neutral-800 text-neutral-400'
                        }`}
                      >
                        {s.role}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      {!isActive && (
                        <button
                          onClick={() => engine.setActiveSession(s.id)}
                          className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-200 border border-neutral-700 transition-colors"
                        >
                          Set as Active
                        </button>
                      )}
                      {isActive && (
                        <span className="text-xs font-mono font-semibold text-emerald-400 flex items-center gap-1">
                          <Check className="h-3 w-3" />
                          <span>ACTIVE TESTING</span>
                        </span>
                      )}
                      <button
                        onClick={() => (isEditing ? handleSaveEdit(s.id) : handleStartEdit(s))}
                        className="p-1 rounded text-neutral-400 hover:text-white"
                        title={isEditing ? 'Save changes' : 'Edit tokens'}
                      >
                        {isEditing ? (
                          <span className="text-xs text-emerald-400 font-mono font-bold">Save</span>
                        ) : (
                          <Edit3 className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Credentials / Token Display or Edit */}
                  {isEditing ? (
                    <div className="space-y-2.5 pt-2 border-t border-neutral-800/80">
                      <div>
                        <label className="text-[11px] text-neutral-400 font-mono uppercase block mb-1">
                          Authorization Header / Token
                        </label>
                        <input
                          type="text"
                          value={editToken}
                          onChange={(e) => setEditToken(e.target.value)}
                          placeholder="Bearer eyJhbGciOi..."
                          className="w-full bg-neutral-950 border border-neutral-800 rounded px-2.5 py-1 text-xs font-mono text-white focus:outline-none focus:border-red-500"
                        />
                      </div>
                      <div>
                        <label className="text-[11px] text-neutral-400 font-mono uppercase block mb-1">
                          Session Cookie
                        </label>
                        <input
                          type="text"
                          value={editCookie}
                          onChange={(e) => setEditCookie(e.target.value)}
                          placeholder="session_id=sess_token_..."
                          className="w-full bg-neutral-950 border border-neutral-800 rounded px-2.5 py-1 text-xs font-mono text-white focus:outline-none focus:border-red-500"
                        />
                      </div>
                      <div>
                        <label className="text-[11px] text-neutral-400 font-mono uppercase block mb-1">
                          CSRF / Nonce Token
                        </label>
                        <input
                          type="text"
                          value={editCsrf}
                          onChange={(e) => setEditCsrf(e.target.value)}
                          placeholder="csrf_token_..."
                          className="w-full bg-neutral-950 border border-neutral-800 rounded px-2.5 py-1 text-xs font-mono text-white focus:outline-none focus:border-red-500"
                        />
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-1.5 font-mono text-xs text-neutral-300 bg-neutral-950 p-2.5 rounded border border-neutral-800/80">
                      <div className="flex items-center justify-between text-neutral-400">
                        <span>Header: {s.tokenHeaderName}</span>
                        <span className="text-[11px] text-neutral-400">Auto-Injected</span>
                      </div>
                      <div className="truncate text-neutral-200">
                        {s.token ? s.token : <span className="text-neutral-400 italic">&lt;No token - Anonymous&gt;</span>}
                      </div>
                      {s.cookie && (
                        <div className="truncate text-neutral-400 text-[11px] pt-1 border-t border-neutral-900">
                          Cookie: {s.cookie}
                        </div>
                      )}
                      {s.csrfToken && (
                        <div className="truncate text-neutral-400 text-[11px]">
                          CSRF: {s.csrfToken}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Auto-Token & Situation Rules */}
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <RefreshCw className="h-4 w-4 text-neutral-400" />
            <span>Automatic Session Rules</span>
          </h3>

          <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-4">
            <p className="text-xs text-neutral-400 leading-relaxed">
              Rules execute deterministically on outbound requests and incoming responses based on situation:
            </p>

            <div className="space-y-3">
              {engine.autoTokenRules.map((rule) => (
                <div
                  key={rule.id}
                  className="rounded border border-neutral-800 bg-neutral-950 p-3 flex items-center justify-between gap-3"
                >
                  <div>
                    <div className="text-xs font-semibold text-white">
                      {rule.name}
                    </div>
                    <div className="text-[11px] font-mono text-neutral-400 mt-0.5">
                      Target: {rule.headerName}
                    </div>
                  </div>

                  <button
                    onClick={() => engine.toggleAutoTokenRule(rule.id)}
                    className="p-1 text-neutral-400 hover:text-white transition-colors"
                  >
                    {rule.enabled ? (
                      <ToggleRight className="h-6 w-6 text-emerald-400" />
                    ) : (
                      <ToggleLeft className="h-6 w-6 text-neutral-400" />
                    )}
                  </button>
                </div>
              ))}
            </div>

            {/* Live Header Injection Simulation */}
            <div className="border-t border-neutral-800 pt-3">
              <span className="text-xs font-semibold text-neutral-300 block mb-1.5 font-mono">
                Current Outbound Header Injector:
              </span>
              <pre className="p-2.5 rounded bg-neutral-950 border border-neutral-800 text-[11px] font-mono text-neutral-300 overflow-x-auto">
{`Host: 127.0.0.1:8080
User-Agent: Agentic-Burp/1.0
Authorization: ${activeSession.token ? activeSession.token.slice(0, 32) + '...' : '<NONE>'}
Cookie: ${activeSession.cookie ? activeSession.cookie.slice(0, 24) + '...' : '<NONE>'}`}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
