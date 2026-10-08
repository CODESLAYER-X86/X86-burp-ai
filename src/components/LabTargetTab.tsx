import React from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { Beaker, Bug, Play, ExternalLink } from 'lucide-react';

interface LabTargetTabProps {
  engine: SecurityEngineService;
}

export const LabTargetTab: React.FC<LabTargetTabProps> = ({ engine }) => {
  const labEndpoints = [
    {
      path: '/api/profile?id=101',
      method: 'GET',
      type: 'IDOR / BOLA',
      vulnDesc: 'Returns Alice profile object without verifying session tenant ownership. User B can view object 101 directly.',
      param: 'id',
    },
    {
      path: '/api/products?cat=items',
      method: 'GET',
      type: 'SQL Injection',
      vulnDesc: 'Concatenates cat parameter directly into SQLite query. Single quote triggers operational syntax error.',
      param: 'cat',
    },
    {
      path: '/search?q=test',
      method: 'GET',
      type: 'Reflected XSS',
      vulnDesc: 'Reflects search query parameter directly into HTML body without entity encoding.',
      param: 'q',
    },
    {
      path: '/account/email',
      method: 'POST',
      type: 'CSRF',
      vulnDesc: 'State-changing email update accepts cookie authentication without anti-CSRF token or Origin validation.',
      param: 'new_email',
    },
    {
      path: '/api/user_data',
      method: 'GET',
      type: 'Insecure CORS',
      vulnDesc: 'Reflects arbitrary Origin header in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.',
      param: 'N/A',
    },
    {
      path: '/fetch?url=http://callback.test',
      method: 'GET',
      type: 'SSRF',
      vulnDesc: 'Server-side URL fetcher fetches arbitrary targets and returns callback correlation token.',
      param: 'url',
    },
  ];

  const handleTestEndpoint = (path: string, method: string) => {
    engine.replayRequest(method, `http://127.0.0.1:8080${path}`, { 'User-Agent': 'Agentic-Burp' });
    engine.logEvent('lab_endpoint_tested', 'INVESTIGATION', `Simulated audit request on lab endpoint: ${method} ${path}`);
  };

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex items-center gap-3 mb-2">
          <Beaker className="h-5 w-5 text-red-400" />
          <h2 className="text-base font-semibold text-white tracking-tight">
            Authorized Local Lab Environment (Built-In Fixture)
          </h2>
        </div>
        <p className="text-xs text-neutral-400 leading-relaxed max-w-3xl">
          This local security lab fixture (running in-scope at <code>http://127.0.0.1:8080</code>) provides intentionally vulnerable target endpoints for CTF practice, detector verification, and benchmark auditing.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {labEndpoints.map((ep, idx) => (
          <div
            key={idx}
            className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4 space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-red-400">
                {ep.type}
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-neutral-950 border border-neutral-800 text-neutral-300">
                {ep.method}
              </span>
            </div>

            <div>
              <div className="text-xs font-mono font-medium text-white break-all">
                {ep.path}
              </div>
              <p className="text-xs text-neutral-400 mt-1 leading-relaxed">
                {ep.vulnDesc}
              </p>
            </div>

            <div className="border-t border-neutral-800/60 pt-3 flex items-center justify-between">
              <span className="text-xs font-mono text-neutral-400">
                Param: {ep.param}
              </span>
              <button
                onClick={() => handleTestEndpoint(ep.path, ep.method)}
                className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-white bg-neutral-800 hover:bg-neutral-700 rounded border border-neutral-700 transition-colors"
              >
                <Play className="h-3 w-3 fill-current" />
                <span>Probe Endpoint</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
