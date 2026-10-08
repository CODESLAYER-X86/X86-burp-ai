import {
  Finding,
  EvidenceItem,
  Observation,
  DiscoveredEndpoint,
  HTTPTransaction,
  ScopePolicy,
  GeminiProjectQuota,
  AgentActivityEvent,
  AssessmentPhase,
  SessionProfile,
  AutoTokenRule
} from '../types';

export class SecurityEngineService {
  private static instance: SecurityEngineService;

  public phase: AssessmentPhase = 'DISCOVERY';
  public isRunning: boolean = false;
  public isPaused: boolean = false;
  public targetUrl: string = 'http://127.0.0.1:8080';
  public iteration: number = 0;
  public maxIterations: number = 15;
  public requestsExecuted: number = 0;
  public maxRequests: number = 200;

  public scopePolicy: ScopePolicy = {
    targets: ['http://127.0.0.1:8080', 'https://authorized-lab.example'],
    allowed_methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
    allowed_ports: [80, 443, 8080, 8443, 3000],
    allow_subdomains: false,
    allow_external_hosts: false,
    allow_internal_loopback: true,
    max_requests_per_minute: 60,
  };

  public geminiProjects: GeminiProjectQuota[] = [
    {
      project_id: 'sec-ops-prod',
      model: 'gemma-4-31b',
      enabled: true,
      requests_today: 142,
      daily_limit: 14000,
      input_tpm_limit: 16000,
      rolling_tpm_used: 3200,
      cooldown_until: 0,
      consecutive_errors: 0,
    },
    {
      project_id: 'sec-ops-overflow',
      model: 'gemma-4-31b',
      enabled: true,
      requests_today: 45,
      daily_limit: 14000,
      input_tpm_limit: 16000,
      rolling_tpm_used: 850,
      cooldown_until: 0,
      consecutive_errors: 0,
    },
    {
      project_id: 'sec-ops-nightly',
      model: 'gemma-4-31b',
      enabled: true,
      requests_today: 12,
      daily_limit: 14000,
      input_tpm_limit: 16000,
      rolling_tpm_used: 120,
      cooldown_until: 0,
      consecutive_errors: 0,
    },
  ];

  public sessionProfiles: SessionProfile[] = [
    {
      id: 'user_a',
      name: 'User A (Alice / Tenant Owner)',
      role: 'primary',
      token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMDEiLCJuYW1lIjoiQWxpY2UifQ.alice_sig',
      tokenHeaderName: 'Authorization',
      cookie: 'session_id=sess_alice_auth_token_9912',
      csrfToken: 'csrf_token_alice_849204',
      autoRefreshCsrf: true,
      customHeaders: { 'X-Tenant-ID': 'tenant_alice_101' },
    },
    {
      id: 'user_b',
      name: 'User B (Bob / Cross-Tenant Attacker)',
      role: 'secondary',
      token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMDIiLCJuYW1lIjoiQm9iIn0.bob_sig',
      tokenHeaderName: 'Authorization',
      cookie: 'session_id=sess_bob_auth_token_4411',
      csrfToken: 'csrf_token_bob_194820',
      autoRefreshCsrf: true,
      customHeaders: { 'X-Tenant-ID': 'tenant_bob_102' },
    },
    {
      id: 'unauth',
      name: 'Unauthenticated (Anonymous Visitor)',
      role: 'unauthenticated',
      token: '',
      tokenHeaderName: 'Authorization',
      cookie: '',
      csrfToken: '',
      autoRefreshCsrf: false,
      customHeaders: {},
    },
  ];

  public activeSessionId: string = 'user_a';

  public autoTokenRules: AutoTokenRule[] = [
    {
      id: 'rule_bearer',
      name: 'Auto-Inject Authorization Bearer Token',
      enabled: true,
      ruleType: 'auto_inject_bearer',
      headerName: 'Authorization',
    },
    {
      id: 'rule_csrf',
      name: 'Auto-Extract & Refresh CSRF Token',
      enabled: true,
      ruleType: 'auto_extract_csrf',
      headerName: 'X-CSRF-Token',
    },
    {
      id: 'rule_cookie',
      name: 'Auto-Sync Session Cookie Jar',
      enabled: true,
      ruleType: 'match_and_replace',
      headerName: 'Cookie',
    },
  ];

  public findings: Finding[] = [];
  public evidenceList: EvidenceItem[] = [];
  public observations: Observation[] = [];
  public endpoints: DiscoveredEndpoint[] = [];
  public trafficHistory: HTTPTransaction[] = [];
  public activityLogs: AgentActivityEvent[] = [];

  private listeners: (() => void)[] = [];
  private stepInterval: any = null;

  public static getInstance(): SecurityEngineService {
    if (!SecurityEngineService.instance) {
      SecurityEngineService.instance = new SecurityEngineService();
      SecurityEngineService.instance.initializeDefaults();
    }
    return SecurityEngineService.instance;
  }

  public subscribe(fn: () => void): () => void {
    this.listeners.push(fn);
    return () => {
      this.listeners = this.listeners.filter(l => l !== fn);
    };
  }

  private notify() {
    this.listeners.forEach(fn => fn());
  }

  private initializeDefaults() {
    this.endpoints = [];
    this.logEvent('engine_initialized', 'IDLE', 'Agentic-Burp initialized. Ready for authorized target assessment.');
  }

  public validateScope(url: string, method: string = 'GET'): { allowed: boolean; reason: string } {
    if (!this.scopePolicy.allowed_methods.includes(method.toUpperCase())) {
      return { allowed: false, reason: `Method '${method}' not in allowed methods.` };
    }

    try {
      const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
      const port = parsed.port ? parseInt(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);

      if (parsed.hostname === '169.254.169.254' || parsed.hostname === 'metadata.google.internal') {
        return { allowed: false, reason: 'Cloud instance metadata blocked by SSRF policy.' };
      }

      if (!this.scopePolicy.allowed_ports.includes(port)) {
        return { allowed: false, reason: `Port ${port} not in allowed ports.` };
      }

      const isTarget = this.scopePolicy.targets.some(t => {
        try {
          const tParsed = new URL(t);
          return tParsed.hostname === parsed.hostname;
        } catch {
          return false;
        }
      });

      if (!isTarget && !this.scopePolicy.allow_external_hosts) {
        return { allowed: false, reason: `Host '${parsed.hostname}' is outside configured scope targets.` };
      }

      return { allowed: true, reason: 'Authorized in-scope target' };
    } catch (e: any) {
      return { allowed: false, reason: `Malformed URL: ${e.message}` };
    }
  }

  public addTarget(target: string) {
    if (target && !this.scopePolicy.targets.includes(target)) {
      this.scopePolicy.targets.push(target);
      this.logEvent('scope_updated', this.phase, `Added target to authorized scope: ${target}`);
      this.notify();
    }
  }

  public removeTarget(target: string) {
    this.scopePolicy.targets = this.scopePolicy.targets.filter(t => t !== target);
    if (this.targetUrl === target && this.scopePolicy.targets.length > 0) {
      this.targetUrl = this.scopePolicy.targets[0];
    }
    this.logEvent('scope_updated', this.phase, `Removed target from scope: ${target}`);
    this.notify();
  }

  public setPrimaryTarget(target: string) {
    if (this.scopePolicy.targets.includes(target)) {
      this.targetUrl = target;
      this.logEvent('primary_target_changed', this.phase, `Active target set to: ${target}`);
      this.notify();
    }
  }

  public getActiveSession(): SessionProfile {
    return this.sessionProfiles.find(s => s.id === this.activeSessionId) || this.sessionProfiles[0];
  }

  public setActiveSession(sessionId: string) {
    if (this.sessionProfiles.some(s => s.id === sessionId)) {
      this.activeSessionId = sessionId;
      const s = this.getActiveSession();
      this.logEvent('session_switched', this.phase, `Switched active testing identity to: ${s.name}`);
      this.notify();
    }
  }

  public updateSessionProfile(sessionId: string, updates: Partial<SessionProfile>) {
    const idx = this.sessionProfiles.findIndex(s => s.id === sessionId);
    if (idx !== -1) {
      this.sessionProfiles[idx] = { ...this.sessionProfiles[idx], ...updates };
      this.logEvent('session_profile_updated', this.phase, `Updated credentials for: ${this.sessionProfiles[idx].name}`);
      this.notify();
    }
  }

  public toggleAutoTokenRule(ruleId: string) {
    const rule = this.autoTokenRules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = !rule.enabled;
      this.notify();
    }
  }

  public applySessionRules(headers: Record<string, string>, sessionId?: string): Record<string, string> {
    const targetSession = sessionId
      ? (this.sessionProfiles.find(s => s.id === sessionId) || this.getActiveSession())
      : this.getActiveSession();

    const outputHeaders = { ...headers };

    for (const rule of this.autoTokenRules) {
      if (!rule.enabled) continue;

      if (rule.ruleType === 'auto_inject_bearer') {
        if (targetSession.token) {
          outputHeaders[targetSession.tokenHeaderName || 'Authorization'] = targetSession.token;
        } else if (targetSession.role === 'unauthenticated') {
          delete outputHeaders['Authorization'];
        }
      } else if (rule.ruleType === 'auto_extract_csrf') {
        if (targetSession.csrfToken) {
          outputHeaders['X-CSRF-Token'] = targetSession.csrfToken;
        }
      } else if (rule.ruleType === 'match_and_replace') {
        if (targetSession.cookie) {
          outputHeaders['Cookie'] = targetSession.cookie;
        } else if (targetSession.role === 'unauthenticated') {
          delete outputHeaders['Cookie'];
        }
      }
    }

    // Merge custom headers
    if (targetSession.customHeaders) {
      Object.assign(outputHeaders, targetSession.customHeaders);
    }

    return outputHeaders;
  }

  public logEvent(event_type: string, phase: string, summary: string, details?: Record<string, any>) {
    this.activityLogs.unshift({
      id: `evt_${Date.now()}_${Math.random().toString(36).substring(7)}`,
      timestamp: Date.now(),
      event_type,
      phase,
      iteration: this.iteration,
      summary,
      details,
    });
    if (this.activityLogs.length > 100) {
      this.activityLogs.pop();
    }
    this.notify();
  }

  private pollInterval: any = null;

  public async startAssessment() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.isPaused = false;
    this.iteration = 0;
    this.phase = 'DISCOVERY';
    this.findings = [];
    this.evidenceList = [];
    this.observations = [];

    this.logEvent('assessment_started', 'DISCOVERY', `Initiating live assessment against target: ${this.targetUrl}`);
    this.notify();

    try {
      // 1. Trigger live scan pipeline on Express backend
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: this.targetUrl }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        this.logEvent('assessment_error', 'ERROR', `Failed to start scan: ${errData.error || res.statusText}`);
        this.isRunning = false;
        this.notify();
        return;
      }

      // 2. Poll backend for real progress and live findings
      if (this.pollInterval) clearInterval(this.pollInterval);
      this.pollInterval = setInterval(async () => {
        try {
          const statusRes = await fetch('/api/scan/status');
          if (statusRes.ok) {
            const data = await statusRes.json();
            this.phase = data.phase || this.phase;
            this.iteration = data.iteration || this.iteration;
            this.requestsExecuted = data.requestsExecuted || this.requestsExecuted;
            if (Array.isArray(data.endpoints)) {
              this.endpoints = data.endpoints;
            }
            if (Array.isArray(data.findings)) {
              this.findings = data.findings;
            }
            if (Array.isArray(data.activityLogs) && data.activityLogs.length > 0) {
              this.activityLogs = data.activityLogs;
            }

            if (!data.isRunning && data.phase === 'COMPLETE') {
              this.isRunning = false;
              clearInterval(this.pollInterval);
              this.pollInterval = null;
            }
            this.notify();
          }
        } catch {}
      }, 1200);
    } catch (err: any) {
      this.logEvent('assessment_error', 'ERROR', `Backend network error: ${err.message}`);
      this.isRunning = false;
      this.notify();
    }
  }

  public pauseAssessment() {
    this.isPaused = true;
    this.logEvent('assessment_paused', this.phase, 'Assessment execution paused by user.');
    this.notify();
  }

  public resumeAssessment() {
    this.isPaused = false;
    this.logEvent('assessment_resumed', this.phase, 'Assessment execution resumed.');
    this.notify();
  }

  public async stopAssessment() {
    this.isRunning = false;
    this.isPaused = false;
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    try {
      await fetch('/api/scan/stop', { method: 'POST' });
    } catch {}
    this.logEvent('assessment_stopped', this.phase, 'Assessment stopped by user.');
    this.notify();
  }

  // Real Repeater execution calling Express backend
  public async replayRequest(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: string
  ): Promise<{
    status_code: number;
    body_text: string;
    elapsed_ms: number;
    similarity: number;
    reasons: string[];
  }> {
    this.requestsExecuted += 1;
    try {
      const res = await fetch('/api/repeater/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, url, headers, body }),
      });
      const data = await res.json();
      this.notify();
      return {
        status_code: data.status_code || 0,
        body_text: data.body_text || '',
        elapsed_ms: data.elapsed_ms || 0,
        similarity: data.similarity ?? 0.95,
        reasons: data.reasons || [],
      };
    } catch (err: any) {
      return {
        status_code: 0,
        body_text: `Network failure connecting to assessment backend: ${err.message}`,
        elapsed_ms: 0,
        similarity: 0,
        reasons: ['Backend communication failure'],
      };
    }
  }

  // Real Fuzzer execution calling Express backend
  public async runRealFuzz(
    targetUrl: string,
    parameter: string,
    family: string
  ): Promise<any[]> {
    try {
      const res = await fetch('/api/fuzzer/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, parameter, family }),
      });
      if (res.ok) {
        const data = await res.json();
        return data.results || [];
      }
    } catch {}
    return [];
  }
}
