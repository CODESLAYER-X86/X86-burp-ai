import {
  Finding,
  EvidenceItem,
  Observation,
  DiscoveredEndpoint,
  HTTPTransaction,
  ScopePolicy,
  GeminiProjectQuota,
  AgentActivityEvent,
  AssessmentPhase
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
    // Initial sample endpoints discovered on authorized lab
    this.endpoints = [
      {
        method: 'GET',
        host: '127.0.0.1',
        port: 8080,
        path: '/api/profile',
        parameters: ['id'],
        source: 'crawler',
        discovered_at: Date.now() - 3600000,
      },
      {
        method: 'GET',
        host: '127.0.0.1',
        port: 8080,
        path: '/search',
        parameters: ['q'],
        source: 'form',
        discovered_at: Date.now() - 3500000,
      },
      {
        method: 'GET',
        host: '127.0.0.1',
        port: 8080,
        path: '/api/products',
        parameters: ['cat', 'sort'],
        source: 'crawler',
        discovered_at: Date.now() - 3400000,
      },
      {
        method: 'POST',
        host: '127.0.0.1',
        port: 8080,
        path: '/account/email',
        parameters: ['new_email'],
        source: 'form',
        discovered_at: Date.now() - 3300000,
      },
      {
        method: 'GET',
        host: '127.0.0.1',
        port: 8080,
        path: '/api/user_data',
        parameters: [],
        source: 'crawler',
        discovered_at: Date.now() - 3200000,
      },
    ];

    // Initial log
    this.logEvent('engine_initialized', 'DISCOVERY', 'Agentic-Burp initialized. Ready for authorized target assessment.');
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

  public startAssessment() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.isPaused = false;
    this.iteration = 0;
    this.phase = 'DISCOVERY';
    this.findings = [];
    this.evidenceList = [];
    this.observations = [];

    this.logEvent('assessment_started', 'DISCOVERY', `Assessment started against target: ${this.targetUrl}`);
    this.notify();

    this.stepInterval = setInterval(() => {
      if (!this.isPaused && this.isRunning) {
        this.stepIteration();
      }
    }, 2400);
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

  public stopAssessment() {
    this.isRunning = false;
    this.isPaused = false;
    if (this.stepInterval) {
      clearInterval(this.stepInterval);
      this.stepInterval = null;
    }
    this.logEvent('assessment_stopped', this.phase, 'Assessment stopped by user.');
    this.notify();
  }

  public stepIteration() {
    if (!this.isRunning) return;
    this.iteration += 1;

    // Quota rotation tracking
    const activeProj = this.geminiProjects[this.iteration % this.geminiProjects.length];
    activeProj.requests_today += 1;
    activeProj.rolling_tpm_used = Math.min(15500, activeProj.rolling_tpm_used + 450);

    if (this.iteration === 1) {
      this.phase = 'DISCOVERY';
      this.logEvent('crawler_dispatched', 'DISCOVERY', `Queue-based crawler mapping authorized target ${this.targetUrl}`);
      this.requestsExecuted += 8;
      this.observations.unshift({
        id: `obs_crawl_${Date.now()}`,
        category: 'crawl_summary',
        source: 'crawler',
        endpoint: this.targetUrl,
        interesting: true,
        summary: 'Discovered 5 endpoints, 3 parameterized query vectors, and 2 HTML forms.',
        signals: ['5_endpoints', '3_params', '2_forms'],
        created_at: Date.now(),
      });
    } else if (this.iteration === 3) {
      this.phase = 'ANALYSIS';
      this.logEvent('passive_analysis_completed', 'ANALYSIS', 'Passive header and cookie security analysis executed (0 network cost).');
      this.observations.unshift({
        id: `obs_headers_${Date.now()}`,
        category: 'passive_security_headers',
        source: 'scanner',
        endpoint: `${this.targetUrl}/`,
        interesting: true,
        summary: 'Missing Content-Security-Policy and X-Frame-Options headers detected.',
        signals: ['missing_csp', 'missing_xfo'],
        created_at: Date.now(),
      });
    } else if (this.iteration === 5) {
      this.phase = 'INVESTIGATION';
      this.logEvent('llm_hypothesis_formulated', 'INVESTIGATION', 'Gemma 4 31B: Identified potential BOLA/IDOR on GET /api/profile?id=101. Planning cross-identity verification.');
    } else if (this.iteration === 7) {
      this.phase = 'INVESTIGATION';
      this.requestsExecuted += 4;
      this.logEvent('detector_executed', 'INVESTIGATION', 'IDOR Detector: Replayed request with Test User B credential against User A object 101.');

      const evId = `evi_idor_${Date.now()}`;
      const newEvidence: EvidenceItem = {
        id: evId,
        evidence_type: 'broken_object_authorization',
        request_id: `req_b_cross_${Date.now()}`,
        response_id: `resp_b_cross_${Date.now()}`,
        baseline_request_id: 'req_a_baseline',
        baseline_response_id: 'resp_a_baseline',
        description: 'User B received HTTP 200 with Alice (User A) confidential profile object without authorization.',
        data: {
          target_object: '101',
          user_a_status: 200,
          user_b_status: 200,
          leaked_fields: ['email', 'ssn', 'account_balance'],
        },
        reproducible: true,
      };
      this.evidenceList.push(newEvidence);

      this.findings.push({
        id: `fnd_idor_${Date.now()}`,
        finding_type: 'BOLA_IDOR',
        title: 'Broken Object-Level Authorization (IDOR) on /api/profile',
        severity: 'HIGH',
        confidence: 'HIGH',
        status: 'INVESTIGATING',
        endpoint: '/api/profile',
        method: 'GET',
        parameter: 'id',
        description: 'The endpoint /api/profile returns sensitive customer records without validating whether the requesting authenticated session owns the object.',
        evidence_ids: [evId],
        impact: 'Tenant separation failure allowing arbitrary users to view confidential records of other accounts.',
        remediation: 'Implement server-side ownership validation: verify current session user ID equals object owner ID.',
        detector: 'idor',
        created_at: Date.now(),
      });
    } else if (this.iteration === 9) {
      this.phase = 'INVESTIGATION';
      this.requestsExecuted += 6;
      this.logEvent('detector_executed', 'INVESTIGATION', 'SQLi Detector: Injected single quote on /api/products?cat=items. Detected sqlite3 syntax error.');

      const evSqli = `evi_sqli_${Date.now()}`;
      this.evidenceList.push({
        id: evSqli,
        evidence_type: 'sql_syntax_error',
        description: "Injected quote triggered 'sqlite3.OperationalError: syntax error near' in HTTP 500 response.",
        data: {
          parameter: 'cat',
          signature: 'syntax error',
          status: 500,
        },
        reproducible: true,
      });

      this.findings.push({
        id: `fnd_sqli_${Date.now()}`,
        finding_type: 'SQL_INJECTION',
        title: 'SQL Injection in parameter cat on /api/products',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        status: 'VERIFIED',
        endpoint: '/api/products',
        method: 'GET',
        parameter: 'cat',
        description: 'Direct concatenation of query parameter cat into backend SQL query triggers syntax errors.',
        evidence_ids: [evSqli],
        impact: 'Arbitrary database read/write access, authentication bypass, data exfiltration.',
        remediation: 'Use parameterized queries or ORM prepared statements.',
        detector: 'sqli',
        created_at: Date.now(),
      });
    } else if (this.iteration === 11) {
      this.phase = 'VERIFICATION';
      this.logEvent('verification_phase_active', 'VERIFICATION', 'Controlled multi-identity confirmation of IDOR finding.');
      // Upgrade IDOR to VERIFIED
      const idorFinding = this.findings.find(f => f.finding_type === 'BOLA_IDOR');
      if (idorFinding) {
        idorFinding.status = 'VERIFIED';
        idorFinding.confidence = 'CONFIRMED';
      }
    } else if (this.iteration === 13) {
      this.phase = 'REPORTING';
      this.logEvent('reporting_phase_active', 'REPORTING', 'Synthesizing verified findings into executive security report.');
    } else if (this.iteration >= this.maxIterations) {
      this.phase = 'COMPLETE';
      this.isRunning = false;
      if (this.stepInterval) clearInterval(this.stepInterval);
      this.logEvent('assessment_completed', 'COMPLETE', 'Security assessment completed successfully. All evidence verified.');
    }

    this.notify();
  }

  // Simulated Repeater execution
  public replayRequest(method: string, url: string, headers: Record<string, string>, body?: string): {
    status_code: number;
    body_text: string;
    elapsed_ms: number;
    similarity: number;
    reasons: string[];
  } {
    this.requestsExecuted += 1;
    let status = 200;
    let respText = '{"status": "ok", "message": "Baseline response"}';

    if (url.includes("'") || url.includes('%27')) {
      status = 500;
      respText = '{"error": "sqlite3.OperationalError: syntax error near single quote"}';
    } else if (url.includes('id=102')) {
      status = 200;
      respText = '{"id": 102, "name": "Bob", "email": "bob@example.com"}';
    } else if (url.includes('id=999999')) {
      status = 404;
      respText = '{"error": "User not found"}';
    }

    const similarity = status === 200 ? 0.92 : 0.35;
    const reasons = status === 500 ? ['Status changed to 500', 'SQL syntax error detected'] : (status === 404 ? ['Status 404 not found'] : []);

    return {
      status_code: status,
      body_text: respText,
      elapsed_ms: 45,
      similarity,
      reasons,
    };
  }
}
