export type FindingSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FindingConfidence = 'LOW' | 'MEDIUM' | 'HIGH' | 'CONFIRMED';
export type FindingStatus = 'SUSPECTED' | 'INVESTIGATING' | 'VERIFIED' | 'REFUTED' | 'INCONCLUSIVE';

export interface Finding {
  id: string;
  finding_type: string;
  title: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  status: FindingStatus;
  endpoint: string;
  method: string;
  parameter?: string;
  description: string;
  evidence_ids: string[];
  impact: string;
  remediation: string;
  detector: string;
  created_at: number;
}

export interface EvidenceItem {
  id: string;
  evidence_type: string;
  request_id?: string;
  response_id?: string;
  baseline_request_id?: string;
  baseline_response_id?: string;
  description: string;
  data: Record<string, any>;
  reproducible: boolean;
}

export interface Observation {
  id: string;
  category: string;
  source: string;
  request_id?: string;
  endpoint: string;
  parameter?: string;
  interesting: boolean;
  summary: string;
  signals: string[];
  differences?: Record<string, any>;
  result?: Record<string, any>;
  created_at: number;
}

export interface DiscoveredEndpoint {
  method: string;
  host: string;
  port: number;
  path: string;
  parameters: string[];
  source: string;
  discovered_at: number;
}

export interface HTTPTransaction {
  request_id: string;
  session_id: string;
  method: string;
  url: string;
  status_code: number;
  body_size: number;
  content_type: string;
  elapsed_ms: number;
  timestamp: number;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  request_body?: string;
  response_body?: string;
}

export interface ScopePolicy {
  targets: string[];
  allowed_methods: string[];
  allowed_ports: number[];
  allow_subdomains: boolean;
  allow_external_hosts: boolean;
  allow_internal_loopback: boolean;
  max_requests_per_minute: number;
}

export interface SessionProfile {
  id: string;
  name: string;
  role: 'primary' | 'secondary' | 'unauthenticated';
  token: string;
  tokenHeaderName: string; // e.g. Authorization, X-API-Key, X-Access-Token
  cookie: string;
  csrfToken?: string;
  autoRefreshCsrf: boolean;
  customHeaders: Record<string, string>;
}

export interface AutoTokenRule {
  id: string;
  name: string;
  enabled: boolean;
  ruleType: 'auto_inject_bearer' | 'auto_extract_csrf' | 'match_and_replace';
  headerName?: string;
  matchPattern?: string;
  replaceValue?: string;
}

export interface GeminiProjectQuota {
  project_id: string;
  model: string;
  enabled: boolean;
  requests_today: number;
  daily_limit: number;
  input_tpm_limit: number;
  rolling_tpm_used: number;
  cooldown_until: number;
  consecutive_errors: number;
}

export interface AgentActivityEvent {
  id: string;
  timestamp: number;
  event_type: string;
  phase: string;
  iteration: number;
  summary: string;
  details?: Record<string, any>;
}

export type AssessmentPhase = 'DISCOVERY' | 'ANALYSIS' | 'INVESTIGATION' | 'VERIFICATION' | 'REPORTING' | 'COMPLETE';
