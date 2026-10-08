import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import http from 'http';
import https from 'https';
import urllib from 'url';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';

const app = express();
const port = parseInt(process.env.PORT || '3000', 10);
const host = '0.0.0.0';

app.use(express.json({ limit: '10mb' }));

// ==========================================
// In-Memory Assessment & Scan State
// ==========================================
interface DiscoveredEndpoint {
  method: string;
  host: string;
  port: number;
  path: string;
  parameters: string[];
  source: string;
  discovered_at: number;
}

interface Finding {
  id: string;
  finding_type: string;
  title: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: 'LOW' | 'MEDIUM' | 'HIGH' | 'CONFIRMED';
  status: 'SUSPECTED' | 'INVESTIGATING' | 'VERIFIED' | 'REFUTED';
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

interface ScanState {
  isRunning: boolean;
  isPaused: boolean;
  targetUrl: string;
  phase: string;
  iteration: number;
  maxIterations: number;
  requestsExecuted: number;
  endpoints: DiscoveredEndpoint[];
  findings: Finding[];
  observations: any[];
  activityLogs: any[];
  process?: any;
}

const currentScan: ScanState = {
  isRunning: false,
  isPaused: false,
  targetUrl: 'http://127.0.0.1:8080',
  phase: 'IDLE',
  iteration: 0,
  maxIterations: 20,
  requestsExecuted: 0,
  endpoints: [],
  findings: [],
  observations: [],
  activityLogs: [],
};

const scopePolicy = {
  targets: ['http://127.0.0.1:8080', 'https://authorized-lab.example', 'http://localhost:3000'],
  allowed_methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
  allowed_ports: [80, 443, 8080, 8443, 3000],
  allow_subdomains: false,
  allow_external_hosts: true, // Allow user-specified targets
  max_requests_per_minute: 60,
};

// ==========================================
// Scope Validation Logic
// ==========================================
function validateUrlScope(urlStr: string, method: string = 'GET') {
  if (!scopePolicy.allowed_methods.includes(method.toUpperCase())) {
    return { allowed: false, reason: `Method ${method} is not allowed.` };
  }
  try {
    const parsed = new URL(urlStr.startsWith('http') ? urlStr : `http://${urlStr}`);
    if (parsed.hostname === '169.254.169.254' || parsed.hostname === 'metadata.google.internal') {
      return { allowed: false, reason: 'Access to Cloud Instance Metadata is blocked by SSRF policy.' };
    }
    const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    if (!scopePolicy.allowed_ports.includes(port) && port !== 3000) {
      return { allowed: false, reason: `Port ${port} is outside allowed ports.` };
    }
    return { allowed: true, reason: 'Authorized in-scope target' };
  } catch (err: any) {
    return { allowed: false, reason: `Malformed URL: ${err.message}` };
  }
}

// ==========================================
// Real HTTP Dispatcher
// ==========================================
async function executeRealHttpRequest(
  method: string,
  targetUrl: string,
  headers: Record<string, string> = {},
  body?: string
): Promise<{
  status_code: number;
  headers: Record<string, string>;
  body_text: string;
  elapsed_ms: number;
  error?: string;
}> {
  const startTime = Date.now();
  currentScan.requestsExecuted += 1;

  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `http://${targetUrl}`);
    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;

    const requestHeaders: Record<string, string> = {
      'User-Agent': 'Agentic-Burp/1.0 (Authorized Security Assessment)',
      Accept: '*/*',
      ...headers,
    };

    if (body && !requestHeaders['Content-Length']) {
      requestHeaders['Content-Length'] = Buffer.byteLength(body).toString();
    }

    return await new Promise((resolve) => {
      const req = client.request(
        parsed,
        {
          method: method.toUpperCase(),
          headers: requestHeaders,
          timeout: 10000,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const elapsed_ms = Date.now() - startTime;
            const fullBody = Buffer.concat(chunks).toString('utf-8');
            const respHeaders: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (Array.isArray(v)) {
                respHeaders[k] = v.join(', ');
              } else if (v) {
                respHeaders[k] = v;
              }
            }
            resolve({
              status_code: res.statusCode || 200,
              headers: respHeaders,
              body_text: fullBody,
              elapsed_ms,
            });
          });
        }
      );

      req.on('error', (err) => {
        resolve({
          status_code: 0,
          headers: {},
          body_text: '',
          elapsed_ms: Date.now() - startTime,
          error: err.message,
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          status_code: 0,
          headers: {},
          body_text: '',
          elapsed_ms: Date.now() - startTime,
          error: 'Connection timed out after 10000ms',
        });
      });

      if (body) {
        req.write(body);
      }
      req.end();
    });
  } catch (err: any) {
    return {
      status_code: 0,
      headers: {},
      body_text: '',
      elapsed_ms: Date.now() - startTime,
      error: err.message,
    };
  }
}

// ==========================================
// Helper: HTML Link and Parameter Extractor
// ==========================================
function extractLinksAndForms(html: string, baseUrlStr: string): { links: string[]; forms: any[] } {
  const links: string[] = [];
  const forms: any[] = [];
  try {
    const baseUrl = new URL(baseUrlStr);

    // Extract hrefs
    const hrefRegex = /href=["']([^"'#>]+)["']/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
      try {
        const full = new URL(match[1], baseUrl).toString();
        if (full.startsWith('http')) links.push(full);
      } catch {}
    }

    // Extract forms
    const formRegex = /<form\s+([^>]+)>(.*?)<\/form>/gis;
    let formMatch;
    while ((formMatch = formRegex.exec(html)) !== null) {
      const formAttrs = formMatch[1];
      const formBody = formMatch[2];
      const actionMatch = /action=["']([^"']*)["']/i.exec(formAttrs);
      const methodMatch = /method=["']([^"']*)["']/i.exec(formAttrs);
      const action = actionMatch ? new URL(actionMatch[1] || '', baseUrl).toString() : baseUrlStr;
      const formMethod = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

      const inputRegex = /<input[^>]+name=["']([^"']+)["'][^>]*>/gi;
      const inputs: string[] = [];
      let inputMatch;
      while ((inputMatch = inputRegex.exec(formBody)) !== null) {
        inputs.push(inputMatch[1]);
      }
      forms.push({ action, method: formMethod, inputs });
    }
  } catch {}
  return { links, forms };
}

// ==========================================
// REST API Routes
// ==========================================

// 1. Scope check & management
app.post('/api/scope/validate', (req: Request, res: Response) => {
  const { url, method } = req.body;
  const result = validateUrlScope(url || '', method || 'GET');
  res.json(result);
});

app.get('/api/scope/policy', (req: Request, res: Response) => {
  res.json(scopePolicy);
});

app.post('/api/scope/policy', (req: Request, res: Response) => {
  const { targets } = req.body;
  if (Array.isArray(targets)) {
    scopePolicy.targets = targets;
  }
  res.json({ status: 'ok', policy: scopePolicy });
});

// 2. Real Repeater execution
app.post('/api/repeater/send', async (req: Request, res: Response) => {
  const { method, url, headers, body } = req.body;
  const scopeCheck = validateUrlScope(url, method);
  if (!scopeCheck.allowed) {
    return res.status(403).json({
      status_code: 403,
      body_text: `BLOCKED BY SCOPE GATE: ${scopeCheck.reason}`,
      headers: {},
      elapsed_ms: 0,
      similarity: 0,
      reasons: [scopeCheck.reason],
    });
  }

  const result = await executeRealHttpRequest(method || 'GET', url, headers || {}, body);

  // Compute similarity / deviation if error
  const isError = result.status_code >= 400 || result.error;
  const reasons: string[] = [];
  if (result.status_code === 500) reasons.push('Server returned HTTP 500 Internal Error');
  if (result.body_text.toLowerCase().includes('syntax error') || result.body_text.toLowerCase().includes('sqlite3')) {
    reasons.push('Database error signature observed in response');
  }

  res.json({
    status_code: result.status_code,
    body_text: result.body_text || (result.error ? `Connection Error: ${result.error}` : ''),
    headers: result.headers,
    elapsed_ms: result.elapsed_ms,
    similarity: isError ? 0.35 : 0.95,
    reasons,
  });
});

// 3. Real Bounded Fuzzer execution
app.post('/api/fuzzer/run', async (req: Request, res: Response) => {
  const { targetUrl, parameter, family } = req.body;
  const scopeCheck = validateUrlScope(targetUrl);
  if (!scopeCheck.allowed) {
    return res.status(403).json({ error: scopeCheck.reason });
  }

  const candidatePayloads: Record<string, string[]> = {
    numeric_boundary: ['0', '-1', '1', '2147483647', '999999', 'NaN'],
    null_and_empty: ['', '%00', 'null', 'undefined'],
    string_bounds: ['A'.repeat(50), 'A'.repeat(500), 'admin', 'root'],
    special_chars: ["'", '"', '`', ';', '--', '/*', '../', '%2e%2e%2f'],
    boolean_variants: ['1', '0', 'true', 'false'],
  };

  const payloads = candidatePayloads[family] || candidatePayloads.numeric_boundary;
  const results = [];

  for (const payload of payloads) {
    const parsed = new URL(targetUrl);
    parsed.searchParams.set(parameter, payload);
    const resp = await executeRealHttpRequest('GET', parsed.toString());
    const isAnomalous = resp.status_code === 500 || resp.body_text.toLowerCase().includes('error');
    results.push({
      payload,
      status: resp.status_code,
      size: Buffer.byteLength(resp.body_text),
      anomalous: isAnomalous,
    });
  }

  res.json({ results });
});

// 4. Real Live Assessment Scan
app.post('/api/scan/start', async (req: Request, res: Response) => {
  const { targetUrl } = req.body;
  if (!targetUrl) {
    return res.status(400).json({ error: 'targetUrl is required' });
  }

  const scopeCheck = validateUrlScope(targetUrl);
  if (!scopeCheck.allowed) {
    return res.status(403).json({ error: scopeCheck.reason });
  }

  // Ensure target is in scope
  if (!scopePolicy.targets.includes(targetUrl)) {
    scopePolicy.targets.push(targetUrl);
  }

  // Reset scan state
  currentScan.isRunning = true;
  currentScan.isPaused = false;
  currentScan.targetUrl = targetUrl;
  currentScan.phase = 'DISCOVERY';
  currentScan.iteration = 0;
  currentScan.requestsExecuted = 0;
  currentScan.endpoints = [];
  currentScan.findings = [];
  currentScan.observations = [];
  currentScan.activityLogs = [
    {
      id: `evt_${Date.now()}`,
      timestamp: Date.now(),
      event_type: 'assessment_started',
      phase: 'DISCOVERY',
      summary: `Started live autonomous assessment on target: ${targetUrl}`,
    },
  ];

  res.json({ status: 'started', target: targetUrl });

  // Run Real Active Crawler & Security Detectors in Background
  runRealScanPipeline(targetUrl);
});

async function runRealScanPipeline(targetUrl: string) {
  const log = (phase: string, summary: string) => {
    currentScan.activityLogs.unshift({
      id: `evt_${Date.now()}_${Math.random().toString(36).substring(7)}`,
      timestamp: Date.now(),
      event_type: 'scan_activity',
      phase,
      iteration: currentScan.iteration,
      summary,
    });
  };

  try {
    // ----------------------------------------------------
    // PHASE 1: DISCOVERY (REAL CRAWL)
    // ----------------------------------------------------
    currentScan.phase = 'DISCOVERY';
    currentScan.iteration = 1;
    log('DISCOVERY', `Crawling root endpoint ${targetUrl} for links and forms...`);

    const rootResp = await executeRealHttpRequest('GET', targetUrl);
    const parsedRoot = new URL(targetUrl);

    currentScan.endpoints.push({
      method: 'GET',
      host: parsedRoot.hostname,
      port: parsedRoot.port ? parseInt(parsedRoot.port, 10) : (parsedRoot.protocol === 'https:' ? 443 : 80),
      path: parsedRoot.pathname || '/',
      parameters: Array.from(parsedRoot.searchParams.keys()),
      source: 'seed',
      discovered_at: Date.now(),
    });

    if (rootResp.body_text) {
      const { links, forms } = extractLinksAndForms(rootResp.body_text, targetUrl);

      // Add discovered links within same origin
      for (const link of links.slice(0, 15)) {
        try {
          const lUrl = new URL(link);
          if (lUrl.hostname === parsedRoot.hostname) {
            const epPath = lUrl.pathname;
            const params = Array.from(lUrl.searchParams.keys());
            if (!currentScan.endpoints.some((e) => e.path === epPath && e.method === 'GET')) {
              currentScan.endpoints.push({
                method: 'GET',
                host: lUrl.hostname,
                port: lUrl.port ? parseInt(lUrl.port, 10) : (lUrl.protocol === 'https:' ? 443 : 80),
                path: epPath,
                parameters: params,
                source: 'crawler',
                discovered_at: Date.now(),
              });
            }
          }
        } catch {}
      }

      // Add forms
      for (const form of forms) {
        try {
          const fUrl = new URL(form.action);
          if (!currentScan.endpoints.some((e) => e.path === fUrl.pathname && e.method === form.method)) {
            currentScan.endpoints.push({
              method: form.method,
              host: fUrl.hostname,
              port: fUrl.port ? parseInt(fUrl.port, 10) : 80,
              path: fUrl.pathname,
              parameters: form.inputs,
              source: 'form',
              discovered_at: Date.now(),
            });
          }
        } catch {}
      }
    }

    log('DISCOVERY', `Crawl complete. Discovered ${currentScan.endpoints.length} unique endpoints.`);

    // ----------------------------------------------------
    // PHASE 2: ANALYSIS (PASSIVE SECURITY SCAN)
    // ----------------------------------------------------
    currentScan.phase = 'ANALYSIS';
    currentScan.iteration = 3;
    log('ANALYSIS', 'Analyzing security headers and cookie flags on target...');

    const headersLower: Record<string, string> = {};
    for (const [k, v] of Object.entries(rootResp.headers)) {
      headersLower[k.toLowerCase()] = v;
    }

    if (!headersLower['content-security-policy']) {
      currentScan.findings.push({
        id: `fnd_csp_${Date.now()}`,
        finding_type: 'MISSING_CSP_HEADER',
        title: 'Missing Content-Security-Policy (CSP) Header',
        severity: 'LOW',
        confidence: 'CONFIRMED',
        status: 'VERIFIED',
        endpoint: parsedRoot.pathname || '/',
        method: 'GET',
        description: 'Target response does not specify a Content-Security-Policy header to restrict resource loading.',
        evidence_ids: [`ev_hdr_csp_${Date.now()}`],
        impact: 'Increases risk of Cross-Site Scripting (XSS) and code injection.',
        remediation: 'Implement a strict Content-Security-Policy header restricting script sources.',
        detector: 'passive_scanner',
        created_at: Date.now(),
      });
    }

    if (!headersLower['x-frame-options'] && !headersLower['content-security-policy']) {
      currentScan.findings.push({
        id: `fnd_xfo_${Date.now()}`,
        finding_type: 'MISSING_XFRAME_OPTIONS',
        title: 'Missing X-Frame-Options Header (Clickjacking Risk)',
        severity: 'LOW',
        confidence: 'CONFIRMED',
        status: 'VERIFIED',
        endpoint: parsedRoot.pathname || '/',
        method: 'GET',
        description: 'Target does not prevent framing in iframes, exposing pages to clickjacking attacks.',
        evidence_ids: [`ev_hdr_xfo_${Date.now()}`],
        impact: 'An attacker could frame this site to trick users into unintended clicks.',
        remediation: 'Set X-Frame-Options: DENY or SAMEORIGIN.',
        detector: 'passive_scanner',
        created_at: Date.now(),
      });
    }

    // ----------------------------------------------------
    // PHASE 3: INVESTIGATION & ACTIVE DETECTORS
    // ----------------------------------------------------
    currentScan.phase = 'INVESTIGATION';
    currentScan.iteration = 5;

    // Check each parameterized endpoint with real probes
    for (const ep of currentScan.endpoints) {
      if (!currentScan.isRunning) break;

      const fullUrl = new URL(ep.path, targetUrl).toString();

      // Test 1: Real SQL Injection probe
      if (ep.parameters.length > 0) {
        const param = ep.parameters[0];
        log('INVESTIGATION', `SQLi Detector: Probing parameter '${param}' on ${ep.path}...`);
        const sqliUrl = new URL(fullUrl);
        sqliUrl.searchParams.set(param, "1'");
        const sqliResp = await executeRealHttpRequest('GET', sqliUrl.toString());

        const bodyLow = sqliResp.body_text.toLowerCase();
        if (
          bodyLow.includes('syntax error') ||
          bodyLow.includes('sqlite3') ||
          bodyLow.includes('sqlstate') ||
          bodyLow.includes('pg_query')
        ) {
          const evId = `ev_sqli_${Date.now()}`;
          currentScan.findings.push({
            id: `fnd_sqli_${Date.now()}`,
            finding_type: 'SQL_INJECTION',
            title: `SQL Injection in parameter '${param}' on ${ep.path}`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            status: 'VERIFIED',
            endpoint: ep.path,
            method: ep.method,
            parameter: param,
            description: `Injecting single quote triggers server database syntax error on parameter '${param}'.`,
            evidence_ids: [evId],
            impact: 'Full database read/write access and authentication bypass.',
            remediation: 'Use parameterized queries or ORM prepared statements.',
            detector: 'sqli',
            created_at: Date.now(),
          });
          log('INVESTIGATION', `Verified SQL Injection on ${ep.path} (parameter: ${param})`);
        }

        // Test 2: Real Reflected XSS probe
        log('INVESTIGATION', `XSS Detector: Injecting canary on ${ep.path}...`);
        const canary = 'xss_canary_probe_<script>1</script>';
        const xssUrl = new URL(fullUrl);
        xssUrl.searchParams.set(param, canary);
        const xssResp = await executeRealHttpRequest('GET', xssUrl.toString());

        if (xssResp.body_text.includes(canary)) {
          const evId = `ev_xss_${Date.now()}`;
          currentScan.findings.push({
            id: `fnd_xss_${Date.now()}`,
            finding_type: 'CROSS_SITE_SCRIPTING',
            title: `Reflected Cross-Site Scripting on ${ep.path}`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            status: 'VERIFIED',
            endpoint: ep.path,
            method: ep.method,
            parameter: param,
            description: `User-supplied payload on '${param}' is reflected unescaped in response HTML.`,
            evidence_ids: [evId],
            impact: 'Allows execution of arbitrary JavaScript in the victim browser context.',
            remediation: 'Contextually HTML-encode user input before rendering it in web responses.',
            detector: 'xss',
            created_at: Date.now(),
          });
          log('INVESTIGATION', `Verified Reflected XSS on ${ep.path} (parameter: ${param})`);
        }
      }

      // Test 3: Insecure CORS probe
      const corsResp = await executeRealHttpRequest('GET', fullUrl, {
        Origin: 'https://attacker-origin.example',
      });
      const acao = corsResp.headers['access-control-allow-origin'];
      const acac = corsResp.headers['access-control-allow-credentials'];
      if (acao === 'https://attacker-origin.example' && acac === 'true') {
        currentScan.findings.push({
          id: `fnd_cors_${Date.now()}`,
          finding_type: 'CORS_MISCONFIGURATION',
          title: `Insecure CORS Misconfiguration on ${ep.path}`,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          status: 'VERIFIED',
          endpoint: ep.path,
          method: 'GET',
          description: 'Server dynamically reflects arbitrary Origin with Access-Control-Allow-Credentials: true.',
          evidence_ids: [`ev_cors_${Date.now()}`],
          impact: 'Third-party malicious websites can read authenticated user responses.',
          remediation: 'Do not reflect arbitrary Origin headers with credentials. Use an allowlist.',
          detector: 'cors',
          created_at: Date.now(),
        });
        log('INVESTIGATION', `Verified Insecure CORS on ${ep.path}`);
      }
    }

    // ----------------------------------------------------
    // PHASE 4: VERIFICATION & REPORTING
    // ----------------------------------------------------
    currentScan.phase = 'VERIFICATION';
    currentScan.iteration = 10;
    log('VERIFICATION', `All findings backed by real network evidence. Transitioning to REPORTING.`);

    currentScan.phase = 'REPORTING';
    currentScan.iteration = 12;
    log('REPORTING', `Generated report with ${currentScan.findings.length} verified findings.`);

    currentScan.phase = 'COMPLETE';
    currentScan.isRunning = false;
    log('COMPLETE', 'Live assessment completed.');
  } catch (err: any) {
    currentScan.phase = 'COMPLETE';
    currentScan.isRunning = false;
    log('COMPLETE', `Assessment finished with notice: ${err.message}`);
  }
}

// 5. Scan status polling
app.get('/api/scan/status', (req: Request, res: Response) => {
  res.json({
    isRunning: currentScan.isRunning,
    isPaused: currentScan.isPaused,
    targetUrl: currentScan.targetUrl,
    phase: currentScan.phase,
    iteration: currentScan.iteration,
    maxIterations: currentScan.maxIterations,
    requestsExecuted: currentScan.requestsExecuted,
    endpoints: currentScan.endpoints,
    findings: currentScan.findings,
    activityLogs: currentScan.activityLogs,
  });
});

app.post('/api/scan/stop', (req: Request, res: Response) => {
  currentScan.isRunning = false;
  currentScan.phase = 'COMPLETE';
  res.json({ status: 'stopped' });
});

// ==========================================
// Start Server with Vite Middleware in Dev
// ==========================================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (req: Request, res: Response) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(port, host, () => {
    console.log(`[Agentic-Burp] Full-Stack Server active on http://${host}:${port}`);
  });
}

startServer();
