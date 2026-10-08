# Agentic-Burp

An AI-assisted web security assessment platform inspired by Burp Suite, powered by an LLM reasoning layer (**Gemma 4 31B**) and governed by strict deterministic scope enforcement.

> **Fundamental Philosophy**: *The LLM reasons. The application executes.*

The system is strictly designed for **authorized security testing, CTF challenges, intentionally vulnerable applications, and local security labs**.

---

## Architecture Overview

```text
User / CLI / Web UI
       ↓
Assessment Engine
       ↓
Gemma 4 31B (Reasoning / Prioritization / Hypotheses)
       ↓
Structured Tool Decision
       ↓
Executor Security Gate (Scope, Permissions, Rate Limits, Budgets)
       ↓
Deterministic Tools (HTTP / Crawler / Repeater / Fuzzer / Detectors)
       ↓
Response Analysis & Evidence Collection
       ↓
Persistent SQLite Storage (Traffic, Findings, Audit Log)
```

---

## Key Capabilities

1. **Deterministic Scope Gate**:
   - Hard execution boundary that the LLM cannot override.
   - Enforces allowed schemes, hosts, ports, methods, rate limits, and SSRF loopback/cloud metadata protection (`169.254.169.254`).

2. **Gemma 4 31B Quota & Multi-Project API Rotation**:
   - Sliding-window TPM tracking over a rolling 60-second window.
   - Quota-driven selection routing requests to the credential pool with the greatest safe headroom.
   - Bounded exponential backoff cooldowns on HTTP 429 errors.
   - API keys are never persisted or printed in plain text logs.

3. **Deterministic Tooling Layer**:
   - **Queue-Based Crawler**: Bounded depth & page limits, automatic form and parameter extraction, compact observation summaries.
   - **Burp Repeater**: Structured request mutations (query, headers, cookies, body) with side-by-side response delta comparator (similarity ratio, status delta, length delta).
   - **Controlled Fuzzer**: Bounded mutation families (`numeric_boundary`, `null_and_empty`, `string_bounds`, `special_chars`, `boolean_variants`) that cluster responses and promote only anomalous deviations to the LLM.
   - **Passive Scanner**: Zero-request header and cookie security analysis.

4. **Evidence-Driven Security Detectors**:
   - **SQL Injection (`sqli`)**: Database error syntax signatures and baseline comparison.
   - **Cross-Site Scripting (`xss`)**: Canary reflection with HTML context classification (body, attribute, script).
   - **IDOR / BOLA (`idor`)**: Multi-session identity separation (User A vs User B) verifying object access across tenant boundaries.
   - **Broken Authentication (`auth`)**: Unauthenticated access verification to protected API paths.
   - **Server-Side Request Forgery (`ssrf`)**: Safe callback correlation token tracking.
   - **Cross-Site Request Forgery (`csrf`)**: State-changing POST/PUT checks under cookie auth without anti-CSRF protection.
   - **CORS Misconfiguration (`cors`)**: Reflective origin detection with credentials enabled.

5. **Finding State Machine**:
   - `SUSPECTED` → `INVESTIGATING` → `VERIFIED` (or `REFUTED` / `INCONCLUSIVE`).
   - Hard invariant: No finding can become `VERIFIED` without reproducible, stored request and response evidence.

---

## CLI Usage

```bash
# Verify system prerequisites, SQLite, model, and scope gate
python3 cli/main.py doctor

# Run automated security assessment against authorized target
python3 cli/main.py scan --target http://127.0.0.1:8080
```

---

## Running the Automated Test Suite

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py"
```
