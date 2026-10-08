# Agentic-Burp

An AI-assisted web security assessment platform inspired by Burp Suite, powered by an LLM reasoning layer (**Gemma 4 31B**) and governed by strict deterministic scope enforcement.

> **Fundamental Philosophy**: *The LLM reasons. The application executes.*

Designed for **authorized security assessments, CTF benchmarks, intentionally vulnerable testbeds, and local security labs**.

---

## Agent / Developer Quickstart Guide

Follow these exact steps to set up and run Agentic-Burp with **zero errors**.

### Prerequisites
* **Python**: 3.10 or higher (Native standard library: `sqlite3`, `asyncio`, `urllib`, `dataclasses`, `unittest` are fully self-contained).
* **Node.js**: 18+ and `npm` (Required for the interactive Web UI dashboard).

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/CODESLAYER-X86/X86-burp-ai.git
cd X86-burp-ai
```

---

### Step 2: Environment Configuration
Copy the provided environment template:
```bash
cp .env.example .env
```

Open `.env` and configure your credentials:
```bash
# Default reasoning engine model
GEMINI_MODEL="gemma-4-31b"

# Primary Gemini API Key (Leave empty to use zero-quota offline test mode)
GEMINI_API_KEY=""

# Optional Multi-Project Rotation (Section 2.X)
GEMINI_PROJECT_1_ID="sec-ops-prod"
GEMINI_PROJECT_1_API_KEY=""
GEMINI_PROJECT_1_MODEL="gemma-4-31b"

GEMINI_PROJECT_2_ID="sec-ops-overflow"
GEMINI_PROJECT_2_API_KEY=""
GEMINI_PROJECT_2_MODEL="gemma-4-31b"
```

> **Note**: If `GEMINI_API_KEY` is not provided, the platform automatically activates the built-in **deterministic offline provider (`FakeGeminiClient`)**, allowing full testing, crawler mapping, repeater execution, and detector validation with **0 token consumption**.

---

### Step 3: Run Diagnostic Self-Check (`doctor`)
Always verify your environment setup before running assessments:

```bash
PYTHONPATH=agentic-burp python3 agentic-burp/cli/main.py doctor
```

**Expected output:**
```text
==================================================
Agentic-Burp Diagnostic Check (doctor)
==================================================
[OK] Python version: 3.10.x
[OK] SQLite WAL engine operational
[OK] Scope and SSRF boundary validation active
[OK] Target Reasoning Model: gemma-4-31b
[OK] Configured Gemini Projects: 1
[OK] Agentic-Burp is ready for authorized assessments.
==================================================
```

---

### Step 4: Run the Complete Automated Test Suite
Verify that all 23 architectural and behavioral test cases pass:

```bash
PYTHONPATH=agentic-burp python3 -m unittest discover -s agentic-burp/tests -p "test_*.py"
```

**Expected output:**
```text
Ran 23 tests in 0.3s
OK
```

---

### Step 5: Launch the Interactive Web Dashboard
Install frontend dependencies and start the local Vite development server:

```bash
npm install
npm run dev
```

The Web UI dashboard will be running at:
```text
http://localhost:3000
```

---

### Step 6: Running Autonomous CLI Scans
To run an automated assessment from the terminal:

```bash
PYTHONPATH=agentic-burp python3 agentic-burp/cli/main.py scan --target http://127.0.0.1:8080
```

---

## Setting & Managing Target Scope

### In the Web Dashboard:
1. Open the **"Scope Gate"** tab.
2. Under **"Configured Authorized Scope Targets"**, type your URL (e.g. `http://127.0.0.1:8080`) and click **"Add Target"**.
3. To delete an old target, click the **Trash Can icon (`🗑`)** next to it.
4. To test an endpoint against the scope filter and SSRF cloud metadata block (`169.254.169.254`), use the **"Live URL Scope & SSRF Validator"** on the right.

### In Configuration Files:
Edit `agentic-burp/config/config.yaml`:
```yaml
target:
  base_url: "http://127.0.0.1:8080"

scope:
  targets:
    - "http://127.0.0.1:8080"
  allowed_methods:
    - "GET"
    - "POST"
    - "PUT"
    - "PATCH"
    - "DELETE"
  allowed_ports:
    - 80
    - 443
    - 8080
  allow_subdomains: false
  allow_external_hosts: false
  max_requests_per_minute: 60
```

---

## Automated Session & Token Handling

Under the **"Sessions & Tokens"** tab in the Web UI:
* **Multi-Identity Profiles**: Configure `User A (Alice)` and `User B (Bob)` with separate Bearer tokens, cookies, and tenant headers.
* **Auto-Token Rules**:
  * Automatically injects `Authorization: Bearer <token>` into outbound requests.
  * Automatically captures and refreshes `X-CSRF-Token` nonces across responses.
  * Automatically isolates cookie jars between testing identities to avoid session bleeding.
* **Repeater Integration**: Use the **"Token / Identity"** dropdown in the Repeater tab to test privilege boundaries and IDOR in one click.

---

## Troubleshooting & Agent Error Prevention

| Error Symptom | Cause | Exact Solution |
| :--- | :--- | :--- |
| `ModuleNotFoundError: No module named 'models'` | `PYTHONPATH` was not set to the `agentic-burp` directory. | Run commands with `PYTHONPATH=agentic-burp python3 ...` or execute `export PYTHONPATH="$(pwd)/agentic-burp:$PYTHONPATH"` in your shell. |
| `SCOPE_DENIED: Host outside configured targets` | Outbound request target is not in the scope allowlist. | Add the target URL in the **Scope Gate** tab or in `config/config.yaml` under `scope.targets`. |
| `sqlite3.OperationalError: no such function: unixepoch` | System SQLite library is older than version 3.38. | Already handled: code uses standard `time.time()` parameterization. |
| `429 Resource Exhausted` | Primary Gemini API key reached rate limits. | System automatically fails over to the next project in the multi-project pool with exponential backoff cooldowns. |
| Port 3000 is already in use | Another service is using port 3000. | Run `npx vite --port 3001` or specify an alternate port. |

---

## Architecture Reference

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
