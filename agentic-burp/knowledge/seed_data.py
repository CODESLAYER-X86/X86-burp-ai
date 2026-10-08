from __future__ import annotations
from typing import List, Dict, Any


SEED_KNOWLEDGE_DOCUMENTS: List[Dict[str, Any]] = [
    {
        "id": "know_idor_rest",
        "title": "Object-Level Authorization Testing in REST APIs",
        "category": "IDOR",
        "context": "REST_API",
        "difficulty": "medium",
        "source_type": "TECHNIQUE_REFERENCE",
        "techniques": ["object identifier manipulation", "multi-session comparison", "tenant isolation verification"],
        "content": (
            "When endpoints expose sequential or predictable object identifiers (e.g. /api/orders?id=101 or /users/<id>), "
            "test whether requesting the object using an alternate authenticated test identity (User B) yields the object. "
            "Legitimate public endpoints will return public data, whereas private objects with broken authorization will "
            "disclose confidential customer records across tenant boundaries. Compare response size, status, and sensitive fields."
        ),
        "advisory_notes": "Advisory only. Always verify that authorization is required before confirming a finding."
    },
    {
        "id": "know_sqli_syntax",
        "title": "Error-Based SQL Injection Probe and Differential Analysis",
        "category": "SQLI",
        "context": "QUERY_PARAM",
        "difficulty": "medium",
        "source_type": "TECHNIQUE_REFERENCE",
        "techniques": ["quote injection", "database error signature matching", "balanced quote repair"],
        "content": (
            "Inject single quotes (') or syntax breaks into input parameters. Observe whether database error signatures "
            "(sqlite3.OperationalError, syntax error, SQLSTATE, pg_query) appear in responses that were absent in baseline responses. "
            "A single 500 error alone is insufficient to confirm SQL injection; verify whether a balanced syntax probe ('' or 1 AND 1=1) "
            "restores clean application execution."
        ),
        "advisory_notes": "Verify against database error signatures or reproducible boolean differential."
    },
    {
        "id": "know_xss_reflection",
        "title": "Reflected Cross-Site Scripting Canary Analysis",
        "category": "XSS",
        "context": "HTML_BODY",
        "difficulty": "low",
        "source_type": "TECHNIQUE_REFERENCE",
        "techniques": ["canary token injection", "context classification", "unencoded reflection check"],
        "content": (
            "Submit a unique benign canary token containing characters like <test>'\" into query or body parameters. "
            "Classify the reflection context (HTML body, attribute value, or script block). Check whether the canary appears "
            "verbatim in the response without proper HTML entity encoding (e.g. &lt;test&gt;). If unescaped inside HTML body or script tags, "
            "arbitrary script execution in the user browser context is confirmed."
        ),
        "advisory_notes": "Verify that Content-Type is text/html and characters are unencoded."
    },
    {
        "id": "know_csrf_state_change",
        "title": "Cross-Site Request Forgery Validation on State-Changing Actions",
        "category": "CSRF",
        "context": "WEB_FORM",
        "difficulty": "medium",
        "source_type": "TECHNIQUE_REFERENCE",
        "techniques": ["cookie-based authentication check", "anti-csrf token omission", "SameSite validation"],
        "content": (
            "On state-changing requests (POST, PUT, DELETE, PATCH), verify whether authentication relies on ambient credentials (cookies). "
            "Replay the request with anti-CSRF headers (X-CSRF-Token) and tokens stripped. If the server executes the state change (HTTP 200/204/302) "
            "without anti-CSRF tokens and cookies lack SameSite=Strict/Lax, a third party can force unauthorized actions."
        ),
        "advisory_notes": "Token check is not applicable to APIs relying strictly on Bearer authorization headers."
    },
    {
        "id": "know_cors_reflection",
        "title": "Insecure CORS Policy with Arbitrary Origin Reflection",
        "category": "CORS",
        "context": "HEADER",
        "difficulty": "low",
        "source_type": "TECHNIQUE_REFERENCE",
        "techniques": ["origin header spoofing", "credential permission check"],
        "content": (
            "Send requests with Origin: https://untrusted-attacker.example. Observe whether Access-Control-Allow-Origin "
            "dynamically mirrors the untrusted origin while Access-Control-Allow-Credentials is set to true. "
            "This permits cross-origin JavaScript on attacker domains to read authenticated victim responses."
        ),
        "advisory_notes": "Requires both reflective ACAO and ACAC=true to constitute a critical exfiltration path."
    },
    {
        "id": "know_ssrf_callback",
        "title": "Server-Side Request Forgery Safe Verification Architecture",
        "category": "SSRF",
        "context": "REST_API",
        "difficulty": "high",
        "source_type": "TECHNIQUE_REFERENCE",
        "techniques": ["safe correlation callback", "out-of-band token verification"],
        "content": (
            "When parameters accept URLs (url, target, dest, webhook, fetch), never blindly scan internal networks. "
            "Instead, provide a controlled loopback callback containing a unique correlation token. If the server fetches "
            "the supplied callback and echoes back the correlation token or content, SSRF behavior is confirmed."
        ),
        "advisory_notes": "Always maintain strict scope boundary; do not attempt arbitrary internal scanning."
    },
    {
        "id": "know_ctf_flag_retrieval",
        "title": "CTF Flag Discovery and Format Validation Strategy",
        "category": "CTF_FLAG",
        "context": "REST_API",
        "difficulty": "medium",
        "source_type": "CTF_WRITEUP",
        "techniques": ["flag format matching", "sensitive property inspection", "evidence confirmation"],
        "content": (
            "In CTF challenges, flags frequently follow standard patterns (FLAG{...}, ctf{...}, or burp{...}) and reside "
            "in protected administrator records, hidden notes fields, or authenticated debug endpoints. Once an authorization "
            "or injection vector is verified, locate the privileged resource, retrieve the payload, validate the flag pattern, "
            "and confirm the origin source before reporting success."
        ),
        "advisory_notes": "Never hallucinate a flag; the exact flag string must be retrieved from a verified target response."
    }
]
