from __future__ import annotations
from typing import Any, Dict, List, Optional
from models.observation import Observation
from models.response import HTTPResponse


def analyze_security_headers(response: HTTPResponse) -> List[Dict[str, Any]]:
    """Passive evaluation of HTTP security headers."""
    issues = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    # Content-Security-Policy
    if "content-security-policy" not in headers_lower:
        issues.append({
            "type": "missing_header",
            "header": "Content-Security-Policy",
            "severity": "LOW",
            "description": "Content-Security-Policy header is missing"
        })

    # X-Frame-Options
    if "x-frame-options" not in headers_lower and "content-security-policy" not in headers_lower:
        issues.append({
            "type": "missing_header",
            "header": "X-Frame-Options",
            "severity": "LOW",
            "description": "X-Frame-Options header is missing (Clickjacking risk)"
        })

    # X-Content-Type-Options
    if "x-content-type-options" not in headers_lower:
        issues.append({
            "type": "missing_header",
            "header": "X-Content-Type-Options",
            "severity": "LOW",
            "description": "X-Content-Type-Options header is missing (MIME-sniffing risk)"
        })

    # Strict-Transport-Security (if HTTPS)
    if response.url.startswith("https://") and "strict-transport-security" not in headers_lower:
        issues.append({
            "type": "missing_header",
            "header": "Strict-Transport-Security",
            "severity": "LOW",
            "description": "HSTS header is missing on HTTPS response"
        })

    # Server / Technology Disclosure
    server_hdr = headers_lower.get("server") or headers_lower.get("x-powered-by")
    if server_hdr:
        issues.append({
            "type": "info_disclosure",
            "header": "Server",
            "value": server_hdr,
            "severity": "INFO",
            "description": f"Server banner disclosed: {server_hdr}"
        })

    return issues


def analyze_cookie_flags(response: HTTPResponse) -> List[Dict[str, Any]]:
    """Passive evaluation of Set-Cookie flags."""
    issues = []
    for k, v in response.headers.items():
        if k.lower() == "set-cookie":
            val_lower = v.lower()
            cookie_name = v.split("=")[0].strip()
            if "httponly" not in val_lower:
                issues.append({
                    "cookie": cookie_name,
                    "issue": "missing_httponly",
                    "severity": "LOW",
                    "description": f"Cookie '{cookie_name}' lacks HttpOnly flag"
                })
            if "secure" not in val_lower and response.url.startswith("https://"):
                issues.append({
                    "cookie": cookie_name,
                    "issue": "missing_secure",
                    "severity": "LOW",
                    "description": f"Cookie '{cookie_name}' lacks Secure flag"
                })
            if "samesite" not in val_lower:
                issues.append({
                    "cookie": cookie_name,
                    "issue": "missing_samesite",
                    "severity": "LOW",
                    "description": f"Cookie '{cookie_name}' lacks explicit SameSite policy"
                })
    return issues


def run_passive_scan(response: HTTPResponse) -> List[Observation]:
    """Generates passive observations from an HTTP response."""
    observations = []
    header_issues = analyze_security_headers(response)
    cookie_issues = analyze_cookie_flags(response)

    if header_issues:
        obs = Observation(
            category="passive_security_headers",
            source="scanner",
            request_id=response.request_id,
            endpoint=response.url,
            interesting=True,
            summary=f"Found {len(header_issues)} security header configurations on {response.url}",
            signals=[f"{len(header_issues)}_header_issues"],
            differences={"issues": header_issues}
        )
        observations.append(obs)

    if cookie_issues:
        obs = Observation(
            category="passive_cookie_flags",
            source="scanner",
            request_id=response.request_id,
            endpoint=response.url,
            interesting=True,
            summary=f"Found {len(cookie_issues)} insecure cookie flag issues on {response.url}",
            signals=[f"{len(cookie_issues)}_cookie_issues"],
            differences={"issues": cookie_issues}
        )
        observations.append(obs)

    return observations
