from __future__ import annotations
import json
import re
from typing import Dict, List, Optional, Any
from models.request import HTTPRequest
from models.response import HTTPResponse
from .token_store import DynamicToken, TokenStore


CSRF_NAMES = ["csrf", "csrf_token", "_csrf", "xsrf", "xsrf_token", "_token", "nonce", "authenticity_token"]


class TokenExtractor:
    """
    Deterministic extraction of dynamic tokens from HTTP responses (Section 6).
    Inspects response headers, cookies, HTML input tags, and JSON bodies.
    """
    @staticmethod
    def extract_from_response(response: HTTPResponse, source_endpoint: str, token_store: TokenStore):
        # 1. Header extraction (X-CSRF-Token, Authorization)
        for h_key, h_val in response.headers.items():
            h_low = h_key.lower()
            if any(c in h_low for c in ["csrf", "xsrf", "token"]):
                token_store.set_token(DynamicToken(
                    name=h_key,
                    location="header",
                    value=h_val,
                    header_name=h_key,
                    source_endpoint=source_endpoint,
                    source_request_id=response.request_id
                ))

        # 2. Cookie extraction (Set-Cookie)
        set_cookie = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
        if set_cookie:
            for part in set_cookie.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    if any(s in k.lower() for s in ["session", "token", "auth", "jwt", "csrf"]):
                        token_store.set_token(DynamicToken(
                            name=f"cookie_{k}",
                            location="cookie",
                            value=v,
                            cookie_name=k,
                            source_endpoint=source_endpoint,
                            source_request_id=response.request_id
                        ))

        # 3. HTML Form Input extraction (<input name="csrf" value="...">)
        body_text = response.body_text
        if "<input" in body_text:
            matches = re.findall(r'<input[^>]+(?:name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']+)["\']|value=["\']([^"\']+)["\'][^>]+name=["\']([^"\']+)["\'])', body_text, re.IGNORECASE)
            for m in matches:
                name = m[0] or m[3]
                val = m[1] or m[2]
                if any(c in name.lower() for c in CSRF_NAMES):
                    token_store.set_token(DynamicToken(
                        name=name,
                        location="form_field",
                        value=val,
                        header_name="X-CSRF-Token",
                        source_endpoint=source_endpoint,
                        source_request_id=response.request_id
                    ))

        # 4. JSON Body extraction
        if body_text.strip().startswith("{") and body_text.strip().endswith("}"):
            try:
                data = json.loads(body_text)
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, str) and any(c in k.lower() for c in ["token", "csrf", "nonce", "access_token"]):
                            token_store.set_token(DynamicToken(
                                name=k,
                                location="json_field",
                                value=v,
                                header_name="Authorization" if "access" in k.lower() else "X-CSRF-Token",
                                source_endpoint=source_endpoint,
                                source_request_id=response.request_id
                            ))
            except Exception:
                pass
