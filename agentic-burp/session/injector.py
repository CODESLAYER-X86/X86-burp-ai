from __future__ import annotations
from typing import Dict, List, Optional
from models.request import HTTPRequest
from .token_store import TokenStore


class TokenInjector:
    """
    Automatically injects current dynamic tokens and cookies into outbound requests (Section 6).
    """
    @staticmethod
    def inject(request: HTTPRequest, token_store: TokenStore) -> HTTPRequest:
        modified_headers = dict(request.headers)
        modified_cookies = dict(request.cookies)

        for token in token_store.list_tokens():
            if token.status != "ACTIVE":
                continue

            # Header injection (e.g. X-CSRF-Token or Authorization)
            if token.header_name and token.value:
                # If it's a CSRF token and method is state-changing (POST, PUT, DELETE)
                if any(c in token.name.lower() for c in ["csrf", "xsrf", "token"]):
                    if request.method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
                        modified_headers[token.header_name] = token.value
                        if request.url not in token.injected_endpoints:
                            token.injected_endpoints.append(request.url)

                # Authorization token injection
                elif token.header_name.lower() == "authorization" and "Authorization" not in modified_headers:
                    val = token.value if token.value.startswith("Bearer ") else f"Bearer {token.value}"
                    modified_headers["Authorization"] = val

            # Cookie injection
            if token.cookie_name and token.value:
                modified_cookies[token.cookie_name] = token.value

        request.headers = modified_headers
        request.cookies = modified_cookies
        return request
