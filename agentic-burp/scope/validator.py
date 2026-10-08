from __future__ import annotations
import fnmatch
from typing import List, Optional, Tuple
from models.scope import ScopePolicy
from .resolver import extract_host_port, is_ip_address, is_loopback_or_private, normalize_url


class ScopeValidationResult:
    def __init__(self, allowed: bool, reason: str = ""):
        self.allowed = allowed
        self.reason = reason

    def __bool__(self):
        return self.allowed

    def __repr__(self):
        return f"<ScopeValidationResult allowed={self.allowed} reason='{self.reason}'>"


class ScopeValidator:
    """
    Deterministic scope gate for all network requests.
    The LLM cannot override or bypass this validator.
    """
    def __init__(self, policy: ScopePolicy):
        self.policy = policy
        self._parsed_targets: List[Tuple[str, str, int]] = []
        self._compile_targets()

    def _compile_targets(self):
        self._parsed_targets = []
        for target in self.policy.targets:
            scheme, host, port = extract_host_port(target)
            self._parsed_targets.append((scheme, host, port))

    def validate_method(self, method: str) -> ScopeValidationResult:
        m = method.upper()
        if m not in self.policy.allowed_methods:
            return ScopeValidationResult(False, f"Method '{m}' is not in allowed methods: {self.policy.allowed_methods}")
        return ScopeValidationResult(True)

    def validate_url(self, url_str: str) -> ScopeValidationResult:
        if not url_str:
            return ScopeValidationResult(False, "URL cannot be empty")

        try:
            scheme, host, port = extract_host_port(url_str)
        except Exception as e:
            return ScopeValidationResult(False, f"Invalid URL structure: {e}")

        # Scheme check
        if scheme not in ["http", "https"]:
            return ScopeValidationResult(False, f"Scheme '{scheme}' is not allowed. Only HTTP/HTTPS permitted.")

        # Port check
        if port not in self.policy.allowed_ports:
            return ScopeValidationResult(False, f"Port {port} is not in allowed ports: {self.policy.allowed_ports}")

        # Metadata endpoint block (Cloud instance metadata SSRF protection)
        if host in ["169.254.169.254", "metadata.google.internal"]:
            return ScopeValidationResult(False, "Cloud instance metadata access is strictly forbidden by SSRF scope policy.")

        # Loopback/Private IP handling
        if is_loopback_or_private(host):
            if not self.policy.allow_internal_loopback:
                return ScopeValidationResult(False, f"Private/loopback destination '{host}' denied by security policy.")

        # Check against target list
        matched = False
        for target_scheme, target_host, target_port in self._parsed_targets:
            # Check host
            host_match = False
            if host == target_host:
                host_match = True
            elif self.policy.allow_subdomains:
                if host.endswith("." + target_host):
                    host_match = True
                elif fnmatch.fnmatch(host, f"*.{target_host}"):
                    host_match = True

            if host_match:
                # Check port match if target port was specified
                if port == target_port:
                    matched = True
                    break

        if not matched:
            if not self.policy.allow_external_hosts:
                return ScopeValidationResult(
                    False,
                    f"Destination '{host}:{port}' is outside configured authorized targets: {[t for t in self.policy.targets]}"
                )

        return ScopeValidationResult(True, "In-scope")

    def validate_request(self, method: str, url_str: str) -> ScopeValidationResult:
        method_res = self.validate_method(method)
        if not method_res:
            return method_res
        return self.validate_url(url_str)
