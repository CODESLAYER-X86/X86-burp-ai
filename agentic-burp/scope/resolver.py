from __future__ import annotations
import ipaddress
import re
import urllib.parse
from typing import Optional, Tuple


def normalize_url(url_str: str) -> str:
    """Produces canonical URL string with sorted query parameters and stripped fragments."""
    if not url_str:
        return ""
    if not url_str.startswith("http://") and not url_str.startswith("https://"):
        url_str = "http://" + url_str

    parsed = urllib.parse.urlsplit(url_str)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Normalize default ports
    if ":" in netloc:
        host, port_str = netloc.split(":", 1)
        try:
            port = int(port_str)
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = host
        except ValueError:
            pass

    path = parsed.path
    if not path:
        path = "/"

    # Normalize query params
    if parsed.query:
        query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query_items.sort(key=lambda x: x[0])
        clean_query = urllib.parse.urlencode(query_items)
    else:
        clean_query = ""

    return urllib.parse.urlunsplit((scheme, netloc, path, clean_query, ""))


def extract_host_port(url_str: str) -> Tuple[str, str, int]:
    """Returns (scheme, host, port) from URL."""
    if not url_str.startswith("http://") and not url_str.startswith("https://"):
        url_str = "http://" + url_str
    parsed = urllib.parse.urlsplit(url_str)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host.lower(), port


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_loopback_or_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return host in ["localhost", "127.0.0.1", "::1"]
