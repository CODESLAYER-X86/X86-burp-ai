from __future__ import annotations
import json
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple


class HTMLContentParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.scripts: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith("javascript:") and not href.startswith("mailto:") and not href.startswith("#"):
                abs_url = urllib.parse.urljoin(self.base_url, href)
                self.links.add(abs_url)

        elif tag == "script" and "src" in attr_dict:
            src = attr_dict["src"].strip()
            if src:
                self.scripts.add(urllib.parse.urljoin(self.base_url, src))

        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            abs_action = urllib.parse.urljoin(self.base_url, action) if action else self.base_url
            self._current_form = {
                "action": abs_action,
                "method": method,
                "enctype": attr_dict.get("enctype", "application/x-www-form-urlencoded"),
                "fields": []
            }

        elif tag in ["input", "textarea", "select"] and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                self._current_form["fields"].append({
                    "name": name,
                    "type": attr_dict.get("type", "text" if tag == "input" else tag),
                    "value": attr_dict.get("value", "")
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def parse_html(html_text: str, base_url: str) -> Dict[str, Any]:
    """Parses HTML into links, forms, scripts, and endpoints."""
    parser = HTMLContentParser(base_url)
    try:
        parser.feed(html_text)
    except Exception:
        pass

    # Extract API-like endpoints from inline text / JS
    api_candidates = set()
    pattern = r'["\'](/api/[a-zA-Z0-9_\-\/]+(?:\?[a-zA-Z0-9_\-=&]+)?)["\']'
    for match in re.finditer(pattern, html_text):
        api_candidates.add(urllib.parse.urljoin(base_url, match.group(1)))

    return {
        "links": sorted(list(parser.links)),
        "scripts": sorted(list(parser.scripts)),
        "forms": parser.forms,
        "api_endpoints": sorted(list(api_candidates))
    }


def compact_json_for_llm(json_str: str, max_items: int = 3) -> Dict[str, Any]:
    """Summarizes JSON payload structure without blowing up token count."""
    try:
        data = json.loads(json_str)
    except Exception:
        return {"error": "invalid_json", "raw_preview": json_str[:200]}

    def _summarize(val: Any) -> Any:
        if isinstance(val, dict):
            return {k: _summarize(v) for k, v in val.items()}
        elif isinstance(val, list):
            count = len(val)
            sampled = [_summarize(item) for item in val[:max_items]]
            return {
                "_type": "array",
                "length": count,
                "samples": sampled
            }
        elif isinstance(val, (int, float, bool)) or val is None:
            return val
        else:
            s = str(val)
            return s if len(s) < 50 else f"{s[:47]}..."

    return _summarize(data)


def parse_cookie_header(header_val: str) -> Dict[str, str]:
    """Parses Cookie or Set-Cookie header into key-value map."""
    cookies = {}
    if not header_val:
        return cookies
    parts = header_val.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies
