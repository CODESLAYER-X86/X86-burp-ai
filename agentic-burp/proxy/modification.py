from __future__ import annotations
import urllib.parse
from typing import List, Dict, Any
from models.request import HTTPRequest
from .history import RequestDiff


class ModificationDiffer:
    """Computes structured immutable diffs between original and modified requests (Section 4)."""
    @staticmethod
    def compute_diff(original: HTTPRequest, modified: HTTPRequest, reason: str = "") -> List[RequestDiff]:
        diffs: List[RequestDiff] = []

        # 1. URL Query Parameter diffs
        orig_parsed = urllib.parse.urlsplit(original.url)
        mod_parsed = urllib.parse.urlsplit(modified.url)
        orig_q = dict(urllib.parse.parse_qsl(orig_parsed.query))
        mod_q = dict(urllib.parse.parse_qsl(mod_parsed.query))

        for k, v in mod_q.items():
            if k not in orig_q:
                diffs.append(RequestDiff(parameter=k, old_value="", new_value=v, reason=reason or "Added parameter"))
            elif orig_q[k] != v:
                diffs.append(RequestDiff(parameter=k, old_value=orig_q[k], new_value=v, reason=reason or "Modified parameter"))

        for k, v in orig_q.items():
            if k not in mod_q:
                diffs.append(RequestDiff(parameter=k, old_value=v, new_value="", reason=reason or "Removed parameter"))

        # 2. Header diffs
        for h, v in modified.headers.items():
            if h not in original.headers:
                diffs.append(RequestDiff(header=h, old_value="", new_value=v, reason=reason or "Added header"))
            elif original.headers[h] != v:
                diffs.append(RequestDiff(header=h, old_value=original.headers[h], new_value=v, reason=reason or "Modified header"))

        for h, v in original.headers.items():
            if h not in modified.headers:
                diffs.append(RequestDiff(header=h, old_value=v, new_value="", reason=reason or "Removed header"))

        # 3. Body diff
        if original.body_text != modified.body_text:
            diffs.append(RequestDiff(
                old_value=original.body_text[:100],
                new_value=modified.body_text[:100],
                reason=reason or "Modified request body"
            ))

        return diffs
