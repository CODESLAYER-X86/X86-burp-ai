import asyncio
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models.endpoint import Endpoint
from models.request import HTTPRequest
from models.response import HTTPResponse
from models.session import AssessmentSession
from security.base import SecurityContext
from security.sqli import SQLiDetector
from security.xss import XSSDetector
from security.idor import IDORDetector
from security.auth import AuthDetector
from security.ssrf import SSRFDetector
from security.csrf import CSRFDetector
from security.cors import CORSDetector


class MockHTTPClient:
    """Mock client returning predetermined security responses for test verification."""
    def __init__(self, responder_func):
        self.responder_func = responder_func

    async def execute(self, request, session=None):
        return self.responder_func(request, session)


class TestSecurityDetectors(unittest.TestCase):
    def test_sqli_detector_identifies_syntax_error(self):
        detector = SQLiDetector()
        ep = Endpoint(method="GET", host="127.0.0.1", port=8080, path="/api/products", parameters=["id"])
        breq = HTTPRequest(method="GET", url="http://127.0.0.1:8080/api/products?id=1")
        bresp = HTTPResponse(status_code=200, body=b'{"id": 1, "name": "Widget"}')

        def responder(req, sess):
            if "'" in req.url or "%27" in req.url:
                return HTTPResponse(status_code=500, body=b"Error: sqlite3.OperationalError: syntax error near '"), None
            return HTTPResponse(status_code=200, body=b'{"id": 1}'), None

        client = MockHTTPClient(responder)
        ctx = SecurityContext("test_sqli", ep, breq, bresp)

        res = asyncio.run(detector.analyze(ctx, client))
        self.assertEqual(res.status, "SUPPORTED")
        self.assertEqual(len(res.candidate_findings), 1)
        self.assertEqual(res.candidate_findings[0].finding_type, "SQL_INJECTION")

    def test_xss_detector_identifies_unencoded_reflection(self):
        detector = XSSDetector()
        ep = Endpoint(method="GET", host="127.0.0.1", port=8080, path="/search", parameters=["q"])
        breq = HTTPRequest(method="GET", url="http://127.0.0.1:8080/search?q=hello")
        bresp = HTTPResponse(status_code=200, body=b"<html><body>Results for hello</body></html>")

        def responder(req, sess):
            # Reflect query q verbatim
            return HTTPResponse(status_code=200, body=b'<html><body>Results for xss_probe_7381<test>"\'</body></html>'), None

        client = MockHTTPClient(responder)
        ctx = SecurityContext("test_xss", ep, breq, bresp)

        res = asyncio.run(detector.analyze(ctx, client))
        self.assertEqual(res.status, "SUPPORTED")
        self.assertEqual(res.candidate_findings[0].status, "VERIFIED")

    def test_idor_detector_identifies_cross_account_leak(self):
        detector = IDORDetector()
        ep = Endpoint(method="GET", host="127.0.0.1", port=8080, path="/api/profile", parameters=["id"])
        breq = HTTPRequest(method="GET", url="http://127.0.0.1:8080/api/profile?id=101")
        bresp = HTTPResponse(status_code=200, body=b'{"id": 101, "email": "alice@corp.test", "ssn": "000-11-2222"}')

        def responder(req, sess):
            # User B successfully retrieves Alice's object
            return HTTPResponse(status_code=200, body=b'{"id": 101, "email": "alice@corp.test", "ssn": "000-11-2222"}'), None

        client = MockHTTPClient(responder)
        ctx = SecurityContext("test_idor", ep, breq, bresp)

        res = asyncio.run(detector.analyze(ctx, client))
        self.assertEqual(res.status, "SUPPORTED")
        self.assertEqual(res.candidate_findings[0].finding_type, "BOLA_IDOR")

    def test_cors_detector_identifies_reflective_origin(self):
        detector = CORSDetector()
        ep = Endpoint(method="GET", host="127.0.0.1", port=8080, path="/api/user_data", parameters=[])
        breq = HTTPRequest(method="GET", url="http://127.0.0.1:8080/api/user_data")
        bresp = HTTPResponse(status_code=200, body=b'{"status": "ok"}')

        def responder(req, sess):
            headers = {
                "access-control-allow-origin": req.headers.get("Origin", ""),
                "access-control-allow-credentials": "true"
            }
            return HTTPResponse(status_code=200, headers=headers, body=b'{"data": "secret"}'), None

        client = MockHTTPClient(responder)
        ctx = SecurityContext("test_cors", ep, breq, bresp)

        res = asyncio.run(detector.analyze(ctx, client))
        self.assertEqual(res.status, "SUPPORTED")
        self.assertEqual(res.candidate_findings[0].finding_type, "CORS_MISCONFIGURATION")


if __name__ == "__main__":
    unittest.main()
