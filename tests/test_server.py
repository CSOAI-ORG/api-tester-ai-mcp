import os
import sys
import unittest
from unittest.mock import patch

# Ensure shared auth middleware is available
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/..")


class TestMCPImport(unittest.TestCase):
    def test_import_server(self):
        """Server module must import without errors."""
        import server  # noqa: F401

    def test_mcp_or_server_object_exists(self):
        """FastMCP servers export 'mcp'; low-level servers export 'server'."""
        import server as srv
        self.assertTrue(
            hasattr(srv, "mcp") or hasattr(srv, "server"),
            "Expected 'mcp' or 'server' object in server.py",
        )


class TestAuthMiddleware(unittest.TestCase):
    def test_check_access_allows_empty_key_as_free_tier(self):
        """Empty API key maps to FREE tier and is allowed."""
        from auth_middleware import check_access, Tier
        allowed, msg, tier = check_access("")
        self.assertTrue(allowed)
        self.assertEqual(tier, Tier.FREE)
        self.assertIsInstance(msg, str)

    def test_check_access_returns_tuple(self):
        """check_access must return a 3-tuple."""
        from auth_middleware import check_access
        result = check_access("")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)


class TestSendRequest(unittest.TestCase):
    def test_send_request_returns_response_details(self):
        """send_request must execute a valid mocked HTTP request."""
        import server as srv

        class DummyResponse:
            status = 201
            reason = "Created"
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return b'{"ok": true}'

        srv._calls.clear()
        srv._usage.clear()

        with patch("server.check_access", return_value=(True, "OK", "free")), patch(
            "server.urllib.request.urlopen",
            return_value=DummyResponse(),
        ) as urlopen:
            result = srv.send_request(
                "post",
                "https://example.com/items",
                headers='{"X-Test": "1"}',
                body='{"name": "Ada"}',
            )

        self.assertEqual(result["status_code"], 201)
        self.assertEqual(result["reason"], "Created")
        self.assertEqual(result["body"], '{"ok": true}')
        self.assertEqual(result["method"], "POST")
        self.assertEqual(result["url"], "https://example.com/items")

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b'{"name": "Ada"}')

        headers = {name.lower(): value for name, value in request.header_items()}
        self.assertEqual(headers["x-test"], "1")
        self.assertEqual(headers["content-type"], "application/json")


class TestHealthEndpoint(unittest.TestCase):
    def test_health_url_resolves(self):
        """Wrapper must expose /health."""
        import urllib.request
        # Note: this test requires the wrapper to be running on port 8000.
        # It is skipped in CI unless the server is active.
        try:
            resp = urllib.request.urlopen("http://localhost:8000/health", timeout=2)
            self.assertEqual(resp.status, 200)
        except Exception as e:
            self.skipTest(f"Server not running: {e}")


if __name__ == "__main__":
    unittest.main()
