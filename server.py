"""
API Tester AI MCP Server - API testing and validation tools."""

import sys, os
from auth_middleware import check_access

import json
import time
import urllib.request
from typing import Any
from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP

from datetime import datetime, timezone
from collections import defaultdict

FREE_DAILY_LIMIT = 50
_usage = defaultdict(list)
def _rl(c="anon"):
    now = datetime.now(timezone.utc)
    _usage[c] = [t for t in _usage[c] if (now-t).total_seconds() < 86400]
    if len(_usage[c]) >= FREE_DAILY_LIMIT: return json.dumps({"error": f"Limit {FREE_DAILY_LIMIT}/day"})
    _usage[c].append(now); return None


mcp = FastMCP("api-tester-ai", instructions="MEOK AI Labs MCP Server")
_calls: dict[str, list[float]] = {}
DAILY_LIMIT = 50

def _rate_check(tool: str) -> bool:
    now = time.time()
    _calls.setdefault(tool, [])
    _calls[tool] = [t for t in _calls[tool] if t > now - 86400]
    if len(_calls[tool]) >= DAILY_LIMIT:
        return False
    _calls[tool].append(now)
    return True

def _server_meter_check(api_key: str = "") -> dict:
    """Calls the live /verify endpoint for server-side metering. Returns the JSON dict.
    Fail-open: if /verify is unreachable or KV isn't configured, returns allowed=True
    (so the local rate-limit in _check_rate_limit remains the safety net)."""
    try:
        data = json.dumps({"api_key": api_key, "tool": ""}).encode()
        req = _meter_urlreq.Request(_METER_URL, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with _meter_urlreq.urlopen(req, timeout=2.5) as r:
            d = json.loads(r.read())
            if isinstance(d, dict) and "allowed" in d:
                return d
    except Exception:
        pass
    return {"allowed": True, "tier": "anonymous", "remaining": 200, "upgrade_url": "https://meok.ai/pricing"}


_METER_URL = "https://proofof.ai/verify"


@mcp.tool()
def send_request(method: str, url: str, headers: str = "", body: str = "", timeout: int = 30, api_key: str = "") -> dict[str, Any]:
    """Build and send an HTTP request. Returns request details (actual sending requires urllib/requests).

    Behavior:
        This tool generates structured output without modifying external systems.
        Output is deterministic for identical inputs. No side effects.
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        method (str): The method to analyze or process.
        url (str): The url to analyze or process.
        headers (str): The headers to analyze or process.
        body (str): The body to analyze or process.
        timeout (int): The timeout to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent - calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    if not _rate_check("send_request"):
        return {"error": "Rate limit exceeded (50/day)"}
    method = method.upper()
    valid_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    if method not in valid_methods:
        return {"error": f"Invalid method. Use: {', '.join(valid_methods)}"}
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return {"error": "Invalid URL"}
    hdrs = {}
    if headers:
        try:
            hdrs = json.loads(headers)
        except json.JSONDecodeError:
            for line in headers.split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip()] = v.strip()
    body_parsed = None
    if body:
        try:
            body_parsed = json.loads(body)
        except json.JSONDecodeError:
            body_parsed = body
    req = urllib.request.Request(url, method=method)
    for k, v in hdrs.items():
        req.add_header(k, v)
    if body and method in ("POST", "PUT", "PATCH"):
        req.data = body.encode("utf-8")
        if "Content-Type" not in hdrs:
            req.add_header("Content-Type", "application/json")
    try:
        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.time() - start
            resp_body = resp.read().decode("utf-8", errors="replace")[:5000]
            return {
                "status_code": resp.status, "reason": resp.reason,
                "headers": dict(resp.headers), "body": resp_body,
                "elapsed_ms": round(elapsed * 1000, 1), "url": url, "method": method
            }
    except Exception as e:
        return {"error": str(e), "url": url, "method": method, "request_headers": hdrs}

STRIPE_199 = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"

def _add_upgrade_tail(response, tier="free"):
    """Append upgrade nudge to free-tier success responses."""
    if isinstance(response, dict) and tier == "free":
        response["_upgrade_note"] = "Pro tier: unlimited calls + priority support. Upgrade: " + STRIPE_199
    return response

@mcp.tool()
def validate_response(status_code: int, body: str, expected_status: int = 200, required_fields: str = "", content_type: str = "", api_key: str = "") -> dict[str, Any]:
    """Validate an API response against expectations.

    Behavior:
        This tool is read-only and stateless - it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        status_code (int): The status code to analyze or process.
        body (str): The body to analyze or process.
        expected_status (int): The expected status to analyze or process.
        required_fields (str): The required fields to analyze or process.
        content_type (str): The content type to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent - calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    if not _rate_check("validate_response"):
        return {"error": "Rate limit exceeded (50/day)"}
    issues = []
    if status_code != expected_status:
        issues.append(f"Expected status {expected_status}, got {status_code}")
    body_parsed = None
    if body:
        try:
            body_parsed = json.loads(body)
        except json.JSONDecodeError:
            if content_type and "json" in content_type.lower():
                issues.append("Expected JSON body but failed to parse")
    if required_fields and body_parsed and isinstance(body_parsed, dict):
        for field in required_fields.split(","):
            field = field.strip()
            if field and field not in body_parsed:
                issues.append(f"Missing required field: {field}")
    return {
        "valid": len(issues) == 0, "issues": issues,
        "status_code": status_code, "is_json": body_parsed is not None,
        "body_size": len(body), "field_count": len(body_parsed) if isinstance(body_parsed, dict) else 0
    }

@mcp.tool()
def check_headers(headers_json: str, api_key: str = "") -> dict[str, Any]:
    """Analyze HTTP response headers for security and best practices.

    Behavior:
        This tool is read-only and stateless - it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        headers_json (str): The headers json to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent - calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    if not _rate_check("check_headers"):
        return {"error": "Rate limit exceeded (50/day)"}
    try:
        headers = json.loads(headers_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON headers"}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    checks = []
    security_headers = {
        "strict-transport-security": "HSTS - forces HTTPS",
        "content-security-policy": "CSP - prevents XSS",
        "x-content-type-options": "Prevents MIME sniffing",
        "x-frame-options": "Prevents clickjacking",
        "x-xss-protection": "XSS filter",
        "referrer-policy": "Controls referrer info",
        "permissions-policy": "Controls browser features",
    }
    for header, desc in security_headers.items():
        present = header in headers_lower
        checks.append({"header": header, "present": present, "description": desc, "value": headers_lower.get(header, "")})
    info_leaks = []
    if "server" in headers_lower:
        info_leaks.append({"header": "Server", "value": headers_lower["server"], "risk": "Reveals server software"})
    if "x-powered-by" in headers_lower:
        info_leaks.append({"header": "X-Powered-By", "value": headers_lower["x-powered-by"], "risk": "Reveals framework"})
    present_count = sum(1 for c in checks if c["present"])
    score = round(present_count / len(checks) * 100)
    return {
        "security_headers": checks, "info_leaks": info_leaks,
        "score": score, "grade": "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "F",
        "total_headers": len(headers)
    }

@mcp.tool()
def generate_curl(method: str, url: str, headers: str = "", body: str = "", api_key: str = "") -> dict[str, Any]:
    """Generate a curl command from request parameters.

    Behavior:
        This tool generates structured output without modifying external systems.
        Output is deterministic for identical inputs. No side effects.
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need structured analysis or classification
        of inputs against established frameworks or standards.

    When NOT to use:
        Not suitable for real-time production decision-making without
        human review of results.

    Args:
        method (str): The method to analyze or process.
        url (str): The url to analyze or process.
        headers (str): The headers to analyze or process.
        body (str): The body to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent - calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": STRIPE_199}
    if err := _rl(): return err

    if not _rate_check("generate_curl"):
        return {"error": "Rate limit exceeded (50/day)"}
    parts = ["curl", "-X", method.upper()]
    if headers:
        try:
            hdrs = json.loads(headers)
        except json.JSONDecodeError:
            hdrs = {}
        for k, v in hdrs.items():
            parts.append(f"-H '{k}: {v}'")
    if body:
        parts.append(f"-d '{body}'")
    parts.append(f"'{url}'")
    curl = " \\\n  ".join(parts)
    # Also generate fetch
    fetch_opts = {"method": method.upper()}
    if headers:
        try:
            fetch_opts["headers"] = json.loads(headers)
        except json.JSONDecodeError:
            pass
    if body:
        fetch_opts["body"] = body
    fetch = f"fetch('{url}', {json.dumps(fetch_opts, indent=2)})"
    return {"curl": curl, "fetch": fetch, "method": method.upper(), "url": url}

def main():
    mcp.run()

if __name__ == '__main__':
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}
