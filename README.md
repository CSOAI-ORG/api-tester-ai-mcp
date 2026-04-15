# API Tester AI MCP Server

> By [MEOK AI Labs](https://meok.ai) — API testing, validation, and security header analysis

## Installation

```bash
pip install api-tester-ai-mcp
```

## Usage

```bash
# Run standalone
python server.py

# Or via MCP
mcp install api-tester-ai-mcp
```

## Tools

### `send_request`
Build and send an HTTP request. Returns status, headers, body, and latency.

**Parameters:**
- `method` (str): HTTP method (GET, POST, PUT, PATCH, DELETE)
- `url` (str): Request URL
- `headers` (str): Headers as JSON or 'Key: Value' lines
- `body` (str): Request body
- `timeout` (int): Timeout in seconds (default 30)

### `validate_response`
Validate an API response against expectations (status code, required fields, content type).

**Parameters:**
- `status_code` (int): Actual status code
- `body` (str): Response body
- `expected_status` (int): Expected status code (default 200)
- `required_fields` (str): Comma-separated required fields
- `content_type` (str): Expected content type

### `check_headers`
Analyze HTTP response headers for security best practices (HSTS, CSP, XSS protection, etc.).

**Parameters:**
- `headers_json` (str): Response headers as JSON

### `generate_curl`
Generate curl and fetch commands from request parameters.

**Parameters:**
- `method` (str): HTTP method
- `url` (str): Request URL
- `headers` (str): Headers as JSON
- `body` (str): Request body

## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
