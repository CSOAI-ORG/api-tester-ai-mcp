<div align="center">

# Api Tester Ai MCP

**API Tester AI MCP Server — API testing and validation tools.**

[![PyPI](https://img.shields.io/pypi/v/meok-api-tester-ai-mcp)](https://pypi.org/project/meok-api-tester-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

API Tester AI MCP Server — API testing and validation tools.

## Tools

| Tool | Description |
|------|-------------|
| `send_request` | Build and send an HTTP request. Returns request details (actual sending requires |
| `validate_response` | Validate an API response against expectations. |
| `check_headers` | Analyze HTTP response headers for security and best practices. |
| `generate_curl` | Generate a curl command from request parameters. |

## Installation

```bash
pip install meok-api-tester-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "api-tester-ai": {
      "command": "python",
      "args": ["-m", "meok_api_tester_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 4 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
