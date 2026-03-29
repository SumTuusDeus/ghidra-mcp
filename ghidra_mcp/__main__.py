"""Entry point: python -m ghidra_mcp"""

import sys

from ghidra_mcp.server import mcp

# Default to stdio (standard MCP transport). Use --sse for persistent sessions.
transport = "sse" if "--sse" in sys.argv else "stdio"

if transport == "sse":
    mcp.settings.host = "127.0.0.1"
    mcp.settings.port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 18080
    mcp.run(transport="sse")
else:
    mcp.run(transport="stdio")
