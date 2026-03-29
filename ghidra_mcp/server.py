"""FastMCP server with lazy JVM init and stdio transport."""

import json
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP, Context

from ghidra_mcp.core import GhidraContext, init_jvm


# Module-level context — JVM starts lazily on first tool call
_ghidra_ctx: GhidraContext | None = None
_jvm_started: bool = False


def _ensure_jvm():
    """Start JVM if not already started."""
    global _jvm_started
    if not _jvm_started:
        init_jvm()
        _jvm_started = True


mcp = FastMCP("ghidra-mcp")


def get_ctx() -> GhidraContext:
    """Get the GhidraContext, starting JVM lazily if needed."""
    global _ghidra_ctx
    _ensure_jvm()
    if _ghidra_ctx is None:
        _ghidra_ctx = GhidraContext()
    return _ghidra_ctx


# Import and register all tool modules
from ghidra_mcp.tools import session  # noqa: E402, F401
from ghidra_mcp.tools import functions  # noqa: E402, F401
from ghidra_mcp.tools import data  # noqa: E402, F401
from ghidra_mcp.tools import search  # noqa: E402, F401
from ghidra_mcp.tools import annotate  # noqa: E402, F401


def main():
    mcp.run(transport="stdio")


# Only run directly if invoked as a script, not as a module
if __name__ == "__main__":
    main()
