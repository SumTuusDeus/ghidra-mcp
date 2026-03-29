# Architecture Spec

## Overview
A Python MCP server (`ghidra_mcp`) that exposes Ghidra's reverse engineering capabilities to LLM agents via PyGhidra. No GUI, no intermediary HTTP layer - direct JVM API access from Python.

## Stack
- **Python 3.12** (system)
- **PyGhidra 3.0.2** (pipx venv at `~/.local/share/pipx/venvs/pyghidra/`)
- **Ghidra 12.0.4** at `/opt/ghidra`
- **FastMCP** (from `mcp` Python SDK)
- **Pydantic v2** for input validation
- **Transport:** stdio (for mcporter integration)

## Runtime Architecture

```
Agent (Cassy) -> mcporter -> stdio -> ghidra_mcp.py -> PyGhidra -> Ghidra JVM (in-process)
```

### JVM Lifecycle
- PyGhidra launches the JVM once at server startup via FastMCP's lifespan hook
- JVM persists for the lifetime of the MCP server process
- Single-threaded access to Ghidra APIs (JVM is not thread-safe for Ghidra operations)

### Session Model
- One binary loaded at a time
- `load_binary` swaps the active program (closes previous, opens new)
- If no binary is loaded, tools return a clear error: "No program loaded. Use ghidra_load_binary first."

### Project Persistence
- Projects stored in `~/.ghidra-mcp/projects/`
- Each binary gets a project named after its filename
- Re-loading a previously analyzed binary skips analysis (project already exists)
- `run_analysis` can force re-analysis if needed

## File Structure
```
ghidra-mcp/
  ghidra_mcp/
    __init__.py
    server.py          # FastMCP server, lifespan, main entry
    core.py            # JVM init, project/program management
    tools/
      __init__.py
      session.py       # load_binary, get_program_info, run_analysis
      functions.py     # list, search, get, decompile, disassemble, call_graph, xrefs
      data.py          # strings, imports, exports, segments, namespaces
      annotate.py      # rename, comment, prototype, retype, struct
      search.py        # byte search, string search
    models/
      __init__.py
      inputs.py        # All Pydantic input models
    utils.py           # Pagination, formatting, error handling
  pyproject.toml       # Project metadata, dependencies
  README.md
```

## Dependencies
```
mcp>=1.2.0,<2
pydantic>=2.0
pyghidra>=3.0
```

## Environment
- `GHIDRA_INSTALL_DIR=/opt/ghidra` (set in ~/.bashrc)
- Server runs from the pipx pyghidra venv (needs access to JVM jars)
- OR: standalone venv that includes pyghidra + mcp + pydantic

## Key Constraints
- All Ghidra API calls must happen on the main thread (no async Ghidra calls)
- Tool functions are `async def` per FastMCP convention but Ghidra calls within them are synchronous
- Call Ghidra synchronously inside async tool functions - do NOT use asyncio.to_thread() (JVM objects aren't thread-safe)
- Pagination on all list operations (default limit=100, max 1000)
- All address parameters accept hex strings (e.g., "0x00104000" or "00104000")
