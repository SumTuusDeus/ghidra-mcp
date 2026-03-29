# ghidra-mcp

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-green.svg)](https://python.org)
[![Ghidra 11.x/12.x](https://img.shields.io/badge/Ghidra-11.x%2F12.x-red.svg)](https://ghidra-sre.org/)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model_Context_Protocol-purple.svg)](https://modelcontextprotocol.io/)

**Give your AI agent a reverse engineer's toolkit.** Load binaries, decompile functions, trace call graphs, search byte patterns, and annotate symbols -- all through the Model Context Protocol.

## Why ghidra-mcp?

- **Headless** -- no Ghidra GUI required. Runs on servers, CI pipelines, containers, anywhere.
- **Direct JVM access** -- PyGhidra launches the JVM in-process. No HTTP bridges, no plugins to install, no multi-process coordination.
- **Simple setup** -- `pip install`, set one env var, run. Three commands to working tools.
- **22 tools** covering the full RE workflow: session management, function analysis, data discovery, and annotations.

## Quick Start

```bash
# 1. Install dependencies (into your PyGhidra environment)
pip install pyghidra "mcp>=1.2.0,<2" "pydantic>=2.0"

# 2. Clone
git clone https://github.com/SumTuusDeus/ghidra-mcp.git
cd ghidra-mcp

# 3. Run (stdio -- standard MCP transport)
GHIDRA_INSTALL_DIR=/opt/ghidra python -m ghidra_mcp
```

That's it. Your MCP client can now call 22 reverse engineering tools.

### SSE transport (persistent server)

```bash
GHIDRA_INSTALL_DIR=/opt/ghidra python -m ghidra_mcp --sse
# Listening on http://127.0.0.1:18080

# Custom port
GHIDRA_INSTALL_DIR=/opt/ghidra python -m ghidra_mcp --sse --port 9090
```

### MCP client configuration

**Claude Desktop / stdio:**
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["-m", "ghidra_mcp"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra"
      }
    }
  }
}
```

**SSE-based clients:**
```json
{
  "mcpServers": {
    "ghidra": {
      "baseUrl": "http://127.0.0.1:18080/sse"
    }
  }
}
```

## Architecture

```
Agent -> MCP client -> stdio/SSE -> ghidra_mcp -> PyGhidra -> Ghidra JVM (in-process)
```

- JVM launches once on first tool call, persists for server lifetime
- One binary loaded at a time; `load_binary` swaps the active program
- Projects cached at `~/.ghidra-mcp/projects/` for instant reloads
- Synchronous Ghidra API calls (JVM is not thread-safe for Ghidra operations)

## Requirements

- Python 3.12+
- [Ghidra](https://ghidra-sre.org/) 11.x or 12.x
- [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) 3.0+
- JDK 21+

## Tools (22)

### Session Management
| Tool | Description |
|------|-------------|
| `ghidra_load_binary` | Load a binary for analysis. First load triggers auto-analysis (30-120s). Subsequent loads are instant (project cached). |
| `ghidra_get_program_info` | Metadata: architecture, compiler, format, function count, SHA256 |
| `ghidra_run_analysis` | Re-run Ghidra auto-analysis |

### Function Analysis
| Tool | Description |
|------|-------------|
| `ghidra_list_functions` | List functions with pagination and sorting |
| `ghidra_search_functions` | Search by name substring (case-insensitive) |
| `ghidra_get_function` | Detailed info: signature, params, local variables, calling convention |
| `ghidra_decompile` | Decompile to C pseudocode |
| `ghidra_disassemble` | Assembly listing for a function |
| `ghidra_get_call_graph` | Callers and callees with configurable depth (max 3) |
| `ghidra_get_xrefs` | Cross-references to/from an address |

### Data & Discovery
| Tool | Description |
|------|-------------|
| `ghidra_list_strings` | Defined strings with optional substring filter |
| `ghidra_list_imports` | Imported symbols and libraries |
| `ghidra_list_exports` | Exported symbols |
| `ghidra_list_segments` | Memory segments with permissions (rwx) |
| `ghidra_list_namespaces` | Non-global namespaces (classes, modules) |
| `ghidra_search_bytes` | Hex byte pattern search with `??` wildcards |

### Annotations (persistent mutations)
| Tool | Description |
|------|-------------|
| `ghidra_rename_function` | Rename a function by name or address |
| `ghidra_rename_variable` | Rename a local variable within a function |
| `ghidra_set_comment` | Set a decompiler or disassembly comment at an address |
| `ghidra_set_function_prototype` | Set a C-style type signature |
| `ghidra_set_variable_type` | Change a variable's data type |
| `ghidra_define_struct` | Create or modify a struct data type |

## Testing

```bash
# Smoke test (loads /usr/bin/ls, decompiles a function)
GHIDRA_INSTALL_DIR=/opt/ghidra python tests/smoke_test.py

# Comprehensive test (exercises all tool categories)
GHIDRA_INSTALL_DIR=/opt/ghidra python tests/comprehensive_test.py
```

## Project Structure

```
ghidra-mcp/
  ghidra_mcp/
    __init__.py
    __main__.py        # Entry point with transport selection
    server.py          # FastMCP server setup
    core.py            # JVM init, project/program management
    utils.py           # Pagination, address parsing, helpers
    models/
      inputs.py        # Pydantic input models
    tools/
      session.py       # load_binary, get_program_info, run_analysis
      functions.py     # list, search, get, decompile, disassemble, call_graph, xrefs
      data.py          # strings, imports, exports, segments, namespaces
      search.py        # byte pattern search
      annotate.py      # rename, comment, prototype, retype, struct
  tests/
  specs/               # Design specs (reference)
  pyproject.toml
```

## Limitations

- Single binary at a time (`load_binary` swaps the active program)
- First load triggers full auto-analysis (30-120s for large binaries)
- PyGhidra must be installed in the same Python environment
- All Ghidra API calls are synchronous (JVM threading constraint)

## License

Apache 2.0 -- see [LICENSE](LICENSE).
