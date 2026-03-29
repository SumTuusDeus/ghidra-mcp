"""Session management tools: load_binary, get_program_info, run_analysis."""

import json
from ghidra_mcp.server import mcp, get_ctx
from ghidra_mcp.core import load_binary, get_program_info, run_analysis


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_load_binary(file_path: str, force_reanalysis: bool = False) -> str:
    """Load a binary file into Ghidra for analysis. Returns program info summary."""
    ctx = get_ctx()
    info = load_binary(ctx, file_path, force_reanalysis)
    return json.dumps(info, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_get_program_info() -> str:
    """Get metadata about the currently loaded binary."""
    ctx = get_ctx()
    info = get_program_info(ctx)
    return json.dumps(info, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_run_analysis(analyzers: list[str] | None = None) -> str:
    """Run or re-run Ghidra's auto-analysis on the loaded program."""
    ctx = get_ctx()
    result = run_analysis(ctx, analyzers)
    return json.dumps(result, indent=2)
