"""Search tools: byte pattern search."""

import json
from ghidra_mcp.server import mcp, get_ctx
from ghidra_mcp.utils import paginate, format_address

import jpype


def _parse_hex_pattern(pattern: str):
    """Parse a hex pattern like '48 89 e5 ?? 00' into Java byte[] and mask byte[].
    
    Returns (bytes_array, mask_array) as jpype Java byte arrays.
    ?? marks wildcard bytes (mask=0x00), concrete bytes get mask=0xff.
    """
    # Normalize: strip, collapse spaces, split into byte tokens
    clean = pattern.strip().replace("  ", " ")
    tokens = clean.split(" ") if " " in clean else [clean[i:i+2] for i in range(0, len(clean), 2)]
    
    search_bytes = []
    mask_bytes = []
    
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if token in ("??", "?"):
            search_bytes.append(0)
            mask_bytes.append(0)
        else:
            val = int(token, 16)
            search_bytes.append(val if val < 128 else val - 256)  # Java signed byte
            mask_bytes.append(-1)  # 0xff as signed byte
    
    # Convert to Java byte arrays
    JByte = jpype.JByte
    j_search = jpype.JArray(JByte)(search_bytes)
    j_mask = jpype.JArray(JByte)(mask_bytes)
    
    return j_search, j_mask


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_search_bytes(
    pattern: str, offset: int = 0, limit: int = 20
) -> str:
    """Search for a byte pattern in the binary's memory. Supports ?? wildcards.
    
    Pattern format: hex bytes separated by spaces. Use ?? for wildcard bytes.
    Examples: '48 89 e5', '48 ?? ?? 48 8b', 'ff 25 ?? ?? 00 00'
    """
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    memory = program.getMemory()
    fm = program.getFunctionManager()

    j_search, j_mask = _parse_hex_pattern(pattern)

    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()

    matches = []
    addr = memory.getMinAddress()
    end_addr = memory.getMaxAddress()

    while addr is not None and len(matches) < offset + limit + 100:
        addr = memory.findBytes(addr, end_addr, j_search, j_mask, True, monitor)
        if addr is None:
            break
        containing = fm.getFunctionContaining(addr)
        matches.append({
            "address": format_address(addr),
            "containing_function": containing.getName() if containing else None,
        })
        # Move to next byte to continue search
        try:
            addr = addr.add(1)
        except Exception:
            break

    return json.dumps(paginate(matches, offset, limit), indent=2)
