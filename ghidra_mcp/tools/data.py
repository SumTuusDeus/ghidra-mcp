"""Data & discovery tools: strings, imports, exports, segments, namespaces."""

import json
from ghidra_mcp.server import mcp, get_ctx
from ghidra_mcp.utils import paginate, format_address


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_list_strings(
    filter: str | None = None, offset: int = 0, limit: int = 100
) -> str:
    """List defined strings in the program with optional filtering."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    listing = program.getListing()

    from ghidra.program.model.data import StringDataInstance

    strings = []
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        d = data_iter.next()
        sdi = StringDataInstance.getStringDataInstance(d)
        if sdi is None or sdi.getStringLength() <= 0:
            continue
        try:
            value = sdi.getStringValue()
            if value is None:
                continue
            value = str(value)
        except Exception:
            continue

        if filter and filter.lower() not in value.lower():
            continue

        strings.append({
            "address": format_address(d.getAddress()),
            "value": value,
            "length": sdi.getStringLength(),
            "data_type": str(d.getDataType().getName()),
        })

    return json.dumps(paginate(strings, offset, limit), indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_list_imports(offset: int = 0, limit: int = 100) -> str:
    """List imported symbols/functions."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    sym_table = program.getSymbolTable()

    from ghidra.program.model.symbol import SourceType

    imports = []
    ext_symbols = sym_table.getExternalSymbols()
    while ext_symbols.hasNext():
        sym = ext_symbols.next()
        ext_loc = sym.getExternalLocation() if hasattr(sym, 'getExternalLocation') else None
        library = ""
        if ext_loc:
            try:
                library = str(ext_loc.getLibraryName())
            except Exception:
                pass
        imports.append({
            "name": sym.getName(),
            "address": format_address(sym.getAddress()),
            "library": library,
        })

    return json.dumps(paginate(imports, offset, limit), indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_list_exports(offset: int = 0, limit: int = 100) -> str:
    """List exported symbols/functions."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    sym_table = program.getSymbolTable()

    from ghidra.program.model.symbol import SymbolType

    exports = []
    sym_iter = sym_table.getAllSymbols(True)
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.isExternalEntryPoint():
            exports.append({
                "name": sym.getName(),
                "address": format_address(sym.getAddress()),
            })

    return json.dumps(paginate(exports, offset, limit), indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_list_segments(offset: int = 0, limit: int = 100) -> str:
    """List memory segments/sections in the binary."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    memory = program.getMemory()

    segments = []
    for block in memory.getBlocks():
        segments.append({
            "name": block.getName(),
            "start_address": format_address(block.getStart()),
            "end_address": format_address(block.getEnd()),
            "size": int(block.getSize()),
            "permissions": (
                ("r" if block.isRead() else "-")
                + ("w" if block.isWrite() else "-")
                + ("x" if block.isExecute() else "-")
            ),
            "is_initialized": bool(block.isInitialized()),
        })

    return json.dumps(paginate(segments, offset, limit), indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_list_namespaces(offset: int = 0, limit: int = 100) -> str:
    """List all non-global namespaces (classes, modules) in the program."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    sym_table = program.getSymbolTable()

    namespaces = set()
    ns_iter = sym_table.getClassNamespaces()
    while ns_iter.hasNext():
        ns = ns_iter.next()
        namespaces.add(ns.getName(True))

    # Also include non-class namespaces
    from ghidra.program.model.symbol import SymbolType
    all_syms = sym_table.getSymbolIterator("*", True)
    while all_syms.hasNext():
        sym = all_syms.next()
        ns = sym.getParentNamespace()
        if ns and not ns.isGlobal():
            namespaces.add(ns.getName(True))

    sorted_ns = sorted(namespaces)
    return json.dumps(paginate(sorted_ns, offset, limit), indent=2)
