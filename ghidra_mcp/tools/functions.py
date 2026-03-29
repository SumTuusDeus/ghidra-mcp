"""Function tools: list, search, get, decompile, disassemble, call_graph, xrefs."""

import json
from ghidra_mcp.server import mcp, get_ctx
from ghidra_mcp.utils import paginate, resolve_function, format_address, parse_address


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_list_functions(
    offset: int = 0, limit: int = 100, sort_by: str = "address"
) -> str:
    """List all functions in the loaded program with pagination."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    fm = program.getFunctionManager()

    functions = []
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        functions.append({
            "name": f.getName(),
            "address": format_address(f.getEntryPoint()),
            "size": int(f.getBody().getNumAddresses()),
            "is_thunk": bool(f.isThunk()),
            "calling_convention": str(f.getCallingConventionName()),
        })

    if sort_by == "name":
        functions.sort(key=lambda x: x["name"].lower())

    return json.dumps(paginate(functions, offset, limit), indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_search_functions(
    query: str, offset: int = 0, limit: int = 100
) -> str:
    """Search for functions whose name contains a given substring (case-insensitive)."""
    ctx = get_ctx()
    ctx.require_program()
    fm = ctx.program.getFunctionManager()
    query_lower = query.lower()

    matches = []
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        if query_lower in f.getName().lower():
            matches.append({
                "name": f.getName(),
                "address": format_address(f.getEntryPoint()),
                "size": int(f.getBody().getNumAddresses()),
            })

    return json.dumps(paginate(matches, offset, limit), indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_get_function(
    name: str | None = None, address: str | None = None
) -> str:
    """Get detailed info about a specific function by name or address."""
    ctx = get_ctx()
    ctx.require_program()
    func = resolve_function(ctx.program, name, address)

    body = func.getBody()
    params = func.getParameters()
    local_vars = func.getLocalVariables()

    return json.dumps({
        "name": func.getName(),
        "address": format_address(func.getEntryPoint()),
        "signature": str(func.getSignature()),
        "size": int(body.getNumAddresses()),
        "calling_convention": str(func.getCallingConventionName()),
        "is_thunk": bool(func.isThunk()),
        "is_external": bool(func.isExternal()),
        "parameter_count": len(params),
        "local_variable_count": len(local_vars),
        "body_start": format_address(body.getMinAddress()),
        "body_end": format_address(body.getMaxAddress()),
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_decompile(
    name: str | None = None, address: str | None = None
) -> str:
    """Decompile a function to C pseudocode."""
    ctx = get_ctx()
    ctx.require_program()
    func = resolve_function(ctx.program, name, address)

    from ghidra.util.task import ConsoleTaskMonitor

    decomp = ctx.get_decompiler()
    result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())

    if result is None or not result.decompileCompleted():
        error_msg = result.getErrorMessage() if result else "Unknown error"
        return json.dumps({"error": f"Decompilation failed: {error_msg}"})

    c_code = result.getDecompiledFunction().getC()
    return json.dumps({
        "function": func.getName(),
        "address": format_address(func.getEntryPoint()),
        "decompiled_code": c_code,
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_disassemble(
    name: str | None = None, address: str | None = None
) -> str:
    """Get assembly listing for a function."""
    ctx = get_ctx()
    ctx.require_program()
    func = resolve_function(ctx.program, name, address)
    listing = ctx.program.getListing()

    instructions = []
    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        comment = inst.getComment(0)  # EOL_COMMENT = 0
        entry = {
            "address": format_address(inst.getAddress()),
            "mnemonic": str(inst.getMnemonicString()),
            "operands": str(inst),
        }
        if comment:
            entry["comment"] = str(comment)
        instructions.append(entry)

    return json.dumps({
        "function": func.getName(),
        "address": format_address(func.getEntryPoint()),
        "instruction_count": len(instructions),
        "instructions": instructions,
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_get_call_graph(
    name: str | None = None,
    address: str | None = None,
    depth: int = 1,
    direction: str = "both",
) -> str:
    """Get the call graph for a function - what it calls and what calls it."""
    ctx = get_ctx()
    ctx.require_program()
    func = resolve_function(ctx.program, name, address)
    program = ctx.program

    depth = max(1, min(depth, 3))

    def get_callees(f, d):
        if d <= 0:
            return []
        results = []
        called = f.getCalledFunctions(None)
        for callee in called:
            entry = {
                "name": callee.getName(),
                "address": format_address(callee.getEntryPoint()),
            }
            if d > 1:
                entry["callees"] = get_callees(callee, d - 1)
            results.append(entry)
        return results

    def get_callers(f, d):
        if d <= 0:
            return []
        results = []
        calling = f.getCallingFunctions(None)
        for caller in calling:
            entry = {
                "name": caller.getName(),
                "address": format_address(caller.getEntryPoint()),
            }
            if d > 1:
                entry["callers"] = get_callers(caller, d - 1)
            results.append(entry)
        return results

    result = {
        "function": func.getName(),
        "address": format_address(func.getEntryPoint()),
    }

    if direction in ("both", "callers"):
        result["callers"] = get_callers(func, depth)
    if direction in ("both", "callees"):
        result["callees"] = get_callees(func, depth)

    return json.dumps(result, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_get_xrefs(
    address: str,
    direction: str = "to",
    offset: int = 0,
    limit: int = 100,
) -> str:
    """Get cross-references to or from a specific address."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    addr = parse_address(program, address)
    if addr is None:
        return json.dumps({"error": f"Invalid address: {address}"})

    ref_manager = program.getReferenceManager()
    fm = program.getFunctionManager()
    refs = []

    if direction == "to":
        ref_iter = ref_manager.getReferencesTo(addr)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            from_addr = ref.getFromAddress()
            containing = fm.getFunctionContaining(from_addr)
            refs.append({
                "from_address": format_address(from_addr),
                "to_address": format_address(ref.getToAddress()),
                "ref_type": str(ref.getReferenceType()),
                "containing_function": containing.getName() if containing else None,
            })
    else:
        ref_array = ref_manager.getReferencesFrom(addr)
        for ref in ref_array:
            to_addr = ref.getToAddress()
            containing = fm.getFunctionContaining(to_addr)
            refs.append({
                "from_address": format_address(ref.getFromAddress()),
                "to_address": format_address(to_addr),
                "ref_type": str(ref.getReferenceType()),
                "containing_function": containing.getName() if containing else None,
            })

    return json.dumps(paginate(refs, offset, limit), indent=2)
