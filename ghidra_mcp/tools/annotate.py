"""Annotation/mutation tools: rename, comment, prototype, retype, struct."""

import json
from ghidra_mcp.server import mcp, get_ctx
from ghidra_mcp.utils import resolve_function, format_address, parse_address


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_rename_function(
    new_name: str,
    old_name: str | None = None,
    address: str | None = None,
) -> str:
    """Rename a function."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    func = resolve_function(program, old_name, address)

    from ghidra.program.model.symbol import SourceType

    prev_name = func.getName()
    tx = program.startTransaction("Rename function")
    success = False
    try:
        func.setName(new_name, SourceType.USER_DEFINED)
        success = True
    finally:
        program.endTransaction(tx, success)

    return json.dumps({
        "old_name": prev_name,
        "new_name": new_name,
        "address": format_address(func.getEntryPoint()),
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_rename_variable(
    old_name: str,
    new_name: str,
    function_name: str | None = None,
    function_address: str | None = None,
) -> str:
    """Rename a local variable within a function."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    func = resolve_function(program, function_name, function_address)

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.decompiler.component import DecompilerUtils
    from ghidra.program.model.symbol import SourceType

    decomp = ctx.get_decompiler()
    result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if result is None or not result.decompileCompleted():
        return json.dumps({"error": "Failed to decompile function"})

    high_func = result.getHighFunction()
    local_map = high_func.getLocalSymbolMap()

    target_sym = None
    sym_iter = local_map.getSymbols()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.getName() == old_name:
            target_sym = sym
            break

    if target_sym is None:
        return json.dumps({"error": f"Variable '{old_name}' not found in function '{func.getName()}'"})

    from ghidra.app.decompiler import HighFunctionDBUtil

    tx = program.startTransaction("Rename variable")
    success = False
    try:
        HighFunctionDBUtil.updateDBVariable(
            target_sym, new_name, None, SourceType.USER_DEFINED
        )
        success = True
    finally:
        program.endTransaction(tx, success)

    return json.dumps({
        "function": func.getName(),
        "old_name": old_name,
        "new_name": new_name,
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_set_comment(
    address: str,
    comment: str,
    comment_type: str = "decompiler",
) -> str:
    """Set a comment at a specific address."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    addr = parse_address(program, address)
    if addr is None:
        return json.dumps({"error": f"Invalid address: {address}"})

    from ghidra.program.model.listing import CodeUnit

    if comment_type == "decompiler":
        ct = CodeUnit.PRE_COMMENT
    else:
        ct = CodeUnit.EOL_COMMENT

    tx = program.startTransaction("Set comment")
    success = False
    try:
        code_unit = program.getListing().getCodeUnitAt(addr)
        if code_unit is None:
            code_unit = program.getListing().getCodeUnitContaining(addr)
        if code_unit is None:
            program.endTransaction(tx, False)
            return json.dumps({"error": f"No code unit at address {address}"})
        code_unit.setComment(ct, comment)
        success = True
    finally:
        program.endTransaction(tx, success)

    return json.dumps({
        "address": format_address(addr),
        "comment": comment,
        "type": comment_type,
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_set_function_prototype(
    address: str,
    prototype: str,
) -> str:
    """Set a function's full type signature from a C-style prototype."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    func = resolve_function(program, address=address)

    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.program.model.data import FunctionDefinitionDataType
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.program.model.symbol import SourceType

    dtm = program.getDataTypeManager()
    parser = FunctionSignatureParser(dtm, None)
    func_def = parser.parse(func.getSignature(), prototype)

    tx = program.startTransaction("Set function prototype")
    success = False
    try:
        cmd = ApplyFunctionSignatureCmd(
            func.getEntryPoint(), func_def, SourceType.USER_DEFINED
        )
        cmd.applyTo(program)
        success = True
    finally:
        program.endTransaction(tx, success)

    return json.dumps({
        "address": format_address(func.getEntryPoint()),
        "prototype": prototype,
        "applied": success,
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_set_variable_type(
    function_address: str,
    variable_name: str,
    new_type: str,
) -> str:
    """Change the data type of a local variable."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program
    func = resolve_function(program, address=function_address)

    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.decompiler import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType

    decomp = ctx.get_decompiler()
    result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if result is None or not result.decompileCompleted():
        return json.dumps({"error": "Failed to decompile function"})

    high_func = result.getHighFunction()
    local_map = high_func.getLocalSymbolMap()

    target_sym = None
    sym_iter = local_map.getSymbols()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.getName() == variable_name:
            target_sym = sym
            break

    if target_sym is None:
        return json.dumps({"error": f"Variable '{variable_name}' not found"})

    # Resolve data type
    dtm = program.getDataTypeManager()
    from ghidra.util.data import DataTypeParser
    data_type_parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
    resolved_type = data_type_parser.parse(new_type)

    if resolved_type is None:
        return json.dumps({"error": f"Cannot resolve type: {new_type}"})

    tx = program.startTransaction("Set variable type")
    success = False
    try:
        HighFunctionDBUtil.updateDBVariable(
            target_sym, None, resolved_type, SourceType.USER_DEFINED
        )
        success = True
    finally:
        program.endTransaction(tx, success)

    return json.dumps({
        "function": func.getName(),
        "variable": variable_name,
        "new_type": str(resolved_type),
    }, indent=2)


@mcp.tool(
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
)
async def ghidra_define_struct(
    name: str,
    fields: list[dict],
    category: str = "/user-defined",
    packed: bool = False,
) -> str:
    """Create or modify a struct data type."""
    ctx = get_ctx()
    ctx.require_program()
    program = ctx.program

    from ghidra.program.model.data import (
        StructureDataType,
        CategoryPath,
    )
    from ghidra.util.data import DataTypeParser

    dtm = program.getDataTypeManager()
    cat_path = CategoryPath(category)
    data_type_parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)

    # Create new struct
    struct = StructureDataType(cat_path, name, 0)
    if packed:
        struct.setPackingEnabled(True)

    for f in fields:
        field_type = data_type_parser.parse(f["type"])
        if field_type is None:
            return json.dumps({"error": f"Cannot resolve field type: {f['type']}"})
        comment = f.get("comment", None)
        struct.add(field_type, field_type.getLength(), f["name"], comment)

    tx = program.startTransaction("Define struct")
    success = False
    try:
        resolved = dtm.addDataType(struct, None)
        success = True
    finally:
        program.endTransaction(tx, success)

    # Build result
    result_fields = []
    for i in range(resolved.getNumComponents()):
        comp = resolved.getComponent(i)
        result_fields.append({
            "name": comp.getFieldName() or "",
            "type": str(comp.getDataType().getName()),
            "offset": comp.getOffset(),
            "size": comp.getLength(),
        })

    return json.dumps({
        "name": resolved.getName(),
        "category": str(resolved.getCategoryPath()),
        "size": resolved.getLength(),
        "fields": result_fields,
    }, indent=2)
