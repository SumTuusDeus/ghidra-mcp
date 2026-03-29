"""Utility functions: pagination, address parsing, error formatting."""


def paginate(items: list, offset: int = 0, limit: int = 100) -> dict:
    """Apply pagination to a list of items."""
    total = len(items)
    sliced = items[offset:offset + limit]
    next_offset = offset + len(sliced)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "count": len(sliced),
        "has_more": next_offset < total,
        "next_offset": next_offset if next_offset < total else None,
        "items": sliced,
    }


def parse_address(program, addr_str: str):
    """Parse a hex address string into a Ghidra Address object."""
    addr_str = addr_str.strip()
    if not addr_str.startswith("0x") and not addr_str.startswith("0X"):
        addr_str = "0x" + addr_str
    return program.getAddressFactory().getAddress(addr_str)


def resolve_function(program, name: str | None = None, address: str | None = None):
    """Resolve a function by name or address. Address takes priority."""
    fm = program.getFunctionManager()

    if address:
        addr = parse_address(program, address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")
        func = fm.getFunctionAt(addr)
        if func is None:
            func = fm.getFunctionContaining(addr)
        if func is None:
            raise ValueError(f"No function found at address {address}")
        return func

    if name:
        # Search by exact name
        from ghidra.program.model.symbol import SymbolTable
        sym_table = program.getSymbolTable()
        symbols = sym_table.getSymbols(name)
        for sym in symbols:
            func = fm.getFunctionAt(sym.getAddress())
            if func is not None:
                return func
        # Try iterating all functions as fallback
        func_iter = fm.getFunctions(True)
        while func_iter.hasNext():
            f = func_iter.next()
            if f.getName() == name:
                return f
        raise ValueError(f"No function found with name '{name}'")

    raise ValueError("Must provide either 'name' or 'address'")


def format_address(addr) -> str:
    """Format a Ghidra Address to a hex string."""
    return str(addr) if addr else ""


def clamp_limit(limit: int, max_val: int = 1000) -> int:
    """Clamp a limit value to the allowed maximum."""
    return max(1, min(limit, max_val))
