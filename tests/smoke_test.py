"""Smoke test: load /usr/bin/ls, verify functions found, decompile one."""

import os
import sys
import json

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra")

# Initialize PyGhidra JVM
import pyghidra
pyghidra.start()

from ghidra_mcp.core import GhidraContext, load_binary, get_program_info, run_analysis
from ghidra_mcp.utils import resolve_function, format_address


def test_load_binary():
    ctx = GhidraContext()

    print("=== Loading /usr/bin/ls ===")
    info = load_binary(ctx, "/usr/bin/ls")
    print(json.dumps(info, indent=2))
    assert info["function_count"] > 0, "Expected functions to be found"
    print(f"OK: Found {info['function_count']} functions")

    print("\n=== Getting program info ===")
    info2 = get_program_info(ctx)
    print(json.dumps(info2, indent=2))
    assert info2["name"], "Expected program name"
    print("OK: Program info retrieved")

    print("\n=== Listing functions (first 10) ===")
    fm = ctx.program.getFunctionManager()
    func_iter = fm.getFunctions(True)
    count = 0
    first_func = None
    while func_iter.hasNext() and count < 10:
        f = func_iter.next()
        if first_func is None and not f.isThunk():
            first_func = f
        print(f"  {f.getName()} @ {format_address(f.getEntryPoint())}")
        count += 1

    if first_func:
        print(f"\n=== Decompiling {first_func.getName()} ===")
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        decomp = DecompInterface()
        decomp.openProgram(ctx.program)
        result = decomp.decompileFunction(first_func, 60, ConsoleTaskMonitor())
        if result and result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
            lines = c_code.split("\n")
            for line in lines[:20]:
                print(f"  {line}")
            print("OK: Decompilation succeeded")
        else:
            print("WARNING: Decompilation failed")
        decomp.dispose()

    print("\n=== Smoke test PASSED ===")
    return True


if __name__ == "__main__":
    try:
        test_load_binary()
    except Exception as e:
        print(f"\nFAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
