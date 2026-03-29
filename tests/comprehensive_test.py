"""Comprehensive smoke test: load binary, list functions, decompile, rename, verify."""

import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra")

import pyghidra
pyghidra.start()

from ghidra_mcp.core import GhidraContext, load_binary, get_program_info
from ghidra_mcp.utils import resolve_function, format_address, paginate, parse_address

passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS: {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL: {name} — {e}")
        failed += 1


def main():
    global passed, failed
    ctx = GhidraContext()

    # --- Session tests ---
    print("=== Session Tests ===")

    test("load binary", lambda: load_binary(ctx, "/usr/bin/ls"))

    def test_program_info():
        info = get_program_info(ctx)
        assert info["name"] == "ls"
        assert info["function_count"] > 0
        assert info["executable_sha256"]
    test("get program info", test_program_info)

    # --- Error handling ---
    print("\n=== Error Handling Tests ===")

    def test_no_program():
        empty = GhidraContext()
        try:
            empty.require_program()
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "No program loaded" in str(e)
    test("no program loaded error", test_no_program)

    def test_bad_file():
        try:
            load_binary(GhidraContext(), "/nonexistent/file")
            assert False, "Should have raised"
        except FileNotFoundError:
            pass
    test("bad file path error", test_bad_file)

    def test_bad_function_name():
        try:
            resolve_function(ctx.program, name="NONEXISTENT_FUNCTION_NAME_12345")
            assert False, "Should have raised"
        except ValueError:
            pass
    test("bad function name error", test_bad_function_name)

    def test_bad_address():
        try:
            resolve_function(ctx.program, address="0xDEADDEADDEADDEAD")
            assert False, "Should have raised"
        except (ValueError, Exception):
            pass
    test("bad address error", test_bad_address)

    def test_no_name_or_address():
        try:
            resolve_function(ctx.program)
            assert False, "Should have raised"
        except ValueError:
            pass
    test("no name or address error", test_no_name_or_address)

    # --- Function listing ---
    print("\n=== Function Tools Tests ===")

    def test_list_functions():
        fm = ctx.program.getFunctionManager()
        functions = []
        func_iter = fm.getFunctions(True)
        while func_iter.hasNext():
            f = func_iter.next()
            functions.append({"name": f.getName(), "address": format_address(f.getEntryPoint())})
        result = paginate(functions, 0, 10)
        assert result["total"] > 100
        assert result["count"] == 10
        assert len(result["items"]) == 10
    test("list functions with pagination", test_list_functions)

    def test_search_functions():
        fm = ctx.program.getFunctionManager()
        matches = []
        func_iter = fm.getFunctions(True)
        while func_iter.hasNext():
            f = func_iter.next()
            if "str" in f.getName().lower():
                matches.append(f.getName())
        assert len(matches) > 0, "Expected string-related functions"
    test("search functions", test_search_functions)

    def test_get_function():
        func = resolve_function(ctx.program, name="_DT_INIT")
        assert func.getName() == "_DT_INIT"
    test("get function by name", test_get_function)

    # --- Decompilation ---
    print("\n=== Decompilation Tests ===")

    def test_decompile():
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        func = resolve_function(ctx.program, name="_DT_INIT")
        decomp = ctx.get_decompiler()
        result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
        assert result and result.decompileCompleted()
        c_code = result.getDecompiledFunction().getC()
        assert "void" in c_code
    test("decompile function", test_decompile)

    # --- Disassembly ---
    def test_disassemble():
        func = resolve_function(ctx.program, name="_DT_INIT")
        listing = ctx.program.getListing()
        body = func.getBody()
        inst_iter = listing.getInstructions(body, True)
        count = 0
        while inst_iter.hasNext():
            inst_iter.next()
            count += 1
        assert count > 0
    test("disassemble function", test_disassemble)

    # --- Data tools ---
    print("\n=== Data Tools Tests ===")

    def test_segments():
        memory = ctx.program.getMemory()
        blocks = list(memory.getBlocks())
        assert len(blocks) > 0
        # Check first block has expected properties
        b = blocks[0]
        assert b.getName()
        assert b.getStart()
    test("list segments", test_segments)

    def test_strings():
        from ghidra.program.model.data import StringDataInstance
        listing = ctx.program.getListing()
        data_iter = listing.getDefinedData(True)
        str_count = 0
        while data_iter.hasNext() and str_count < 5:
            d = data_iter.next()
            sdi = StringDataInstance.getStringDataInstance(d)
            if sdi and sdi.getStringLength() > 0:
                str_count += 1
        assert str_count > 0
    test("list strings", test_strings)

    # --- Rename (mutation) ---
    print("\n=== Annotation Tests ===")

    def test_rename_function():
        from ghidra.program.model.symbol import SourceType
        func = resolve_function(ctx.program, name="_DT_INIT")
        original_name = func.getName()
        program = ctx.program

        # Rename
        tx = program.startTransaction("test rename")
        try:
            func.setName("_test_renamed", SourceType.USER_DEFINED)
        finally:
            program.endTransaction(tx, True)

        # Verify
        renamed = resolve_function(program, name="_test_renamed")
        assert renamed.getName() == "_test_renamed"

        # Rename back
        tx = program.startTransaction("test rename back")
        try:
            renamed.setName(original_name, SourceType.USER_DEFINED)
        finally:
            program.endTransaction(tx, True)

        restored = resolve_function(program, name=original_name)
        assert restored.getName() == original_name
    test("rename function and verify", test_rename_function)

    def test_set_comment():
        from ghidra.program.model.listing import CodeUnit
        func = resolve_function(ctx.program, name="_DT_INIT")
        addr = func.getEntryPoint()
        program = ctx.program

        tx = program.startTransaction("test comment")
        try:
            cu = program.getListing().getCodeUnitAt(addr)
            cu.setComment(CodeUnit.PRE_COMMENT, "Test comment from smoke test")
        finally:
            program.endTransaction(tx, True)

        cu = program.getListing().getCodeUnitAt(addr)
        comment = cu.getComment(CodeUnit.PRE_COMMENT)
        assert comment == "Test comment from smoke test"

        # Clean up
        tx = program.startTransaction("cleanup comment")
        try:
            cu.setComment(CodeUnit.PRE_COMMENT, None)
        finally:
            program.endTransaction(tx, True)
    test("set and read comment", test_set_comment)

    # --- Address parsing ---
    print("\n=== Utility Tests ===")

    def test_parse_address():
        addr1 = parse_address(ctx.program, "0x00104000")
        addr2 = parse_address(ctx.program, "00104000")
        assert str(addr1) == str(addr2)
    test("parse address with/without 0x prefix", test_parse_address)

    def test_paginate():
        items = list(range(50))
        result = paginate(items, offset=10, limit=5)
        assert result["total"] == 50
        assert result["offset"] == 10
        assert result["count"] == 5
        assert result["items"] == [10, 11, 12, 13, 14]
    test("paginate utility", test_paginate)

    # --- Summary ---
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)
    print("All tests PASSED")


if __name__ == "__main__":
    main()
