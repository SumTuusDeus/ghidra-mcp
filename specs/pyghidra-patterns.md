# PyGhidra Integration Patterns

## Critical Knowledge

This spec documents the PyGhidra API patterns the implementation MUST follow. PyGhidra 3.0.2 has specific quirks.

## JVM Initialization

PyGhidra starts the JVM via `pyghidra.start()`. This MUST happen once, before any Ghidra API calls.

```python
import pyghidra
import os

os.environ["GHIDRA_INSTALL_DIR"] = "/opt/ghidra"
pyghidra.start()  # Starts JVM, only call once
```

After `pyghidra.start()`, you can import Java classes:
```python
from ghidra.program.model.listing import Program
from ghidra.app.decompiler import DecompInterface
# etc.
```

## Loading a Binary (CORRECT pattern for 3.0.2)

The `open_program()` API is **deprecated**. Use `open_project()` + `program_context()`:

```python
from pyghidra import open_project
from pathlib import Path

project_location = Path("~/.ghidra-mcp/projects").expanduser()
project_location.mkdir(parents=True, exist_ok=True)

with open_project(
    binary_path="/usr/bin/ls",
    project_location=str(project_location),
    project_name="ls_project",
    analyze=True  # Run auto-analysis on import
) as project:
    program = project.openProgram("/", "ls", True)  # or similar
```

**IMPORTANT:** The exact API for open_project needs to be verified at implementation time. The test that worked used the deprecated open_program with explicit project_location:

```python
# This worked in our smoke test (deprecated but functional):
with pyghidra.open_program(
    "/usr/bin/ls",
    project_location="/tmp/ghidra_projects",
    project_name="test"
) as flat_api:
    program = flat_api.getCurrentProgram()
```

The implementor should test both approaches and use whichever is stable.

## Accessing Program Data

Once you have a `program` object:

```python
# Function manager
fm = program.getFunctionManager()
for func in fm.getFunctions(True):  # True = forward iteration
    print(func.getName(), func.getEntryPoint())

# Symbol table
sym_table = program.getSymbolTable()

# Memory
memory = program.getMemory()
for block in memory.getBlocks():
    print(block.getName(), block.getStart(), block.getEnd())

# Listing (instructions, data)
listing = program.getListing()
```

## Decompilation

```python
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(program)

# Decompile a specific function
result = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
if result and result.decompileCompleted():
    c_code = result.getDecompiledFunction().getC()
    high_function = result.getHighFunction()
```

## Transactions (for mutations)

ALL modifications to a program require a transaction:

```python
tx = program.startTransaction("Description of change")
try:
    # Do modifications here
    func.setName("new_name", SourceType.USER_DEFINED)
    success = True
except Exception as e:
    success = False
finally:
    program.endTransaction(tx, success)
```

## Address Resolution

```python
# Parse an address string
addr = program.getAddressFactory().getAddress("0x00104000")

# Get function at or containing an address
fm = program.getFunctionManager()
func = fm.getFunctionAt(addr)
if func is None:
    func = fm.getFunctionContaining(addr)
```

## Cross-References

```python
from ghidra.program.model.symbol import ReferenceManager

ref_manager = program.getReferenceManager()

# Refs TO an address
ref_iter = ref_manager.getReferencesTo(addr)
while ref_iter.hasNext():
    ref = ref_iter.next()
    from_addr = ref.getFromAddress()
    ref_type = ref.getReferenceType()

# Refs FROM an address
refs = ref_manager.getReferencesFrom(addr)  # Returns array, not iterator
```

## Thread Safety

- Ghidra is NOT thread-safe
- All Ghidra API calls should happen sequentially
- In the FastMCP async context, use synchronous calls within async wrappers
- Do NOT use asyncio.to_thread() for Ghidra calls - the JVM objects aren't thread-safe
- Instead, just call Ghidra synchronously inside the async tool functions (blocking is acceptable since we're single-binary, single-user)

## Saving Changes

After mutations, save the program:
```python
from ghidra.framework.model import DomainFile
program.save("reason for save", ConsoleTaskMonitor())
```

## Known Gotchas

1. `open_program()` is deprecated in PyGhidra 3.x - use `open_project()` if possible
2. Project location must be writable - don't try to create projects next to system binaries
3. Java iterators (FunctionIterator, etc.) follow Java iteration patterns - use `hasNext()` / `next()`
4. Some Ghidra classes need Swing thread for GUI operations (we don't need this headless)
5. `ConsoleTaskMonitor()` is the standard task monitor for headless operations
6. Function iteration with `getFunctions(True)` iterates forward by address; `False` iterates backward
7. The DecompInterface should be reused across calls for performance (don't recreate per-decompile)
