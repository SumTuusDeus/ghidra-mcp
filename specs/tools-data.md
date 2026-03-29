# Data & Discovery Tools

## ghidra_list_strings

**Purpose:** List defined strings in the program with optional filtering.

**Inputs:**
- `filter` (str, optional): Substring filter on string content (case-insensitive)
- `offset` (int, default=0): Pagination offset
- `limit` (int, default=100, max=2000): Max results

**Output:** List of strings, each with: address, value, length, data_type

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_list_imports

**Purpose:** List imported symbols/functions.

**Inputs:**
- `offset` (int, default=0): Pagination offset
- `limit` (int, default=100, max=1000): Max results

**Output:** List of imports, each with: name, address, library (if known)

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_list_exports

**Purpose:** List exported symbols/functions.

**Inputs:**
- `offset` (int, default=0): Pagination offset
- `limit` (int, default=100, max=1000): Max results

**Output:** List of exports, each with: name, address

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_list_segments

**Purpose:** List memory segments/sections in the binary.

**Inputs:**
- `offset` (int, default=0): Pagination offset
- `limit` (int, default=100): Max results

**Output:** List of segments, each with: name, start_address, end_address, size, permissions (rwx), is_initialized

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_list_namespaces

**Purpose:** List all non-global namespaces (classes, modules) in the program.

**Inputs:**
- `offset` (int, default=0): Pagination offset
- `limit` (int, default=100, max=1000): Max results

**Output:** Sorted list of namespace names

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_search_bytes

**Purpose:** Search for a byte pattern in the binary's memory.

**Inputs:**
- `pattern` (str, required): Hex byte pattern, supports wildcards. Examples: "48 89 e5", "ff 15 ?? ?? ?? ??", "deadbeef"
- `offset` (int, default=0): Pagination
- `limit` (int, default=20, max=100): Max results

**Output:** List of matching addresses with surrounding context (function name if within one)

**Annotations:** readOnly=True, destructive=False, idempotent=True

**Notes:**
- Wildcards: `??` matches any single byte
- Pattern is space-delimited hex bytes
- Search covers all initialized memory blocks
