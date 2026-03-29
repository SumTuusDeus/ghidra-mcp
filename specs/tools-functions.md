# Function Tools

## ghidra_list_functions

**Purpose:** List all functions in the loaded program with pagination.

**Inputs:**
- `offset` (int, default=0): Pagination offset
- `limit` (int, default=100, max=1000): Max results to return
- `sort_by` (str, default="address"): Sort order - "address" or "name"

**Output:** Paginated list with total count, each entry: name, address, size, is_thunk, calling_convention

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_search_functions

**Purpose:** Search for functions whose name contains a given substring.

**Inputs:**
- `query` (str, required, min_length=1): Substring to search for (case-insensitive)
- `offset` (int, default=0): Pagination offset
- `limit` (int, default=100, max=1000): Max results

**Output:** Matching functions with name, address, size

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_get_function

**Purpose:** Get detailed info about a specific function by name or address.

**Inputs:**
- `name` (str, optional): Function name (exact match)
- `address` (str, optional): Function address (hex string)
- At least one of `name` or `address` must be provided. If both, address takes priority.

**Output:**
```json
{
  "name": "main",
  "address": "0x00105090",
  "signature": "int main(int argc, char **argv)",
  "size": 284,
  "calling_convention": "__stdcall",
  "is_thunk": false,
  "is_external": false,
  "parameter_count": 2,
  "local_variable_count": 8,
  "body_start": "0x00105090",
  "body_end": "0x001051ac"
}
```

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_decompile

**Purpose:** Decompile a function to C pseudocode.

**Inputs:**
- `name` (str, optional): Function name
- `address` (str, optional): Function address
- At least one required.

**Output:** The decompiled C code as a string. Includes the function signature, local variables, and body.

**Annotations:** readOnly=True, destructive=False, idempotent=True

**Notes:**
- Decompilation timeout: 60 seconds per function
- If decompilation fails, return error with reason

---

## ghidra_disassemble

**Purpose:** Get assembly listing for a function.

**Inputs:**
- `name` (str, optional): Function name
- `address` (str, optional): Function address
- At least one required.

**Output:** List of instructions, each with: address, mnemonic, operands, comment (if any)

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_get_call_graph

**Purpose:** Get the call graph for a function - what it calls and what calls it.

**Inputs:**
- `name` (str, optional): Function name
- `address` (str, optional): Function address
- `depth` (int, default=1, max=3): How many levels deep to traverse
- `direction` (str, default="both"): "callers", "callees", or "both"

**Output:**
```json
{
  "function": "main",
  "address": "0x00105090",
  "callers": [
    {"name": "_start", "address": "0x00104020", "ref_address": "0x00104055"}
  ],
  "callees": [
    {"name": "printf", "address": "0x00104700", "ref_address": "0x001050b0"},
    {"name": "exit", "address": "0x00104710", "ref_address": "0x001050ff"}
  ]
}
```

**Annotations:** readOnly=True, destructive=False, idempotent=True

**Notes:** Depth > 1 builds a tree. Keep depth low to avoid massive output on large binaries.

---

## ghidra_get_xrefs

**Purpose:** Get cross-references to or from a specific address.

**Inputs:**
- `address` (str, required): Target address (hex string)
- `direction` (str, default="to"): "to" (who references this address) or "from" (what this address references)
- `offset` (int, default=0): Pagination
- `limit` (int, default=100, max=1000): Max results

**Output:** List of references, each with: from_address, to_address, ref_type, containing_function (if applicable)

**Annotations:** readOnly=True, destructive=False, idempotent=True
