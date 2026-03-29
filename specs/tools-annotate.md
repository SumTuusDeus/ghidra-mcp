# Annotation & Mutation Tools

These tools modify the Ghidra project state. Changes persist to the project file on disk.

## ghidra_rename_function

**Purpose:** Rename a function.

**Inputs:**
- `old_name` (str, optional): Current function name
- `address` (str, optional): Function address (takes priority if both given)
- `new_name` (str, required, min_length=1, max_length=255): New name for the function

**Behavior:** Wraps in a Ghidra transaction. Sets SourceType.USER_DEFINED.

**Output:** Confirmation with old name, new name, address

**Annotations:** readOnly=False, destructive=False, idempotent=True

---

## ghidra_rename_variable

**Purpose:** Rename a local variable within a function.

**Inputs:**
- `function_name` (str, optional): Function containing the variable
- `function_address` (str, optional): Function address (alternative to name)
- `old_name` (str, required): Current variable name
- `new_name` (str, required): New variable name

**Behavior:**
1. Decompile the function to get HighFunction
2. Find the variable in the LocalSymbolMap
3. Use HighFunctionDBUtil.updateDBVariable to rename
4. Handle commit if variable is a parameter

**Output:** Confirmation or error

**Annotations:** readOnly=False, destructive=False, idempotent=True

---

## ghidra_set_comment

**Purpose:** Set a comment at a specific address.

**Inputs:**
- `address` (str, required): Address to comment
- `comment` (str, required): Comment text
- `comment_type` (str, default="decompiler"): "decompiler" (PRE_COMMENT) or "disassembly" (EOL_COMMENT)

**Output:** Confirmation

**Annotations:** readOnly=False, destructive=False, idempotent=True

---

## ghidra_set_function_prototype

**Purpose:** Set a function's full type signature.

**Inputs:**
- `address` (str, required): Function address
- `prototype` (str, required): C-style prototype, e.g. "int main(int argc, char **argv)"

**Behavior:**
1. Parse prototype using Ghidra's FunctionSignatureParser
2. Apply via ApplyFunctionSignatureCmd
3. Return success/failure with details

**Output:** Confirmation with parsed signature details, or parse error

**Annotations:** readOnly=False, destructive=False, idempotent=True

---

## ghidra_set_variable_type

**Purpose:** Change the data type of a local variable.

**Inputs:**
- `function_address` (str, required): Function address
- `variable_name` (str, required): Variable to retype
- `new_type` (str, required): New type name (e.g., "int", "char *", "DWORD", struct names)

**Behavior:**
1. Decompile function to get HighFunction
2. Find variable in LocalSymbolMap
3. Resolve data type from Ghidra's DataTypeManager (search all categories)
4. Handle pointer types (PVOID, PCHAR, etc.)
5. Apply via HighFunctionDBUtil.updateDBVariable

**Output:** Confirmation with resolved type details

**Annotations:** readOnly=False, destructive=False, idempotent=True

---

## ghidra_define_struct

**Purpose:** Create or modify a struct data type.

**Inputs:**
- `name` (str, required): Struct name
- `fields` (list[dict], required): List of fields, each with:
  - `name` (str): Field name
  - `type` (str): Field type (e.g., "int", "char[32]", "void *")
  - `comment` (str, optional): Field comment
- `category` (str, default="/user-defined"): DataType category path
- `packed` (bool, default=False): Whether to pack the struct (no padding)

**Behavior:**
1. Check if struct already exists (update) or create new
2. Resolve each field type from DataTypeManager
3. Build StructureDataType with appropriate field sizes
4. Add to the program's DataTypeManager

**Output:** Struct definition with name, total size, field offsets

**Annotations:** readOnly=False, destructive=False, idempotent=True

**Notes:** This is critical for RE workflows - most binaries use structs that Ghidra doesn't auto-detect.
