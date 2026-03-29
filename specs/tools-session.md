# Session Management Tools

## ghidra_load_binary

**Purpose:** Load a binary file into Ghidra for analysis.

**Inputs:**
- `file_path` (str, required): Absolute path to the binary file
- `force_reanalysis` (bool, default=False): If True, delete existing project and re-import/re-analyze

**Behavior:**
1. Validate file exists and is readable
2. Check if a project already exists for this binary in `~/.ghidra-mcp/projects/`
3. If project exists and `force_reanalysis=False`: open existing project (skip analysis)
4. If project doesn't exist or `force_reanalysis=True`: import binary, run auto-analysis
5. Close any previously loaded program first
6. Store the active program/project in server state (lifespan context)

**Output:** Program info summary (name, architecture, compiler, format, entry point, function count)

**Annotations:** readOnly=False, destructive=False, idempotent=True

**Notes:**
- Auto-analysis can take 30-120 seconds for large binaries. This is expected.
- Supported formats: ELF, PE, Mach-O, raw binary, COFF, etc. (whatever Ghidra supports)

---

## ghidra_get_program_info

**Purpose:** Get metadata about the currently loaded binary.

**Inputs:** None

**Output:**
```json
{
  "name": "ls",
  "path": "/usr/bin/ls",
  "language": "x86/little/64/default",
  "compiler": "gcc",
  "format": "ELF",
  "entry_point": "0x00105090",
  "function_count": 412,
  "memory_blocks": 8,
  "image_base": "0x00100000",
  "executable_sha256": "abc123..."
}
```

**Annotations:** readOnly=True, destructive=False, idempotent=True

---

## ghidra_run_analysis

**Purpose:** Run or re-run Ghidra's auto-analysis on the loaded program.

**Inputs:**
- `analyzers` (list[str], optional): Specific analyzer names to run. If empty, runs all default analyzers.

**Behavior:**
1. Check a program is loaded
2. Run analysis via `AutoAnalysisManager` or `analyzeHeadless` equivalent
3. Return summary of what was found/updated

**Output:** Analysis summary (new functions found, references resolved, etc.)

**Annotations:** readOnly=False, destructive=False, idempotent=True
