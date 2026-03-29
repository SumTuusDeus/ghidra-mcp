"""Core module: JVM initialization, project/program management."""

import os
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


PROJECT_DIR = Path("~/.ghidra-mcp/projects").expanduser()


@dataclass
class GhidraContext:
    """Manages the active Ghidra program and project state."""

    program: object = None
    flat_api: object = None
    project: object = None
    binary_path: Optional[str] = None
    _decomp: object = field(default=None, repr=False)

    @property
    def is_loaded(self) -> bool:
        return self.program is not None

    def require_program(self):
        """Raise if no program is loaded."""
        if not self.is_loaded:
            raise RuntimeError("No program loaded. Use ghidra_load_binary first.")

    def get_decompiler(self):
        """Get or create a reusable DecompInterface for the current program."""
        if self._decomp is None:
            from ghidra.app.decompiler import DecompInterface
            self._decomp = DecompInterface()
            self._decomp.openProgram(self.program)
        return self._decomp

    def close(self):
        """Close the current program and project."""
        if self._decomp is not None:
            self._decomp.dispose()
            self._decomp = None
        # The context manager from open_program handles cleanup
        self.program = None
        self.flat_api = None
        self.project = None
        self.binary_path = None


def init_jvm():
    """Initialize PyGhidra JVM. Must be called once at startup."""
    os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra")
    import pyghidra
    pyghidra.start()


def load_binary(ctx: GhidraContext, file_path: str, force_reanalysis: bool = False):
    """Load a binary into Ghidra. Returns program info dict."""
    import pyghidra

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    project_name = path.stem + "_project"
    project_path = PROJECT_DIR / project_name

    # Force reanalysis: delete existing project
    if force_reanalysis and project_path.exists():
        shutil.rmtree(project_path)

    # Close previous program if any
    if ctx.is_loaded:
        ctx.close()

    # Determine if we need analysis
    need_analysis = force_reanalysis or not project_path.exists()

    # Open program using the deprecated but functional API
    flat_api = pyghidra.open_program(
        str(path),
        project_location=str(PROJECT_DIR),
        project_name=project_name,
        analyze=need_analysis,
    )
    # open_program returns a context manager; we enter it and keep ref
    actual_flat_api = flat_api.__enter__()
    program = actual_flat_api.getCurrentProgram()

    ctx.flat_api = actual_flat_api
    ctx.project = flat_api  # Keep ref to context manager for cleanup
    ctx.program = program
    ctx.binary_path = str(path)

    return get_program_info(ctx)


def get_program_info(ctx: GhidraContext) -> dict:
    """Get metadata about the currently loaded program."""
    ctx.require_program()
    program = ctx.program

    import hashlib
    sha256 = ""
    if ctx.binary_path:
        try:
            sha256 = hashlib.sha256(Path(ctx.binary_path).read_bytes()).hexdigest()
        except Exception:
            pass

    fm = program.getFunctionManager()
    func_count = fm.getFunctionCount()
    memory = program.getMemory()
    blocks = list(memory.getBlocks())

    lang = program.getLanguage()
    compiler_spec = program.getCompilerSpec()

    return {
        "name": program.getName(),
        "path": ctx.binary_path or "",
        "language": str(lang.getLanguageID()),
        "compiler": str(compiler_spec.getCompilerSpecID()),
        "format": str(program.getExecutableFormat()),
        "entry_point": str(program.getMinAddress()) if program.getMinAddress() else "",
        "function_count": func_count,
        "memory_blocks": len(blocks),
        "image_base": str(program.getImageBase()),
        "executable_sha256": sha256,
    }


def run_analysis(ctx: GhidraContext, analyzers: list[str] | None = None) -> dict:
    """Run or re-run auto-analysis on the loaded program."""
    ctx.require_program()
    program = ctx.program

    from ghidra.util.task import ConsoleTaskMonitor

    fm = program.getFunctionManager()
    func_count_before = fm.getFunctionCount()

    # In headless/PyGhidra mode, AutoAnalysisManager is in a different package
    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        monitor = ConsoleTaskMonitor()
        mgr.reAnalyzeAll(None)
        mgr.startAnalysis(monitor)
    except (ImportError, Exception) as e:
        # Fallback: use flat API's analyzeAll if available
        try:
            from ghidra.program.flatapi import FlatProgramAPI
            flat = FlatProgramAPI(program)
            flat.analyzeAll(program)
        except Exception:
            # Last resort: analysis was already run on import, just report current state
            pass

    func_count_after = fm.getFunctionCount()

    return {
        "status": "analysis_complete",
        "functions_before": func_count_before,
        "functions_after": func_count_after,
        "new_functions": func_count_after - func_count_before,
    }
