import logging
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("framework.compiler")


class CompilationError(Exception):
    """Raised when compilation fails."""
    pass


class Compiler:
    """Manages compilation of C and C++ benchmark test cases."""

    def __init__(self, compiler_bin: str = "clang", default_flags: Optional[List[str]] = None) -> None:
        self.compiler_bin = compiler_bin
        self.default_flags = default_flags or ["-g", "-O0", "-fno-omit-frame-pointer"]

    def compile(
        self,
        source_path: Path,
        output_binary: Path,
        extra_flags: Optional[List[str]] = None,
        defines: Optional[List[str]] = None,
        include_dirs: Optional[List[Path]] = None,
        extra_sources: Optional[List[Path]] = None,
    ) -> Path:
        """
        Compiles the given C or C++ source file into an executable binary.
        Automatically selects C++ compiler (clang++ / g++) when dealing with .cpp files.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        output_binary.parent.mkdir(parents=True, exist_ok=True)

        # Detect C++
        is_cpp = source_path.suffix.lower() in (".cpp", ".cc", ".cxx") or any(
            s.suffix.lower() in (".cpp", ".cc", ".cxx") for s in (extra_sources or [])
        )

        binary = self.compiler_bin
        if is_cpp:
            if binary == "clang":
                binary = "clang++"
            elif binary == "gcc":
                binary = "g++"

        cmd: List[str] = [binary]
        cmd.extend(self.default_flags)

        if is_cpp:
            cmd.extend(["-std=c++14", "-Wno-deprecated", "-Wno-macro-redefined"])

        if defines:
            for define in defines:
                cmd.append(f"-D{define}")

        if include_dirs:
            for inc in include_dirs:
                if inc.exists():
                    cmd.append(f"-I{inc}")

        if extra_flags:
            cmd.extend(extra_flags)

        # Main source file
        cmd.append(str(source_path))

        # Auxiliary sources (e.g. io.c for Juliet, companion files)
        if extra_sources:
            for extra in extra_sources:
                if extra.exists():
                    cmd.append(str(extra))

        cmd.extend(["-o", str(output_binary)])

        logger.debug("Executing compilation: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")

        if result.returncode != 0:
            logger.error("Compilation failed:\nSTDOUT: %s\nSTDERR: %s", result.stdout, result.stderr)
            raise CompilationError(
                f"Failed to compile {source_path.name} with return code {result.returncode}.\n"
                f"Compiler stderr:\n{result.stderr}"
            )

        return output_binary
