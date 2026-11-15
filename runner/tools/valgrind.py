import logging
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from runner.framework.compiler import Compiler
from runner.framework.executor import Executor
from runner.framework.models import DetectionOutcome, TestCase, ToolResult
from runner.tools.base import ToolAdapter

logger = logging.getLogger("tools.valgrind")


class ValgrindTool(ToolAdapter):
    """Valgrind Memcheck runner and diagnostic log analyzer."""

    VALGRIND_ERROR_REGEX = re.compile(
        r"==\d+==\s+(Invalid read|Invalid write|Invalid free\(\)|Mismatched free\(\)|Use of uninitialised value)",
        re.IGNORECASE,
    )
    LEAK_SUMMARY_REGEX = re.compile(
        r"==\d+==\s+(definitely lost|indirectly lost|possibly lost|still reachable|suppressed):"
        r"\s+([\d,]+) bytes in ([\d,]+) blocks",
        re.IGNORECASE,
    )

    def __init__(self, compiler: Compiler, executor: Executor) -> None:
        super().__init__(name="valgrind", compiler=compiler, executor=executor)
        self.valgrind_bin = shutil.which("valgrind")

    def compile(self, test_case: TestCase, output_dir: Path) -> Path:
        out_bin = output_dir / f"{test_case.path.stem}_{test_case.flavor.value}_valgrind"
        defines, include_dirs, extra_sources = self.get_compilation_params(test_case)

        return self.compiler.compile(
            source_path=test_case.path,
            output_binary=out_bin,
            extra_flags=["-g", "-O0"],
            defines=defines,
            include_dirs=include_dirs,
            extra_sources=extra_sources,
        )

    def run(self, test_case: TestCase, binary_path: Path) -> ToolResult:
        stdin_data = self.get_stdin_data(test_case)
        if not self.valgrind_bin:
            logger.warning("Valgrind binary not found in PATH.")
            return ToolResult(
                tool_name=self.name,
                test_case=test_case,
                detected=False,
                outcome=DetectionOutcome.ERROR,
                raw_stderr="Valgrind is not installed or not available in PATH (Run inside Ubuntu ARM64 environment).",
                error_type="VALGRIND_NOT_FOUND",
            )

        cmd = [
            self.valgrind_bin,
            "--tool=memcheck",
            "--leak-check=full",
            "--errors-for-leak-kinds=none",
            "--error-exitcode=101",
            "--track-origins=yes",
            str(binary_path),
        ]

        exit_code, stdout, stderr, metrics = self.executor.run(
            cmd,
            stdin_data=stdin_data,
        )
        if metrics.timed_out:
            _, _, diagnostics = self.parse_diagnostics(stderr, exit_code)
            return ToolResult(
                tool_name=self.name,
                test_case=test_case,
                detected=False,
                outcome=DetectionOutcome.ERROR,
                raw_stdout=stdout,
                raw_stderr=stderr,
                error_type="EXECUTION_TIMEOUT",
                diagnostics=diagnostics,
                metrics=metrics,
            )

        detected, error_type, diagnostics = self.parse_diagnostics(stderr, exit_code)

        return ToolResult(
            tool_name=self.name,
            test_case=test_case,
            detected=detected,
            outcome=self.evaluate_outcome(test_case, detected),
            raw_stdout=stdout,
            raw_stderr=stderr,
            error_type=error_type,
            diagnostics=diagnostics,
            metrics=metrics,
        )

    def parse_diagnostics(self, stderr: str, exit_code: int) -> tuple[bool, Optional[str], Dict[str, Any]]:
        diagnostics: Dict[str, Any] = {}
        leak_summary = {
            match.group(1).lower().replace(" ", "_"): {
                "bytes": int(match.group(2).replace(",", "")),
                "blocks": int(match.group(3).replace(",", "")),
            }
            for match in self.LEAK_SUMMARY_REGEX.finditer(stderr)
        }
        if leak_summary:
            diagnostics["leak_summary"] = leak_summary

        match = self.VALGRIND_ERROR_REGEX.search(stderr)

        if match:
            error_type = match.group(1).strip()
            diagnostics["error_type"] = error_type
            return True, error_type, diagnostics

        if exit_code == 101:
            diagnostics["error_exitcode"] = 101
            return True, "MEMCHECK_DETECTED_ERROR", diagnostics

        leaked_bytes = sum(
            leak_summary.get(kind, {}).get("bytes", 0)
            for kind in ("definitely_lost", "indirectly_lost", "possibly_lost")
        )
        return False, "MEMORY_LEAK" if leaked_bytes else None, diagnostics
