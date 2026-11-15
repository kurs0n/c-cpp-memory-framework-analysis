import logging
import re
from pathlib import Path
from typing import Dict, Any, Optional

from runner.framework.compiler import Compiler
from runner.framework.executor import Executor
from runner.framework.models import DetectionOutcome, TestCase, ToolResult
from runner.tools.base import ToolAdapter

logger = logging.getLogger("tools.asan")


class ASanTool(ToolAdapter):
    """AddressSanitizer (ASan) instrumentation and diagnostic parser."""

    ASAN_ERROR_REGEX = re.compile(
        r"ERROR:\s+AddressSanitizer:\s+(attempting\s+double-free|attempting\s+free|[a-zA-Z0-9\-_]+)",
        re.IGNORECASE,
    )

    def __init__(self, compiler: Compiler, executor: Executor) -> None:
        super().__init__(name="asan", compiler=compiler, executor=executor)

    def compile(self, test_case: TestCase, output_dir: Path) -> Path:
        out_bin = output_dir / f"{test_case.path.stem}_{test_case.flavor.value}_asan"
        defines, include_dirs, extra_sources = self.get_compilation_params(test_case)

        asan_flags = [
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-g",
            "-O0",
        ]
        return self.compiler.compile(
            source_path=test_case.path,
            output_binary=out_bin,
            extra_flags=asan_flags,
            defines=defines,
            include_dirs=include_dirs,
            extra_sources=extra_sources,
        )

    def run(self, test_case: TestCase, binary_path: Path) -> ToolResult:
        env = {
            "ASAN_OPTIONS": "symbolize=1:detect_leaks=0:color=never",
        }
        exit_code, stdout, stderr, metrics = self.executor.run(
            [str(binary_path)],
            env=env,
            stdin_data=self.get_stdin_data(test_case),
        )

        if metrics.timed_out:
            return ToolResult(
                tool_name=self.name,
                test_case=test_case,
                detected=False,
                outcome=DetectionOutcome.ERROR,
                raw_stdout=stdout,
                raw_stderr=stderr,
                error_type="EXECUTION_TIMEOUT",
                metrics=metrics,
            )

        detected, error_type, diagnostics = self.parse_diagnostics(stderr)

        if not detected and (exit_code != 0 and "AddressSanitizer" in stderr):
            detected = True
            error_type = "UNKNOWN_ASAN_ERROR"

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

    def parse_diagnostics(self, stderr: str) -> tuple[bool, Optional[str], Dict[str, Any]]:
        diagnostics: Dict[str, Any] = {}
        match = self.ASAN_ERROR_REGEX.search(stderr)

        if not match:
            return False, None, diagnostics

        error_type = match.group(1).strip()
        diagnostics["error_type"] = error_type

        addr_match = re.search(r"on address (0x[0-9a-fA-F]+)", stderr)
        if addr_match:
            diagnostics["target_address"] = addr_match.group(1)

        op_match = re.search(r"(READ|WRITE) of size (\d+)", stderr)
        if op_match:
            diagnostics["operation"] = op_match.group(1)
            diagnostics["access_size"] = int(op_match.group(2))

        return True, error_type, diagnostics
