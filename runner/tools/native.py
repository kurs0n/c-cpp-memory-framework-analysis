import logging
from pathlib import Path
from runner.framework.compiler import Compiler
from runner.framework.executor import Executor
from runner.framework.models import DetectionOutcome, TestCase, ToolResult
from runner.tools.base import ToolAdapter

logger = logging.getLogger("tools.native")


class NativeTool(ToolAdapter):
    """Uninstrumented baseline compilation and execution."""

    def __init__(self, compiler: Compiler, executor: Executor) -> None:
        super().__init__(name="native", compiler=compiler, executor=executor)

    def compile(self, test_case: TestCase, output_dir: Path) -> Path:
        out_bin = output_dir / f"{test_case.path.stem}_{test_case.flavor.value}_native"
        defines, include_dirs, extra_sources = self.get_compilation_params(test_case)

        return self.compiler.compile(
            source_path=test_case.path,
            output_binary=out_bin,
            extra_flags=["-O0"],
            defines=defines,
            include_dirs=include_dirs,
            extra_sources=extra_sources,
        )

    def run(self, test_case: TestCase, binary_path: Path) -> ToolResult:
        exit_code, stdout, stderr, metrics = self.executor.run(
            [str(binary_path)],
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

        # In native uninstrumented code, detection is strictly hardware/OS faults (SIGSEGV, SIGBUS, abort)
        detected = exit_code != 0
        error_type = "CRASH_SIGSEGV" if exit_code in (-11, 139) else ("NON_ZERO_EXIT" if exit_code != 0 else None)

        return ToolResult(
            tool_name=self.name,
            test_case=test_case,
            detected=detected,
            outcome=self.evaluate_outcome(test_case, detected),
            raw_stdout=stdout,
            raw_stderr=stderr,
            error_type=error_type,
            metrics=metrics,
        )
