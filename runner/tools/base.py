import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple
from runner.framework.compiler import Compiler
from runner.framework.executor import Executor
from runner.framework.models import TestCase, ToolResult, DetectionOutcome, TestFlavor

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
JULIET_SUPPORT_DIR = REPO_ROOT / "benchmark" / "juliet" / "testcasesupport"


class ToolAdapter(ABC):
    """Abstract interface for all security analysis and baseline tools."""

    JULIET_CWE129_INPUT_PATTERN = re.compile(r"__CWE129_(?:fgets|fscanf)_", re.IGNORECASE)

    def __init__(self, name: str, compiler: Compiler, executor: Executor) -> None:
        self.name = name
        self.compiler = compiler
        self.executor = executor

    @abstractmethod
    def compile(self, test_case: TestCase, output_dir: Path) -> Path:
        """Compiles the test case binary with required instrumentation flags."""
        pass

    @abstractmethod
    def run(self, test_case: TestCase, binary_path: Path) -> ToolResult:
        """Executes the test case and evaluates diagnostic detection."""
        pass

    def evaluate_outcome(self, test_case: TestCase, detected: bool) -> DetectionOutcome:
        """
        Determines whether the result is a True Positive, False Positive,
        True Negative, or False Negative based on ground-truth flavor.
        """
        if test_case.flavor == TestFlavor.BAD:
            return DetectionOutcome.TRUE_POSITIVE if detected else DetectionOutcome.FALSE_NEGATIVE
        else:
            return DetectionOutcome.FALSE_POSITIVE if detected else DetectionOutcome.TRUE_NEGATIVE

    def get_stdin_data(self, test_case: TestCase) -> Optional[str]:
        """Return configured input or record a deterministic fixture for known Juliet sources."""
        if test_case.stdin_data is not None:
            return test_case.stdin_data

        is_juliet = "juliet" in str(test_case.path).lower()
        is_cwe121_index_source = test_case.cwe.upper() == "CWE121" and self.JULIET_CWE129_INPUT_PATTERN.search(
            test_case.path.name
        )
        if is_juliet and is_cwe121_index_source:
            test_case.stdin_data = "10\n"
        return test_case.stdin_data

    def get_compilation_params(self, test_case: TestCase) -> Tuple[List[str], List[Path], List[Path]]:
        """
        Detects if testcase is Juliet or synthetic and returns appropriate:
        (defines, include_dirs, extra_sources)
        """
        is_juliet = "juliet" in str(test_case.path).lower()

        if is_juliet:
            defines = ["INCLUDEMAIN"]
            if test_case.flavor == TestFlavor.BAD:
                defines.append("OMITGOOD")
            else:
                defines.append("OMITBAD")

            include_dirs = [JULIET_SUPPORT_DIR]
            extra_sources = [JULIET_SUPPORT_DIR / "io.c"]

            # Handle multi-file Juliet testcases (e.g. ..._22a.c needs ..._22b.c,
            # and ..._81a.cpp needs ..._81_bad.cpp, ..._81_goodB2G.cpp)
            stem = test_case.path.stem
            match = re.search(r"_(\d+)([a-zA-Z])$", stem)
            if match and match.group(2).lower() == "a":
                prefix = stem[:-1]  # remove 'a' -> e.g. ..._22 or ..._81
                companions = sorted([
                    f for f in test_case.path.parent.glob(f"{prefix}*")
                    if f != test_case.path and f.suffix.lower() in (".c", ".cpp")
                ])
                extra_sources.extend(companions)

            return defines, include_dirs, extra_sources
        else:
            defines = ["RUN_BAD"] if test_case.flavor == TestFlavor.BAD else ["RUN_GOOD"]
            return defines, [], []
