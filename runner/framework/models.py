from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any


class TestFlavor(str, Enum):
    BAD = "bad"
    GOOD = "good"


class DetectionOutcome(str, Enum):
    TRUE_POSITIVE = "TP"    # Vulnerability present & detected
    FALSE_POSITIVE = "FP"   # Vulnerability absent & falsely reported
    TRUE_NEGATIVE = "TN"    # Vulnerability absent & no error reported
    FALSE_NEGATIVE = "FN"   # Vulnerability present & missed by tool
    ERROR = "ERROR"         # Compilation or environment execution error


@dataclass
class TestCase:
    """Represents a single test case target."""
    path: Path
    cwe: str
    flavor: TestFlavor = TestFlavor.BAD
    description: str = ""
    stdin_data: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        data["flavor"] = self.flavor.value
        return data


@dataclass
class ExecutionMetrics:
    """Resource consumption and performance metrics."""
    wall_clock_time_s: float = 0.0
    user_time_s: float = 0.0
    sys_time_s: float = 0.0
    peak_rss_kb: Optional[int] = None
    exit_code: int = 0
    timed_out: bool = False


@dataclass
class ToolResult:
    """Outcome of running a detection tool on a specific test case."""
    tool_name: str
    test_case: TestCase
    detected: bool
    outcome: DetectionOutcome
    raw_stdout: str = ""
    raw_stderr: str = ""
    error_type: Optional[str] = None
    diagnostics: Dict[str, Any] = field(default_factory=dict)
    metrics: ExecutionMetrics = field(default_factory=ExecutionMetrics)
    repetition: int = 1
    tool_order: int = 1
    planned_repetitions: int = 1
    random_seed: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "test_case": self.test_case.to_dict(),
            "detected": self.detected,
            "outcome": self.outcome.value,
            "error_type": self.error_type,
            "metrics": asdict(self.metrics),
            "diagnostics": self.diagnostics,
            "raw_stderr": self.raw_stderr,
            "repetition": self.repetition,
            "used_for_classification": (
                self.repetition == 1 and self.outcome != DetectionOutcome.ERROR
            ),
            "tool_order": self.tool_order,
            "planned_repetitions": self.planned_repetitions,
            "random_seed": self.random_seed,
        }
