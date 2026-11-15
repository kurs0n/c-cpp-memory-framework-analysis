#!/usr/bin/env python3
"""
CLI entry point for Memory Safety Benchmarking Framework.
Author: Patryk Kurek (Student ID: 414887)
"""
import argparse
import fnmatch
import logging
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Type

# Add root directory to sys.path to allow runner.* imports
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from runner.framework.compiler import Compiler, CompilationError
from runner.framework.analysis import generate_analysis
from runner.framework.executor import Executor
from runner.framework.models import (
    DetectionOutcome,
    ExecutionMetrics,
    TestCase,
    TestFlavor,
    ToolResult,
)
from runner.framework.reporter import Reporter
from runner.tools.base import ToolAdapter
from runner.tools.native import NativeTool
from runner.tools.asan import ASanTool
from runner.tools.valgrind import ValgrindTool

AVAILABLE_TOOLS: Dict[str, Type[ToolAdapter]] = {
    "native": NativeTool,
    "asan": ASanTool,
    "valgrind": ValgrindTool,
}


def _error_result(
    tool_name: str,
    test_case: TestCase,
    error_type: str,
    message: str,
    *,
    repetition: int = 0,
    tool_order: int = 0,
    planned_repetitions: int = 1,
    random_seed: Optional[int] = None,
) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        test_case=test_case,
        detected=False,
        outcome=DetectionOutcome.ERROR,
        raw_stderr=message,
        error_type=error_type,
        metrics=ExecutionMetrics(exit_code=1),
        repetition=repetition,
        tool_order=tool_order,
        planned_repetitions=planned_repetitions,
        random_seed=random_seed,
    )


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%H:%M:%S",
    )


def extract_cwe_from_filename(file_path: Path) -> str:
    """Extracts CWE identifier from file naming conventions (e.g. CWE121, cwe121)."""
    stem = file_path.stem.upper()
    for part in stem.split("_"):
        if part.startswith("CWE") and any(c.isdigit() for c in part):
            return part
    return "CWE-UNKNOWN"


def is_primary_test_file(path: Path) -> bool:
    """
    Filters out helper files:
    - Excludes 'testcasesupport' infrastructure (e.g. io.c, std_thread.c)
    - Excludes multi-file Juliet companion sinks (e.g. ..._22b.c, ..._52c.c, ..._81_bad.cpp)
      which do not contain a main() function and are linked into the primary entrypoint (e.g. ..._81a.cpp)
    """
    if "testcasesupport" in path.parts:
        return False

    if path.suffix.lower() not in (".c", ".cpp"):
        return False

    stem = path.stem

    # Exclude companion single-letter sinks (e.g. 22b, 52c, 72b)
    match = re.search(r"_(\d+)([a-zA-Z])$", stem)
    if match and match.group(2).lower() != "a":
        return False

    # Exclude companion bad/good sinks (e.g. 81_bad, 81_goodB2G, 82_goodG2B)
    if re.search(r"_(\d+)_(bad|good)", stem):
        return False

    # Robust check: verify that this file contains a main() function definition
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        if "main(" not in content and "main (" not in content:
            return False
    except Exception:
        return False

    return True


def run_single(args: argparse.Namespace) -> int:
    source_file = Path(args.file).resolve()
    if not source_file.is_file():
        logging.error("Source file not found: %s", source_file)
        return 1

    cwe = args.cwe or extract_cwe_from_filename(source_file)
    flavor = TestFlavor(args.flavor)
    test_case = TestCase(path=source_file, cwe=cwe, flavor=flavor)

    compiler = Compiler()
    executor = Executor(timeout_seconds=args.timeout)

    tools_to_run: List[str] = [args.tool] if args.tool != "all" else list(AVAILABLE_TOOLS.keys())
    results: List[ToolResult] = []

    with tempfile.TemporaryDirectory(prefix="mem_bench_build_") as tmp_dir:
        build_dir = Path(tmp_dir)
        for tool_name in tools_to_run:
            adapter_cls = AVAILABLE_TOOLS[tool_name]
            adapter = adapter_cls(compiler=compiler, executor=executor)

            logging.info("Compiling %s with %s...", source_file.name, tool_name)
            try:
                bin_path = adapter.compile(test_case=test_case, output_dir=build_dir)
            except CompilationError as e:
                logging.error("Build failure for %s with %s: %s", test_case.path.name, tool_name, e)
                results.append(
                    _error_result(
                        tool_name,
                        test_case,
                        "COMPILATION_ERROR",
                        str(e),
                    )
                )
                continue

            logging.info("Running testcase with %s (%s)...", tool_name, flavor.value)
            try:
                res = adapter.run(test_case=test_case, binary_path=bin_path)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                logging.error("Error executing %s with %s: %s", test_case.path.name, tool_name, exc)
                res = _error_result(
                    tool_name,
                    test_case,
                    "EXECUTION_ERROR",
                    str(exc),
                )
            results.append(res)

    Reporter.print_summary(results)

    if args.json:
        Reporter.export_json(results, Path(args.json))
    if args.csv:
        Reporter.export_csv(results, Path(args.csv))

    return 0


def run_benchmark(args: argparse.Namespace) -> int:
    if args.repetitions < 1:
        logging.error("--repetitions must be at least one")
        return 1

    target_dir = Path(args.dir).resolve()
    if not target_dir.is_dir():
        logging.error("Benchmark directory does not exist: %s", target_dir)
        return 1

    tool_names = list(
        dict.fromkeys(
            t.strip() for t in args.tools.split(",") if t.strip() in AVAILABLE_TOOLS
        )
    )
    if not tool_names:
        logging.error("No valid tools specified. Available: %s", list(AVAILABLE_TOOLS.keys()))
        return 1

    # Discover candidate files
    raw_files = sorted(list(target_dir.glob("**/*.c")) + list(target_dir.glob("**/*.cpp")))
    c_files = [f for f in raw_files if is_primary_test_file(f)]

    # Apply optional exclude filter (default: *socket* to avoid blocking on network calls)
    if args.exclude:
        c_files = [f for f in c_files if not fnmatch.fnmatch(f.name, args.exclude)]

    # Apply optional filter (e.g. *01.c or *wcs*)
    if args.filter:
        c_files = [f for f in c_files if fnmatch.fnmatch(f.name, args.filter)]

    # Apply optional CWE filter
    if args.cwe:
        target_cwe = args.cwe.upper()
        c_files = [f for f in c_files if target_cwe in extract_cwe_from_filename(f)]

    # Apply limit
    if args.limit and args.limit > 0:
        c_files = c_files[:args.limit]

    if not c_files:
        logging.warning("No matching C/C++ test files found in %s", target_dir)
        return 0

    logging.info(
        "Benchmarking %d selected testcases in %s (Tools: %s, repetitions: %d)",
        len(c_files),
        target_dir.name,
        ", ".join(tool_names),
        args.repetitions,
    )

    compiler = Compiler()
    executor = Executor(timeout_seconds=args.timeout)
    results: List[ToolResult] = []
    rng = random.Random(args.seed)

    flavors = [TestFlavor.BAD, TestFlavor.GOOD] if args.both_flavors else [TestFlavor(args.flavor)]

    with tempfile.TemporaryDirectory(prefix="mem_bench_suite_") as tmp_dir:
        build_dir = Path(tmp_dir)
        for idx, src in enumerate(c_files, 1):
            cwe = extract_cwe_from_filename(src)
            logging.info("[%d/%d] Testing %s (%s)", idx, len(c_files), src.name, cwe)
            for flavor in flavors:
                test_case = TestCase(path=src, cwe=cwe, flavor=flavor)
                adapters: Dict[str, ToolAdapter] = {
                    tool_name: AVAILABLE_TOOLS[tool_name](
                        compiler=compiler, executor=executor
                    )
                    for tool_name in tool_names
                }
                binaries: Dict[str, Path] = {}
                for tool_name in tool_names:
                    try:
                        binaries[tool_name] = adapters[tool_name].compile(
                            test_case=test_case, output_dir=build_dir
                        )
                    except (CompilationError, OSError) as exc:
                        logging.error(
                            "Build failure for %s with %s: %s",
                            src.name,
                            tool_name,
                            exc,
                        )
                        results.append(
                            _error_result(
                                tool_name,
                                test_case,
                                "COMPILATION_ERROR",
                                str(exc),
                                planned_repetitions=args.repetitions,
                                random_seed=args.seed,
                            )
                        )

                runnable_tools = list(binaries)
                for repetition in range(1, args.repetitions + 1):
                    run_order = runnable_tools.copy()
                    rng.shuffle(run_order)
                    for tool_order, tool_name in enumerate(run_order, start=1):
                        try:
                            result = adapters[tool_name].run(
                                test_case=test_case,
                                binary_path=binaries[tool_name],
                            )
                        except (
                            OSError,
                            subprocess.SubprocessError,
                            ValueError,
                        ) as exc:
                            logging.error(
                                "Execution failed for %s with %s on repetition %d: %s",
                                src.name,
                                tool_name,
                                repetition,
                                exc,
                            )
                            result = _error_result(
                                tool_name,
                                test_case,
                                "EXECUTION_ERROR",
                                str(exc),
                                repetition=repetition,
                                tool_order=tool_order,
                                planned_repetitions=args.repetitions,
                                random_seed=args.seed,
                            )
                        result.repetition = repetition
                        result.tool_order = tool_order
                        result.planned_repetitions = args.repetitions
                        result.random_seed = args.seed
                        results.append(result)

    Reporter.print_benchmark_summary(results)

    if args.json:
        Reporter.export_json(results, Path(args.json))
    if args.csv:
        Reporter.export_csv(results, Path(args.csv))

    return 0


def run_analysis(args: argparse.Namespace) -> int:
    try:
        summary = generate_analysis(
            Path(args.input),
            Path(args.output_dir),
            confidence_level=args.confidence_level,
        )
    except (OSError, TypeError, ValueError) as exc:
        logging.error("Unable to analyze benchmark results: %s", exc)
        return 1

    def format_statistic(
        statistics: dict[str, object],
        value_key: str,
        interval_key: str,
        suffix: str = "x",
    ) -> str:
        value = statistics.get(value_key)
        if not isinstance(value, (int, float)):
            return "N/A"
        interval = statistics.get(interval_key)
        formatted = f"{value:.2f}{suffix}"
        if isinstance(interval, dict):
            lower = interval.get("lower")
            upper = interval.get("upper")
            if isinstance(lower, (int, float)) and isinstance(upper, (int, float)):
                formatted += f" [{lower:.2f}, {upper:.2f}]"
        return formatted

    print("\nBENCHMARK ANALYSIS")
    print(f"Confidence level: {summary['confidence_level']:.0%}")
    print(
        f"{'Tool':<12} | {'TP':>6} | {'FP':>6} | {'TN':>6} | "
        f"{'FN':>6} | {'Errors':>6} | {'Accuracy':>10}"
    )
    for tool, data in summary["by_tool"].items():
        counts = data["confusion_matrix"]
        accuracy = data["metrics"]["accuracy"]["estimate"]
        accuracy_text = f"{accuracy:.1%}" if accuracy is not None else "N/A"
        print(
            f"{tool:<12} | {counts['TP']:>6} | {counts['FP']:>6} | "
            f"{counts['TN']:>6} | {counts['FN']:>6} | "
            f"{data['execution_errors_excluded']:>6} | {accuracy_text:>10}"
        )
    print("\nRUN-TO-RUN DETECTION STABILITY BY FLAVOR")
    print(
        f"{'Tool':<12} | {'Flavor':<6} | {'Cases':>6} | {'Runs':>6} | "
        f"{'Unstable':>8} | {'Mean run detection':>18}"
    )
    for flavor, flavor_data in summary["by_flavor"].items():
        for tool, data in flavor_data["by_tool"].items():
            stability = data["run_detection_consistency"]
            flavor_rate = stability["per_testcase_detection_rate_by_flavor"].get(
                flavor, {}
            )
            rate = flavor_rate.get("average")
            rate_text = f"{rate:.1%}" if rate is not None else "N/A"
            print(
                f"{tool:<12} | {flavor:<6} | {data['sample_count']:>6} | "
                f"{stability['execution_count']:>6} | "
                f"{stability['unstable_testcases']:>8} | {rate_text:>18}"
            )
    print("\nPAIRED WALL-CLOCK SLOWDOWN VS NATIVE")
    for flavor, flavor_data in summary["overhead_vs_native"]["by_flavor"].items():
        print(f"\n{flavor.upper()} flavor")
        print(
            f"{'Tool':<12} | {'Cases':>6} | {'Paired runs':>11} | "
            f"{'Median slowdown':>28} | "
            f"{'Mean slowdown':>28} | {'Geometric mean':>28}"
        )
        for tool, data in flavor_data["wall_clock_time_s"]["by_tool"].items():
            slowdown = data["slowdown_factor"]
            median_text = format_statistic(
                slowdown, "median", "median_confidence_interval"
            )
            mean_text = format_statistic(
                slowdown, "average", "confidence_interval"
            )
            geometric_mean_text = format_statistic(
                slowdown, "geometric_mean", "geometric_mean_confidence_interval"
            )
            print(
                f"{tool:<12} | {data['matched_testcases']:>6} | "
                f"{data['paired_repetitions']:>11} | "
                f"{median_text:>28} | {mean_text:>28} | "
                f"{geometric_mean_text:>28}"
            )
    print("\nPAIRED PEAK RSS MULTIPLIER VS NATIVE")
    for flavor, flavor_data in summary["overhead_vs_native"]["by_flavor"].items():
        print(f"\n{flavor.upper()} flavor")
        print(
            f"{'Tool':<12} | {'Cases':>6} | {'Paired runs':>11} | "
            f"{'Median RSS multiplier':>28} | "
            f"{'Mean RSS multiplier':>28}"
        )
        for tool, data in flavor_data["peak_rss_kb"]["by_tool"].items():
            multiplier = data["memory_multiplier"]
            median_text = format_statistic(
                multiplier, "median", "median_confidence_interval"
            )
            mean_text = format_statistic(
                multiplier, "average", "confidence_interval"
            )
            print(
                f"{tool:<12} | {data['matched_testcases']:>6} | "
                f"{data['paired_repetitions']:>11} | "
                f"{median_text:>28} | {mean_text:>28}"
            )
    print(
        f"Cells show point estimate [{summary['confidence_level']:.0%} bootstrap CI] "
        "over testcase-level "
        "paired estimates."
    )
    print(f"Summary and charts: {Path(args.output_dir)}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Memory Corruption Vulnerability Detection Framework (Thesis Evaluation Framework)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommand to execute")

    # 'run' subcommand
    run_parser = subparsers.add_parser("run", help="Run a single test case with a specific tool")
    run_parser.add_argument("--file", "-f", required=True, help="Path to C/C++ source file")
    run_parser.add_argument(
        "--tool", "-t", default="all", choices=list(AVAILABLE_TOOLS.keys()) + ["all"], help="Tool adapter to test"
    )
    run_parser.add_argument("--flavor", choices=["bad", "good"], default="bad", help="Testcase flavor (bad or good)")
    run_parser.add_argument("--cwe", help="Explicit CWE identifier (e.g. CWE121)")
    run_parser.add_argument("--timeout", type=float, default=10.0, help="Execution timeout in seconds")
    run_parser.add_argument("--json", help="Path to export JSON results")
    run_parser.add_argument("--csv", help="Path to export CSV metrics")

    # 'benchmark' subcommand
    bench_parser = subparsers.add_parser("benchmark", help="Run a benchmark suite across multiple tools")
    bench_parser.add_argument(
        "--dir", "-d", default="benchmark/synthetic", help="Directory containing C/C++ benchmark files"
    )
    bench_parser.add_argument(
        "--tools", default="native,asan", help="Comma-separated list of tools (native,asan,valgrind)"
    )
    bench_parser.add_argument("--flavor", choices=["bad", "good"], default="bad", help="Flavor to test if not testing both")
    bench_parser.add_argument("--both-flavors", action="store_true", default=True, help="Test both good and bad flavors")
    bench_parser.add_argument("--filter", help="Filename glob pattern (e.g. '*01.c' for baseline testcases)")
    bench_parser.add_argument(
        "--exclude", default="*socket*", help="Filename glob pattern to exclude (default: '*socket*' to prevent blocking network calls)"
    )
    bench_parser.add_argument("--cwe", help="Filter testcases by CWE identifier (e.g. CWE121 or CWE416)")
    bench_parser.add_argument("--limit", type=int, default=0, help="Limit number of testcases to execute (0 = unlimited)")
    bench_parser.add_argument("--timeout", type=float, default=10.0, help="Per-test timeout in seconds")
    bench_parser.add_argument(
        "--repetitions",
        type=int,
        default=5,
        help="Measured executions per testcase/tool/flavor (default: 5)",
    )
    bench_parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed for reproducible randomized tool execution order (default: 42)",
    )
    bench_parser.add_argument("--json", default="results/json/benchmark_run.json", help="JSON export path")
    bench_parser.add_argument("--csv", default="results/csv/benchmark_run.csv", help="CSV export path")

    analysis_parser = subparsers.add_parser(
        "analyze", help="Analyze exported benchmark results and create charts"
    )
    analysis_parser.add_argument(
        "--input",
        default="results/csv/benchmark_run.csv",
        help="Input benchmark results (.csv or .json)",
    )
    analysis_parser.add_argument(
        "--output-dir",
        default="results/analysis",
        help="Directory for summary.json and generated charts",
    )
    analysis_parser.add_argument(
        "--confidence-level",
        type=float,
        default=0.95,
        help="Confidence level for intervals (default: 0.95)",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.command == "run":
        sys.exit(run_single(args))
    elif args.command == "benchmark":
        sys.exit(run_benchmark(args))
    elif args.command == "analyze":
        sys.exit(run_analysis(args))


if __name__ == "__main__":
    main()
