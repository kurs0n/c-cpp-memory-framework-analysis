import csv
import json
import logging
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, List

from runner.framework.models import DetectionOutcome, ToolResult

logger = logging.getLogger("framework.reporter")

LEAK_KINDS = (
    "definitely_lost",
    "indirectly_lost",
    "possibly_lost",
    "still_reachable",
    "suppressed",
)


class Reporter:
    """Handles structured reporting in JSON, CSV, and formatted text."""

    @staticmethod
    def export_json(results: List[ToolResult], output_file: Path) -> None:
        """Exports full benchmark results to a formatted JSON file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        data = [r.to_dict() for r in results]
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("JSON report saved to: %s", output_file)

    @staticmethod
    def export_csv(results: List[ToolResult], output_file: Path) -> None:
        """Exports flat benchmark metrics to a CSV file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "tool_name",
            "testcase",
            "testcase_path",
            "cwe",
            "flavor",
            "stdin_data",
            "detected",
            "outcome",
            "error_type",
            "wall_clock_time_s",
            "user_time_s",
            "sys_time_s",
            "peak_rss_kb",
            "exit_code",
            "timed_out",
            "repetition",
            "used_for_classification",
            "tool_order",
            "planned_repetitions",
            "random_seed",
        ]
        fieldnames.extend(
            f"leak_{kind}_{measure}"
            for kind in LEAK_KINDS
            for measure in ("bytes", "blocks")
        )

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row: Dict[str, Any] = {
                    "tool_name": r.tool_name,
                    "testcase": r.test_case.path.name,
                    "testcase_path": str(r.test_case.path),
                    "cwe": r.test_case.cwe,
                    "flavor": r.test_case.flavor.value,
                    "stdin_data": r.test_case.stdin_data or "",
                    "detected": r.detected,
                    "outcome": r.outcome.value,
                    "error_type": r.error_type or "",
                    "wall_clock_time_s": f"{r.metrics.wall_clock_time_s:.5f}",
                    "user_time_s": f"{r.metrics.user_time_s:.5f}",
                    "sys_time_s": f"{r.metrics.sys_time_s:.5f}",
                    "peak_rss_kb": r.metrics.peak_rss_kb,
                    "exit_code": r.metrics.exit_code,
                    "timed_out": r.metrics.timed_out,
                    "repetition": r.repetition,
                    "used_for_classification": (
                        r.repetition == 1
                        and r.outcome != DetectionOutcome.ERROR
                    ),
                    "tool_order": r.tool_order,
                    "planned_repetitions": r.planned_repetitions,
                    "random_seed": r.random_seed,
                }
                leak_summary = r.diagnostics.get("leak_summary", {})
                if isinstance(leak_summary, dict):
                    for kind in LEAK_KINDS:
                        leak_counts = leak_summary.get(kind, {})
                        if isinstance(leak_counts, dict):
                            for measure in ("bytes", "blocks"):
                                row[f"leak_{kind}_{measure}"] = leak_counts.get(
                                    measure, ""
                                )
                writer.writerow(row)
        logger.info("CSV report saved to: %s", output_file)

    @staticmethod
    def print_summary(results: List[ToolResult]) -> None:
        """Prints a human-readable summary table to stdout."""
        header = f"{'Tool':<12} | {'CWE':<8} | {'Testcase':<24} | {'Flavor':<6} | {'Detected':<9} | {'Outcome':<6} | {'Time (s)':<10} | {'Peak RSS (KB)'}"
        separator = "-" * len(header)
        print("\n" + separator)
        print("EXPERIMENT EXECUTION SUMMARY")
        print(separator)
        print(header)
        print(separator)

        for r in results:
            peak_rss = (
                str(r.metrics.peak_rss_kb)
                if r.metrics.peak_rss_kb is not None
                else "N/A"
            )
            print(
                f"{r.tool_name:<12} | "
                f"{r.test_case.cwe:<8} | "
                f"{r.test_case.path.stem:<24} | "
                f"{r.test_case.flavor.value:<6} | "
                f"{str(r.detected):<9} | "
                f"{r.outcome.value:<6} | "
                f"{r.metrics.wall_clock_time_s:<10.4f} | "
                f"{peak_rss}"
            )
        print(separator + "\n")

    @staticmethod
    def print_benchmark_summary(results: List[ToolResult]) -> None:
        """Print one concise line per tool, CWE, and flavor after repeated runs."""
        groups: dict[
            tuple[str, str, str],
            dict[tuple[str, str], list[ToolResult]],
        ] = defaultdict(lambda: defaultdict(list))
        for result in results:
            group_key = (
                result.tool_name,
                result.test_case.cwe,
                result.test_case.flavor.value,
            )
            case_key = (
                str(result.test_case.path),
                result.test_case.stdin_data or "",
            )
            groups[group_key][case_key].append(result)

        header = (
            f"{'Tool':<12} | {'CWE':<8} | {'Flavor':<6} | {'Cases':>6} | "
            f"{'Detected':>10} | {'Unstable':>8} | {'Runs':>6} | "
            f"{'Errors':>6} | {'Mean case median (s)':>20}"
        )
        separator = "-" * len(header)
        print("\n" + separator)
        print("BENCHMARK SUMMARY (CASE-LEVEL DETECTION)")
        print(separator)
        print(header)
        print(separator)

        for (tool_name, cwe, flavor), cases in sorted(groups.items()):
            detected_cases = 0
            unstable_cases = 0
            valid_run_count = 0
            error_count = 0
            case_median_times = []
            classifiable_case_count = 0

            for case_results in cases.values():
                valid_results = [
                    result
                    for result in case_results
                    if result.outcome != DetectionOutcome.ERROR
                    and not result.metrics.timed_out
                ]
                error_count += len(case_results) - len(valid_results)
                valid_run_count += len(valid_results)
                if valid_results:
                    detections = sum(result.detected for result in valid_results)
                    detection_rate = detections / len(valid_results)
                    unstable_cases += 0 < detection_rate < 1
                    case_times = [
                        result.metrics.wall_clock_time_s for result in valid_results
                    ]
                    case_median_times.append(median(case_times))

                classification_runs = [
                    result
                    for result in valid_results
                    if result.repetition == 1
                ]
                if not classification_runs:
                    continue

                classifiable_case_count += 1
                detected_cases += classification_runs[0].detected

            mean_time = mean(case_median_times) if case_median_times else None
            mean_time_text = f"{mean_time:.5f}" if mean_time is not None else "N/A"
            print(
                f"{tool_name:<12} | {cwe:<8} | {flavor:<6} | "
                f"{classifiable_case_count:>6} | "
                f"{detected_cases:>5}/{classifiable_case_count:<4} | "
                f"{unstable_cases:>8} | {valid_run_count:>6} | "
                f"{error_count:>6} | {mean_time_text:>13}"
            )
        print(separator + "\n")
