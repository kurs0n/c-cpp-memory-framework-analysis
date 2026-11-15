import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from runner.framework.analysis import analyze_results, generate_analysis, load_results
from runner.framework.analyzer import analyze_results as legacy_analyze_results
from runner.framework.compiler import Compiler
from runner.framework.executor import Executor
from runner.framework.models import (
    DetectionOutcome,
    ExecutionMetrics,
    TestCase,
    TestFlavor,
    ToolResult,
)
from runner.framework.reporter import Reporter
from runner.main import run_benchmark
from runner.tools.asan import ASanTool
from runner.tools.native import NativeTool
from runner.tools.valgrind import ValgrindTool


class TestFramework(unittest.TestCase):
    def test_analyzer_compatibility_module_reexports_analysis_api(self) -> None:
        self.assertIs(legacy_analyze_results, analyze_results)

    def test_benchmark_runs_only_measured_repetitions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            benchmark_dir = Path(tmp_dir)
            (benchmark_dir / "case.c").write_text(
                "int main(void) { return 0; }\n",
                encoding="utf-8",
            )
            run_results = []

            class StubAdapter:
                def __init__(self, compiler: object, executor: object) -> None:
                    pass

                def compile(self, test_case: TestCase, output_dir: Path) -> Path:
                    return output_dir / "case.out"

                def run(self, test_case: TestCase, binary_path: Path) -> ToolResult:
                    result = ToolResult(
                        tool_name="stub",
                        test_case=test_case,
                        detected=False,
                        outcome=DetectionOutcome.FALSE_NEGATIVE,
                    )
                    run_results.append(result)
                    return result

            args = SimpleNamespace(
                repetitions=2,
                dir=str(benchmark_dir),
                tools="stub",
                exclude=None,
                filter=None,
                cwe=None,
                limit=0,
                both_flavors=False,
                flavor="bad",
                timeout=10,
                seed=42,
                json=None,
                csv=None,
            )
            with (
                patch("runner.main.AVAILABLE_TOOLS", {"stub": StubAdapter}),
                patch("runner.main.Compiler"),
                patch("runner.main.Executor"),
                patch.object(Reporter, "print_benchmark_summary"),
            ):
                exit_code = run_benchmark(args)

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(run_results), 2)
        self.assertEqual([result.repetition for result in run_results], [1, 2])

    def test_analysis_reads_flat_csv_and_excludes_errors(self) -> None:
        fields = [
            "tool_name", "testcase", "cwe", "flavor", "detected", "outcome",
            "wall_clock_time_s", "user_time_s", "sys_time_s", "peak_rss_kb",
        ]
        rows = [
            ["asan", "one.c", "CWE121", "bad", "True", "TP", "1", "0.5", "0.1", "100"],
            ["asan", "two.c", "CWE121", "bad", "False", "FN", "2", "1.0", "0.2", "200"],
            ["asan", "three.c", "CWE121", "good", "True", "FP", "3", "1.5", "0.3", "300"],
            ["asan", "four.c", "CWE121", "good", "False", "TN", "4", "2.0", "0.4", "400"],
            ["asan", "failed.c", "CWE121", "bad", "False", "ERROR", "10", "0", "0", "500"],
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_file = Path(tmp_dir) / "results.csv"
            with csv_file.open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(fields)
                writer.writerows(rows)

            results = load_results(csv_file)
            summary = analyze_results(results)["by_tool"]["asan"]

        self.assertEqual(summary["confusion_matrix"], {"TP": 1, "FP": 1, "TN": 1, "FN": 1})
        self.assertEqual(summary["execution_errors_excluded"], 1)
        self.assertEqual(summary["metrics"]["accuracy"]["estimate"], 0.5)
        self.assertIsNotNone(summary["metrics"]["accuracy"]["confidence_interval"])
        self.assertEqual(summary["performance"]["wall_clock_time_s"]["average"], 2.5)
        self.assertAlmostEqual(
            summary["performance"]["wall_clock_time_s"]["standard_deviation"],
            (5 / 3) ** 0.5,
        )

    def test_analysis_calculates_paired_time_and_rss_overhead(self) -> None:
        rows = []
        for testcase_id, tool_name, detected, wall_time, peak_rss in (
            ("case-a.c", "native", False, 0.5, 10_000),
            ("case-a.c", "asan", True, 1.0, 15_000),
            ("case-b.c", "native", False, 2.0, 20_000),
            ("case-b.c", "asan", True, 3.0, 40_000),
        ):
            rows.append(
                {
                    "tool_name": tool_name,
                    "testcase_id": testcase_id,
                    "cwe": "CWE121",
                    "flavor": "bad",
                    "stdin_data": "",
                    "detected": detected,
                    "outcome": "TP" if detected else "FN",
                    "metrics": {
                        "wall_clock_time_s": wall_time,
                        "user_time_s": 0.1,
                        "sys_time_s": 0.01,
                        "peak_rss_kb": peak_rss,
                    },
                }
            )

        overhead = analyze_results(rows)["overhead_vs_native"]
        bad_overhead = overhead["by_flavor"]["bad"]
        time_stats = bad_overhead["wall_clock_time_s"]["by_tool"]["asan"]
        rss_stats = bad_overhead["peak_rss_kb"]["by_tool"]["asan"]
        self.assertEqual(time_stats["matched_testcases"], 2)
        self.assertEqual(time_stats["wall_clock_overhead_percent"]["average"], 75)
        self.assertAlmostEqual(
            time_stats["wall_clock_overhead_percent"]["standard_deviation"],
            (1250**0.5),
        )
        self.assertEqual(time_stats["slowdown_factor"]["average"], 1.75)
        self.assertEqual(time_stats["slowdown_factor"]["median"], 1.75)
        self.assertAlmostEqual(time_stats["slowdown_factor"]["geometric_mean"], 3**0.5)
        self.assertIsNotNone(
            time_stats["slowdown_factor"]["median_confidence_interval"]
        )
        self.assertIsNotNone(
            time_stats["slowdown_factor"]["geometric_mean_confidence_interval"]
        )
        self.assertIsNotNone(
            time_stats["wall_clock_overhead_percent"]["confidence_interval"]
        )
        self.assertEqual(rss_stats["matched_testcases"], 2)
        self.assertEqual(rss_stats["peak_rss_overhead_percent"]["average"], 75)
        self.assertEqual(rss_stats["memory_multiplier"]["average"], 1.75)

    def test_analysis_aggregates_repetitions_per_case_before_classification(
        self,
    ) -> None:
        rows = []
        measurements = (
            ("case-a.c", "native", 1, False, 1.0, 10_000),
            ("case-a.c", "native", 2, False, 1.2, 10_000),
            ("case-a.c", "asan", 1, True, 2.0, 15_000),
            ("case-a.c", "asan", 2, True, 2.4, 15_000),
            ("case-b.c", "native", 1, False, 2.0, 20_000),
            ("case-b.c", "native", 2, False, 2.0, 20_000),
            ("case-b.c", "asan", 1, True, 4.0, 40_000),
            ("case-b.c", "asan", 2, False, 6.0, 40_000),
        )
        for (
            testcase_id,
            tool_name,
            repetition,
            detected,
            wall_time,
            peak_rss,
        ) in measurements:
            rows.append(
                {
                    "tool_name": tool_name,
                    "testcase_id": testcase_id,
                    "cwe": "CWE416",
                    "flavor": "bad",
                    "stdin_data": "",
                    "detected": detected,
                    "outcome": "TP" if detected else "FN",
                    "repetition": repetition,
                    "metrics": {
                        "wall_clock_time_s": wall_time,
                        "user_time_s": 0.1,
                        "sys_time_s": 0.01,
                        "peak_rss_kb": peak_rss,
                    },
                }
            )

        summary = analyze_results(rows)
        asan = summary["by_tool"]["asan"]
        time_overhead = summary["overhead_vs_native"]["by_flavor"]["bad"][
            "wall_clock_time_s"
        ]["by_tool"]["asan"]

        self.assertEqual(asan["sample_count"], 2)
        self.assertEqual(
            asan["confusion_matrix"],
            {"TP": 2, "FP": 0, "TN": 0, "FN": 0},
        )
        self.assertEqual(asan["run_detection_consistency"]["execution_count"], 4)
        self.assertEqual(
            asan["run_detection_consistency"]["unstable_testcases"],
            1,
        )
        self.assertEqual(
            asan["run_detection_consistency"][
                "per_testcase_detection_rate_by_flavor"
            ]["bad"]["average"],
            0.75,
        )
        self.assertEqual(asan["performance"]["wall_clock_time_s"]["average"], 3.6)
        self.assertEqual(time_overhead["matched_testcases"], 2)
        self.assertEqual(time_overhead["paired_repetitions"], 4)
        self.assertEqual(
            time_overhead["wall_clock_overhead_percent"]["average"],
            125,
        )
        self.assertEqual(
            time_overhead["testcase_estimates"][0]["paired_repetitions"],
            2,
        )
        stability_cases = summary["testcase_detection"]["by_flavor"]["bad"]["asan"]
        self.assertEqual(stability_cases[1]["classification"], "TP")
        self.assertEqual(stability_cases[1]["detection_rate"], 0.5)
        self.assertEqual(stability_cases[1]["detected_executions"], 1)
        self.assertEqual(stability_cases[1]["valid_executions"], 2)
        self.assertEqual(
            summary["run_protocol"]["planned_repetitions"],
            [1],
        )

    def test_analysis_separates_good_and_bad_performance_and_overhead(self) -> None:
        rows = []
        for flavor, detected, native_time, asan_time in (
            ("bad", False, 1.0, 10.0),
            ("good", False, 1.0, 2.0),
        ):
            for repetition in (1, 2):
                for tool_name, wall_time in (
                    ("native", native_time),
                    ("asan", asan_time),
                ):
                    rows.append(
                        {
                            "tool_name": tool_name,
                            "testcase_id": "case.c",
                            "cwe": "CWE416",
                            "flavor": flavor,
                            "stdin_data": "",
                            "detected": detected,
                            "outcome": (
                                "FN" if flavor == "bad" else "TN"
                            ),
                            "repetition": repetition,
                            "metrics": {
                                "wall_clock_time_s": wall_time,
                                "user_time_s": 0.1,
                                "sys_time_s": 0.01,
                                "peak_rss_kb": 10_000
                                if tool_name == "native"
                                else 20_000,
                            },
                        }
                    )

        summary = analyze_results(rows)
        bad = summary["by_flavor"]["bad"]["by_tool"]["asan"]
        good = summary["by_flavor"]["good"]["by_tool"]["asan"]
        overhead_by_flavor = summary["overhead_vs_native"]["by_flavor"]

        self.assertEqual(
            summary["by_tool"]["asan"]["confusion_matrix"],
            {"TP": 0, "FP": 0, "TN": 1, "FN": 1},
        )
        self.assertEqual(bad["performance"]["wall_clock_time_s"]["average"], 10)
        self.assertEqual(good["performance"]["wall_clock_time_s"]["average"], 2)
        self.assertEqual(
            overhead_by_flavor["bad"]["wall_clock_time_s"]["by_tool"]["asan"][
                "slowdown_factor"
            ]["average"],
            10,
        )
        self.assertEqual(
            overhead_by_flavor["good"]["wall_clock_time_s"]["by_tool"]["asan"][
                "slowdown_factor"
            ]["average"],
            2,
        )

    def test_error_on_classification_run_does_not_use_later_detection_vote(self) -> None:
        rows = [
            {
                "tool_name": "asan",
                "testcase_id": "case.c",
                "cwe": "CWE416",
                "flavor": "bad",
                "stdin_data": "",
                "detected": False,
                "outcome": "ERROR",
                "repetition": 1,
                "metrics": {
                    "wall_clock_time_s": None,
                    "user_time_s": None,
                    "sys_time_s": None,
                    "peak_rss_kb": None,
                },
            },
            {
                "tool_name": "asan",
                "testcase_id": "case.c",
                "cwe": "CWE416",
                "flavor": "bad",
                "stdin_data": "",
                "detected": True,
                "outcome": "TP",
                "repetition": 2,
                "metrics": {
                    "wall_clock_time_s": 2.0,
                    "user_time_s": 0.1,
                    "sys_time_s": 0.01,
                    "peak_rss_kb": 10_000,
                },
            },
        ]

        result = analyze_results(rows)["by_tool"]["asan"]

        self.assertEqual(result["sample_count"], 0)
        self.assertEqual(result["execution_errors_excluded"], 1)
        self.assertEqual(result["testcases_without_classification_run"], 1)
        self.assertEqual(
            result["confusion_matrix"],
            {"TP": 0, "FP": 0, "TN": 0, "FN": 0},
        )
        self.assertEqual(result["performance"]["wall_clock_time_s"]["average"], 2)

    def test_analysis_generates_time_and_rss_overhead_charts(self) -> None:
        fields = [
            "tool_name", "testcase_path", "cwe", "flavor", "detected", "outcome",
            "warmup_runs",
            "wall_clock_time_s", "user_time_s", "sys_time_s", "peak_rss_kb",
        ]
        rows = [
            ["native", "case.c", "CWE121", "bad", False, "FN", 3, 0.5, 0.1, 0.01, 10_000],
            ["asan", "case.c", "CWE121", "bad", True, "TP", 3, 1.0, 0.2, 0.02, 15_000],
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_file = Path(tmp_dir) / "results.csv"
            output_dir = Path(tmp_dir) / "analysis"
            with input_file.open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(fields)
                writer.writerows(rows)

            summary = generate_analysis(input_file, output_dir)

            self.assertEqual(
                summary["overhead_vs_native"]["by_flavor"]["bad"]["peak_rss_kb"][
                    "by_tool"
                ]["asan"]["matched_testcases"],
                1,
            )
            self.assertNotIn("warmup_runs", summary["run_protocol"])
            self.assertTrue((output_dir / "wall_clock/wall_clock_overhead.png").is_file())
            self.assertTrue((output_dir / "peak_rss/peak_rss_overhead.png").is_file())
            self.assertTrue((output_dir / "repeatability/repeatability.png").is_file())
            self.assertTrue(
                (output_dir / "wall_clock/wall_clock_slowdown_boxplot.png").is_file()
            )
            self.assertTrue(
                (output_dir / "peak_rss/peak_rss_multiplier_boxplot.png").is_file()
            )
            self.assertTrue((output_dir / "detection/detection_heatmap.png").is_file())
            self.assertTrue(
                (output_dir / "detection/detection_stability_bad.png").is_file()
            )
            self.assertTrue(
                (output_dir / "detection/detection_stability_good.png").is_file()
            )

    def test_models_serialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "dummy.c"
            test_file.write_text("int main() { return 0; }")
            tc = TestCase(path=test_file, cwe="CWE121", flavor=TestFlavor.BAD)
            data = tc.to_dict()
            self.assertEqual(data["cwe"], "CWE121")
            self.assertEqual(data["flavor"], "bad")
            self.assertEqual(data["path"], str(test_file))
            self.assertIsNone(data["stdin_data"])
            result = ToolResult(
                tool_name="asan",
                test_case=tc,
                detected=True,
                outcome=DetectionOutcome.TRUE_POSITIVE,
            )
            self.assertTrue(result.to_dict()["used_for_classification"])

    def test_executor_sends_provided_stdin(self) -> None:
        exit_code, stdout, _, _ = Executor().run(
            [sys.executable, "-c", "import sys; print(sys.stdin.read(), end='')"],
            stdin_data="10\n",
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, "10\n")

    def test_executor_peak_rss_is_per_process(self) -> None:
        executor = Executor()
        high_memory_script = (
            "import time; data = bytearray(48 * 1024 * 1024); "
            "[(data.__setitem__(i, 1)) for i in range(0, len(data), 4096)]; "
            "time.sleep(0.15)"
        )
        _, _, _, high_memory_metrics = executor.run(
            [sys.executable, "-c", high_memory_script]
        )
        _, _, _, low_memory_metrics = executor.run(
            [sys.executable, "-c", "import time; time.sleep(0.1)"]
        )

        self.assertIsNotNone(high_memory_metrics.peak_rss_kb)
        self.assertIsNotNone(low_memory_metrics.peak_rss_kb)
        self.assertGreater(
            high_memory_metrics.peak_rss_kb,
            low_memory_metrics.peak_rss_kb + 20_000,
        )

    def test_executor_timeout_kills_child_and_marks_metrics(self) -> None:
        with self.assertLogs("framework.executor", level="WARNING"):
            exit_code, stdout, _, metrics = Executor(timeout_seconds=0.05).run(
                [
                    sys.executable,
                    "-c",
                    "import time; print('started', flush=True); time.sleep(5)",
                ]
            )

        self.assertEqual(exit_code, -1)
        self.assertEqual(stdout, "started\n")
        self.assertTrue(metrics.timed_out)

    def test_tool_timeouts_are_errors_not_detections(self) -> None:
        test_case = TestCase(
            path=Path("timeout.c"),
            cwe="CWE416",
            flavor=TestFlavor.BAD,
        )
        tools = (
            NativeTool(Compiler(), Executor()),
            ASanTool(Compiler(), Executor()),
            ValgrindTool(Compiler(), Executor()),
        )
        for tool in tools:
            with self.subTest(tool=tool.name):
                with (
                    patch.object(
                        tool.executor,
                        "run",
                        return_value=(
                            -1,
                            "",
                            "",
                            ExecutionMetrics(exit_code=-1, timed_out=True),
                        ),
                    ),
                    patch.object(tool, "valgrind_bin", "valgrind", create=True),
                ):
                    result = tool.run(test_case, Path("timeout"))

                self.assertFalse(result.detected)
                self.assertEqual(result.outcome, DetectionOutcome.ERROR)
                self.assertFalse(result.to_dict()["used_for_classification"])

    def test_juliet_cwe129_sources_get_deterministic_input(self) -> None:
        tool = NativeTool(Compiler(), Executor())
        for source in ("fgets", "fscanf"):
            for flavor in (TestFlavor.BAD, TestFlavor.GOOD):
                test_case = TestCase(
                    path=Path(
                        f"/workspace/benchmark/juliet/testcases/CWE121/"
                        f"CWE121_Stack_Based_Buffer_Overflow__CWE129_{source}_01.c"
                    ),
                    cwe="CWE121",
                    flavor=flavor,
                )
                self.assertEqual(tool.get_stdin_data(test_case), "10\n")
                self.assertEqual(test_case.stdin_data, "10\n")
                self.assertEqual(test_case.to_dict()["stdin_data"], "10\n")

    def test_reports_record_stdin_and_repetition_metadata_without_warmups(self) -> None:
        test_case = TestCase(
            path=Path("test.c"),
            cwe="CWE121",
            flavor=TestFlavor.BAD,
            stdin_data="10\n",
        )
        result = ToolResult(
            tool_name="asan",
            test_case=test_case,
            detected=True,
            outcome=DetectionOutcome.TRUE_POSITIVE,
            repetition=4,
            tool_order=2,
            planned_repetitions=20,
            random_seed=17,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "results.csv"
            json_file = Path(tmp_dir) / "results.json"
            Reporter.export_csv([result], output_file)
            with output_file.open(newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                fieldnames = reader.fieldnames or []
                row = next(reader)
            Reporter.export_json([result], json_file)
            with json_file.open(encoding="utf-8") as file:
                json_result = json.load(file)[0]
        self.assertEqual(row["stdin_data"], "10\n")
        self.assertEqual(row["repetition"], "4")
        self.assertEqual(row["used_for_classification"], "False")
        self.assertEqual(row["tool_order"], "2")
        self.assertNotIn("warmup_runs", fieldnames)
        self.assertEqual(row["planned_repetitions"], "20")
        self.assertEqual(row["random_seed"], "17")
        self.assertEqual(json_result["repetition"], 4)
        self.assertFalse(json_result["used_for_classification"])
        self.assertEqual(json_result["tool_order"], 2)
        self.assertNotIn("warmup_runs", json_result)
        self.assertEqual(json_result["planned_repetitions"], 20)
        self.assertEqual(json_result["random_seed"], 17)

    def test_csv_report_records_valgrind_leak_breakdown(self) -> None:
        test_case = TestCase(
            path=Path("leaky_good.c"),
            cwe="CWE416",
            flavor=TestFlavor.GOOD,
        )
        result = ToolResult(
            tool_name="valgrind",
            test_case=test_case,
            detected=False,
            outcome=DetectionOutcome.TRUE_NEGATIVE,
            error_type="MEMORY_LEAK",
            diagnostics={
                "leak_summary": {
                    "definitely_lost": {"bytes": 100, "blocks": 1},
                    "indirectly_lost": {"bytes": 0, "blocks": 0},
                    "possibly_lost": {"bytes": 0, "blocks": 0},
                    "still_reachable": {"bytes": 0, "blocks": 0},
                    "suppressed": {"bytes": 0, "blocks": 0},
                }
            },
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "results.csv"
            Reporter.export_csv([result], output_file)
            with output_file.open(newline="", encoding="utf-8") as file:
                row = next(csv.DictReader(file))

        self.assertEqual(row["detected"], "False")
        self.assertEqual(row["outcome"], "TN")
        self.assertEqual(row["leak_definitely_lost_bytes"], "100")
        self.assertEqual(row["leak_definitely_lost_blocks"], "1")
        self.assertEqual(row["leak_still_reachable_bytes"], "0")

    def test_outcome_evaluation(self) -> None:
        compiler = Compiler()
        executor = Executor()
        tool = NativeTool(compiler, executor)

        tc_bad = TestCase(path=Path("dummy.c"), cwe="CWE121", flavor=TestFlavor.BAD)
        self.assertEqual(tool.evaluate_outcome(tc_bad, detected=True), DetectionOutcome.TRUE_POSITIVE)
        self.assertEqual(tool.evaluate_outcome(tc_bad, detected=False), DetectionOutcome.FALSE_NEGATIVE)

        tc_good = TestCase(path=Path("dummy.c"), cwe="CWE121", flavor=TestFlavor.GOOD)
        self.assertEqual(tool.evaluate_outcome(tc_good, detected=False), DetectionOutcome.TRUE_NEGATIVE)
        self.assertEqual(tool.evaluate_outcome(tc_good, detected=True), DetectionOutcome.FALSE_POSITIVE)

    def test_asan_diagnostic_parsing(self) -> None:
        compiler = Compiler()
        executor = Executor()
        asan = ASanTool(compiler, executor)

        sample_stderr = """
=================================================================
==43210==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040 pc 0x0001046bc920 bp 0x7ffee7604d50 sp 0x7ffee7604d48
READ of size 1 at 0x603000000040 thread T0
    #0 0x1046bc91f in cwe416_bad cwe416_uaf.c:20
    #1 0x1046bca18 in main cwe416_uaf.c:38
=================================================================
        """
        detected, err_type, diag = asan.parse_diagnostics(sample_stderr)
        self.assertTrue(detected)
        self.assertEqual(err_type, "heap-use-after-free")
        self.assertEqual(diag["target_address"], "0x603000000040")
        self.assertEqual(diag["operation"], "READ")
        self.assertEqual(diag["access_size"], 1)

    def test_asan_parses_multiword_double_free_type(self) -> None:
        tool = ASanTool(Compiler(), Executor())
        stderr = "==42==ERROR: AddressSanitizer: attempting double-free on 0x1234 in thread T0"
        detected, error_type, diagnostics = tool.parse_diagnostics(stderr)
        self.assertTrue(detected)
        self.assertEqual(error_type, "attempting double-free")
        self.assertEqual(diagnostics["error_type"], "attempting double-free")

    def test_valgrind_keeps_leaks_separate_from_memory_errors(self) -> None:
        tool = ValgrindTool(Compiler(), Executor())
        leak_log = (
            "==42== LEAK SUMMARY:\n"
            "==42==    definitely lost: 100 bytes in 1 blocks\n"
            "==42==    indirectly lost: 0 bytes in 0 blocks\n"
            "==42==    possibly lost: 0 bytes in 0 blocks\n"
            "==42==    still reachable: 0 bytes in 0 blocks\n"
            "==42== ERROR SUMMARY: 1 errors from 1 contexts\n"
        )

        detected, error_type, diagnostics = tool.parse_diagnostics(leak_log, 0)

        self.assertFalse(detected)
        self.assertEqual(error_type, "MEMORY_LEAK")
        self.assertEqual(
            diagnostics["leak_summary"]["definitely_lost"],
            {"bytes": 100, "blocks": 1},
        )

        use_after_free_log = "==42== Invalid read of size 1\n" + leak_log
        detected, error_type, _ = tool.parse_diagnostics(use_after_free_log, 101)
        self.assertTrue(detected)
        self.assertEqual(error_type, "Invalid read")

    def test_valgrind_good_case_leak_is_not_a_target_detection(self) -> None:
        tool = ValgrindTool(Compiler(), Executor())
        leak_log = (
            "==42== LEAK SUMMARY:\n"
            "==42==    definitely lost: 100 bytes in 1 blocks\n"
            "==42==    indirectly lost: 0 bytes in 0 blocks\n"
            "==42==    possibly lost: 0 bytes in 0 blocks\n"
            "==42==    still reachable: 0 bytes in 0 blocks\n"
        )
        test_case = TestCase(
            path=Path("good.c"),
            cwe="CWE416",
            flavor=TestFlavor.GOOD,
        )
        with (
            patch.object(tool, "valgrind_bin", "valgrind"),
            patch.object(
                tool.executor,
                "run",
                return_value=(0, "", leak_log, ExecutionMetrics()),
            ) as executor_run,
        ):
            result = tool.run(test_case, Path("good"))

        command = executor_run.call_args.args[0]
        self.assertIn("--errors-for-leak-kinds=none", command)
        self.assertFalse(result.detected)
        self.assertEqual(result.outcome, DetectionOutcome.TRUE_NEGATIVE)
        self.assertEqual(result.error_type, "MEMORY_LEAK")


if __name__ == "__main__":
    unittest.main()
