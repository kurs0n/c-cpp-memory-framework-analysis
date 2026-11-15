"""Calculate benchmark accuracy, stability, and overhead statistics."""

import math
import random
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from statistics import NormalDist, mean, median, stdev
from typing import Any

from .constants import (
    BOOTSTRAP_ITERATIONS,
    BOOTSTRAP_SEED,
    OUTCOMES,
    PERFORMANCE_METRICS,
)


def _percentile(sorted_values: Sequence[float], probability: float) -> float:
    position = probability * (len(sorted_values) - 1)
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return sorted_values[lower_index]
    fraction = position - lower_index
    return (
        sorted_values[lower_index] * (1 - fraction)
        + sorted_values[upper_index] * fraction
    )


def _bootstrap_mean_interval(
    values: Sequence[float], confidence_level: float
) -> dict[str, float] | None:
    return _bootstrap_interval(values, confidence_level, mean)


def _bootstrap_interval(
    values: Sequence[float],
    confidence_level: float,
    statistic: Callable[[Sequence[float]], float | None],
) -> dict[str, float] | None:
    if len(values) < 2:
        return None

    randomizer = random.Random(BOOTSTRAP_SEED)
    bootstrap_statistics = []
    sample_count = len(values)
    for _ in range(BOOTSTRAP_ITERATIONS):
        sample = [
            values[randomizer.randrange(sample_count)] for _ in range(sample_count)
        ]
        statistic_value = statistic(sample)
        if statistic_value is not None:
            bootstrap_statistics.append(statistic_value)
    if not bootstrap_statistics:
        return None
    bootstrap_statistics.sort()
    tail_probability = (1 - confidence_level) / 2
    return {
        "lower": _percentile(bootstrap_statistics, tail_probability),
        "upper": _percentile(bootstrap_statistics, 1 - tail_probability),
    }


def _wilson_interval(
    successes: int, trials: int, confidence_level: float
) -> dict[str, float] | None:
    if trials == 0:
        return None
    z_score = NormalDist().inv_cdf((1 + confidence_level) / 2)
    proportion = successes / trials
    denominator = 1 + z_score**2 / trials
    center = (proportion + z_score**2 / (2 * trials)) / denominator
    margin = (
        z_score
        * math.sqrt(
            proportion * (1 - proportion) / trials + z_score**2 / (4 * trials**2)
        )
        / denominator
    )
    return {"lower": max(0.0, center - margin), "upper": min(1.0, center + margin)}


def _proportion(successes: int, trials: int, confidence_level: float) -> dict[str, Any]:
    interval = _wilson_interval(successes, trials, confidence_level)
    return {
        "estimate": successes / trials if trials else None,
        "numerator": successes,
        "denominator": trials,
        "confidence_interval": interval,
    }


def _summarize_values(
    values: Sequence[float], confidence_level: float
) -> dict[str, Any]:
    count = len(values)
    average = mean(values) if count else None
    standard_deviation = stdev(values) if count > 1 else None
    return {
        "count": count,
        "average": average,
        "median": median(values) if count else None,
        "standard_deviation": standard_deviation,
        "confidence_interval": _bootstrap_mean_interval(values, confidence_level),
    }


def _geometric_mean(values: Sequence[float]) -> float | None:
    if not values:
        return None
    if any(value < 0 for value in values):
        raise ValueError("Geometric mean requires non-negative values")
    if any(value == 0 for value in values):
        return 0.0
    return math.exp(mean(math.log(value) for value in values))


def _summarize_paired_values(
    values: Sequence[float], confidence_level: float, include_geometric_mean: bool
) -> dict[str, Any]:
    result = _summarize_values(values, confidence_level)
    result["median_confidence_interval"] = _bootstrap_interval(
        values, confidence_level, median
    )
    if include_geometric_mean:
        result["geometric_mean"] = _geometric_mean(values)
        result["geometric_mean_confidence_interval"] = _bootstrap_interval(
            values, confidence_level, _geometric_mean
        )
    return result


def _case_key(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row["testcase_id"]),
        str(row["cwe"]),
        str(row["flavor"]),
        str(row["stdin_data"]),
    )


def _summarize_group(
    rows: Sequence[Mapping[str, Any]], confidence_level: float
) -> dict[str, Any]:
    cases: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        cases[_case_key(row)].append(row)

    counts = {outcome: 0 for outcome in OUTCOMES}
    execution_errors = 0
    testcases_without_classification_run = 0
    valid_execution_count = 0
    detected_execution_count = 0
    unstable_testcases = 0
    per_case_detection_rates_by_flavor: dict[str, list[float]] = defaultdict(list)
    case_metric_estimates: dict[str, list[float]] = {
        metric: [] for metric in PERFORMANCE_METRICS
    }
    within_case_standard_deviations: dict[str, list[float]] = {
        metric: [] for metric in PERFORMANCE_METRICS
    }
    within_case_coefficients_of_variation: dict[str, list[float]] = {
        metric: [] for metric in PERFORMANCE_METRICS
    }
    metric_measurement_counts = {metric: 0 for metric in PERFORMANCE_METRICS}

    for case_rows in cases.values():
        valid_rows = [row for row in case_rows if row["outcome"] != "ERROR"]
        execution_errors += len(case_rows) - len(valid_rows)
        if valid_rows:
            valid_execution_count += len(valid_rows)
            detected_count = sum(bool(row["detected"]) for row in valid_rows)
            detected_execution_count += detected_count
            detection_rate = detected_count / len(valid_rows)
            flavor = str(valid_rows[0]["flavor"])
            per_case_detection_rates_by_flavor[flavor].append(detection_rate)
            if 0 < detection_rate < 1:
                unstable_testcases += 1

        classification_rows = [
            row
            for row in case_rows
            if row["outcome"] != "ERROR" and (row.get("repetition") or 1) == 1
        ]
        if classification_rows:
            classification_row = classification_rows[0]
            case_detected = bool(classification_row["detected"])
            flavor = classification_row["flavor"]
            if flavor == "bad":
                outcome = "TP" if case_detected else "FN"
            else:
                outcome = "FP" if case_detected else "TN"
            counts[outcome] += 1
        else:
            testcases_without_classification_run += 1

        if not valid_rows:
            continue

        for metric in PERFORMANCE_METRICS:
            values = [
                row["metrics"][metric]
                for row in valid_rows
                if row["metrics"][metric] is not None
            ]
            if not values:
                continue
            metric_measurement_counts[metric] += len(values)
            case_estimate = median(values)
            case_metric_estimates[metric].append(case_estimate)
            if len(values) > 1:
                run_standard_deviation = stdev(values)
                within_case_standard_deviations[metric].append(run_standard_deviation)
                if case_estimate != 0:
                    within_case_coefficients_of_variation[metric].append(
                        run_standard_deviation / abs(case_estimate) * 100
                    )

    tp, fp, tn, fn = (counts[key] for key in OUTCOMES)
    total = sum(counts.values())
    accuracy = _proportion(tp + tn, total, confidence_level)
    precision = _proportion(tp, tp + fp, confidence_level)
    recall = _proportion(tp, tp + fn, confidence_level)
    specificity = _proportion(tn, tn + fp, confidence_level)
    f1_denominator = 2 * tp + fp + fn
    metrics: dict[str, Any] = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1_score": {
            "estimate": 2 * tp / f1_denominator if f1_denominator else None,
            "numerator": 2 * tp,
            "denominator": f1_denominator,
            "confidence_interval": None,
        },
    }
    performance = {}
    for metric in PERFORMANCE_METRICS:
        metric_summary = _summarize_values(
            case_metric_estimates[metric], confidence_level
        )
        metric_summary["measurement_count"] = metric_measurement_counts[metric]
        metric_summary["within_case_repeatability"] = {
            "standard_deviation": _summarize_values(
                within_case_standard_deviations[metric], confidence_level
            ),
            "coefficient_of_variation_percent": _summarize_values(
                within_case_coefficients_of_variation[metric], confidence_level
            ),
        }
        performance[metric] = metric_summary

    return {
        "sample_count": total,
        "execution_errors_excluded": execution_errors,
        "testcases_without_classification_run": (testcases_without_classification_run),
        "confusion_matrix": counts,
        "metrics": metrics,
        "performance": performance,
        "run_detection_consistency": {
            "execution_count": valid_execution_count,
            "detected_execution_count": detected_execution_count,
            "unstable_testcases": unstable_testcases,
            "per_testcase_detection_rate_by_flavor": {
                flavor: _summarize_values(rates, confidence_level)
                for flavor, rates in sorted(per_case_detection_rates_by_flavor.items())
            },
        },
    }


def _summarize_paired_overhead(
    rows: Sequence[Mapping[str, Any]],
    confidence_level: float,
    metric_name: str,
    overhead_key: str,
    factor_key: str,
    zero_baseline_key: str,
    baseline_tool: str = "native",
) -> dict[str, Any]:
    measurements: dict[
        str,
        dict[tuple[str, str, str, str], dict[int, list[float | None]]],
    ] = defaultdict(dict)
    for row in rows:
        if row["outcome"] == "ERROR":
            continue
        case_key = _case_key(row)
        if not case_key[0]:
            continue
        repetition = row.get("repetition", 1)
        if repetition is None:
            repetition = 1
        tool_measurements = measurements[str(row["tool_name"])]
        case_measurements = tool_measurements.setdefault(case_key, {})
        case_measurements.setdefault(int(repetition), []).append(
            row["metrics"][metric_name]
        )

    baseline_cases = measurements.get(baseline_tool, {})
    by_tool = {}
    for tool_name, tool_cases in sorted(measurements.items()):
        if tool_name == baseline_tool:
            continue

        overheads: list[float] = []
        ratios: list[float] = []
        testcase_estimates: list[dict[str, Any]] = []
        within_case_overhead_standard_deviations: list[float] = []
        within_case_ratio_standard_deviations: list[float] = []
        unmatched_testcases = 0
        unmatched_tool_repetitions = 0
        missing_tool_metric_testcases = 0
        missing_baseline_metric_testcases = 0
        zero_baseline_testcases = 0
        zero_baseline_repetitions = 0
        paired_repetitions = 0
        for case_key, tool_runs in tool_cases.items():
            available_tool_values = {
                repetition: median(value for value in values if value is not None)
                for repetition, values in tool_runs.items()
                if any(value is not None for value in values)
            }
            if not available_tool_values:
                missing_tool_metric_testcases += 1
                continue
            native_runs = baseline_cases.get(case_key)
            if native_runs is None:
                unmatched_testcases += 1
                continue
            available_native_values = {
                repetition: median(value for value in values if value is not None)
                for repetition, values in native_runs.items()
                if any(value is not None for value in values)
            }
            if not available_native_values:
                missing_baseline_metric_testcases += 1
                continue

            case_ratios = []
            case_overheads = []
            case_has_zero_baseline = False
            for repetition, tool_value in available_tool_values.items():
                native_value = available_native_values.get(repetition)
                if native_value is None:
                    unmatched_tool_repetitions += 1
                    continue
                if native_value <= 0:
                    zero_baseline_repetitions += 1
                    case_has_zero_baseline = True
                    continue
                ratio = tool_value / native_value
                case_ratios.append(ratio)
                case_overheads.append((ratio - 1) * 100)

            if case_has_zero_baseline:
                zero_baseline_testcases += 1
            if not case_ratios:
                continue

            paired_repetitions += len(case_ratios)
            case_ratio = median(case_ratios)
            case_overhead = median(case_overheads)
            ratios.append(case_ratio)
            overheads.append(case_overhead)
            testcase_estimates.append(
                {
                    "testcase_id": case_key[0],
                    "cwe": case_key[1],
                    "flavor": case_key[2],
                    "stdin_data": case_key[3],
                    "paired_repetitions": len(case_ratios),
                    factor_key: case_ratio,
                    overhead_key: case_overhead,
                }
            )
            if len(case_overheads) > 1:
                within_case_overhead_standard_deviations.append(stdev(case_overheads))
                within_case_ratio_standard_deviations.append(stdev(case_ratios))

        by_tool[tool_name] = {
            "matched_testcases": len(ratios),
            "paired_repetitions": paired_repetitions,
            "unmatched_tool_testcases": unmatched_testcases,
            "unmatched_tool_repetitions": unmatched_tool_repetitions,
            "missing_tool_metric_testcases": missing_tool_metric_testcases,
            "missing_baseline_metric_testcases": missing_baseline_metric_testcases,
            "zero_baseline_repetitions": zero_baseline_repetitions,
            zero_baseline_key: zero_baseline_testcases,
            overhead_key: _summarize_paired_values(
                overheads, confidence_level, include_geometric_mean=False
            ),
            factor_key: _summarize_paired_values(
                ratios, confidence_level, include_geometric_mean=True
            ),
            "testcase_estimates": testcase_estimates,
            "within_case_overhead_standard_deviation": _summarize_values(
                within_case_overhead_standard_deviations, confidence_level
            ),
            "within_case_ratio_standard_deviation": _summarize_values(
                within_case_ratio_standard_deviations, confidence_level
            ),
        }

    return by_tool


def _summarize_overhead_group(
    rows: Sequence[Mapping[str, Any]], confidence_level: float
) -> dict[str, Any]:
    return {
        "wall_clock_time_s": {
            "by_tool": _summarize_paired_overhead(
                rows,
                confidence_level,
                "wall_clock_time_s",
                "wall_clock_overhead_percent",
                "slowdown_factor",
                "zero_baseline_time_testcases",
            ),
            "by_cwe": {
                cwe: _summarize_paired_overhead(
                    cwe_rows,
                    confidence_level,
                    "wall_clock_time_s",
                    "wall_clock_overhead_percent",
                    "slowdown_factor",
                    "zero_baseline_time_testcases",
                )
                for cwe, cwe_rows in sorted(_group_rows_by_cwe(rows).items())
            },
        },
        "peak_rss_kb": {
            "formula": ("((tool_peak_rss_kb / native_peak_rss_kb) - 1) * 100"),
            "by_tool": _summarize_paired_overhead(
                rows,
                confidence_level,
                "peak_rss_kb",
                "peak_rss_overhead_percent",
                "memory_multiplier",
                "zero_baseline_rss_testcases",
            ),
            "by_cwe": {
                cwe: _summarize_paired_overhead(
                    cwe_rows,
                    confidence_level,
                    "peak_rss_kb",
                    "peak_rss_overhead_percent",
                    "memory_multiplier",
                    "zero_baseline_rss_testcases",
                )
                for cwe, cwe_rows in sorted(_group_rows_by_cwe(rows).items())
            },
        },
    }


def _group_rows_by_cwe(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("cwe", "CWE-UNKNOWN"))].append(row)
    return grouped


def _testcase_detection_details(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    grouped: dict[
        tuple[str, str, tuple[str, str, str, str]],
        list[Mapping[str, Any]],
    ] = defaultdict(list)
    for row in rows:
        key = (str(row["flavor"]), str(row["tool_name"]), _case_key(row))
        grouped[key].append(row)

    details: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for (flavor, tool, case_key), case_rows in sorted(grouped.items()):
        valid_rows = [row for row in case_rows if row["outcome"] != "ERROR"]
        detected_count = sum(bool(row["detected"]) for row in valid_rows)
        classification_rows = [
            row
            for row in case_rows
            if row["outcome"] != "ERROR" and (row.get("repetition") or 1) == 1
        ]
        classification = None
        if classification_rows:
            detected = bool(classification_rows[0]["detected"])
            classification = (
                ("TP" if detected else "FN")
                if flavor == "bad"
                else ("FP" if detected else "TN")
            )
        details[flavor][tool].append(
            {
                "testcase_id": case_key[0],
                "cwe": case_key[1],
                "stdin_data": case_key[3],
                "classification": classification,
                "classification_run_detected": (
                    bool(classification_rows[0]["detected"])
                    if classification_rows
                    else None
                ),
                "detection_rate": (
                    detected_count / len(valid_rows) if valid_rows else None
                ),
                "detected_executions": detected_count,
                "valid_executions": len(valid_rows),
                "execution_errors": len(case_rows) - len(valid_rows),
            }
        )
    return {
        flavor: dict(tool_details) for flavor, tool_details in sorted(details.items())
    }


def analyze_results(
    rows: Sequence[Mapping[str, Any]], confidence_level: float = 0.95
) -> dict[str, Any]:
    """Calculate confusion matrices, detection rates, and performance statistics."""
    if not 0 < confidence_level < 1:
        raise ValueError("confidence_level must be strictly between 0 and 1")

    by_tool: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    by_cwe: dict[str, dict[str, list[Mapping[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    rows_by_cwe: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    by_flavor: dict[str, dict[str, list[Mapping[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    rows_by_flavor: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        tool_name = str(row["tool_name"])
        cwe = str(row.get("cwe", "CWE-UNKNOWN"))
        flavor = str(row["flavor"])
        by_tool[tool_name].append(row)
        by_cwe[cwe][tool_name].append(row)
        rows_by_cwe[cwe].append(row)
        by_flavor[flavor][tool_name].append(row)
        rows_by_flavor[flavor].append(row)

    flavor_summaries = {
        flavor: {
            "by_tool": {
                tool: _summarize_group(tool_rows, confidence_level)
                for tool, tool_rows in sorted(tool_groups.items())
            }
        }
        for flavor, tool_groups in sorted(by_flavor.items())
    }

    return {
        "confidence_level": confidence_level,
        "confidence_interval_methods": {
            "proportions": "Wilson score interval",
            "averages": (
                f"Percentile bootstrap over testcase-level estimates "
                f"({BOOTSTRAP_ITERATIONS} resamples)"
            ),
            "paired_statistics": (
                f"Percentile bootstrap over testcase-level estimates for the "
                f"mean, median, and geometric mean "
                f"({BOOTSTRAP_ITERATIONS} resamples)"
            ),
        },
        "case_classification_rule": (
            "The first measured run (repetition 1) determines each testcase's "
            "classification. Later repetitions are used for performance and "
            "run-to-run stability, not additional confusion-matrix votes."
        ),
        "performance_aggregation": (
            "Each testcase contributes one estimate: the median of its valid "
            "measured repetitions. Confidence intervals resample testcases. Use "
            "by_flavor for good/bad comparisons; combined by_tool values mix flavors."
        ),
        "run_protocol": {
            "classification_repetition": 1,
            "planned_repetitions": sorted(
                {row.get("planned_repetitions", 1) for row in rows}
            ),
            "random_seeds": sorted(
                {
                    row.get("random_seed")
                    for row in rows
                    if row.get("random_seed") is not None
                }
            ),
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_iterations": BOOTSTRAP_ITERATIONS,
        },
        "overhead_vs_native": {
            "baseline_tool": "native",
            "metric": "wall_clock_time_s",
            "formula": "((tool_time / native_time) - 1) * 100",
            "aggregation": (
                "Analyze good and bad flavors separately. Pair runs by testcase, CWE, "
                "flavor, stdin, and repetition; use the median paired ratio within each "
                "testcase. Report arithmetic mean, median, and geometric mean of those "
                "testcase estimates; bootstrap each statistic over testcase estimates."
            ),
            "by_flavor": {
                flavor: _summarize_overhead_group(flavor_rows, confidence_level)
                for flavor, flavor_rows in sorted(rows_by_flavor.items())
            },
        },
        "by_tool": {
            tool: _summarize_group(tool_rows, confidence_level)
            for tool, tool_rows in sorted(by_tool.items())
        },
        "by_cwe": {
            cwe: {
                tool: _summarize_group(tool_rows, confidence_level)
                for tool, tool_rows in sorted(tool_groups.items())
            }
            for cwe, tool_groups in sorted(by_cwe.items())
        },
        "by_flavor": flavor_summaries,
        "testcase_detection": {
            "aggregation": (
                "Detection rate is the fraction of valid measured runs that detected "
                "the target issue. Classification is based only on repetition 1."
            ),
            "by_flavor": _testcase_detection_details(rows),
        },
    }
