"""Generate charts from benchmark analysis summaries."""

from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _plot_confusion_matrices(summary: Mapping[str, Any], output_file: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tools = list(summary["by_tool"])
    if not tools:
        return
    figure, axes = plt.subplots(
        1, len(tools), figsize=(4 * len(tools), 4), squeeze=False
    )
    for axis, tool in zip(axes[0], tools):
        counts = summary["by_tool"][tool]["confusion_matrix"]
        matrix = [[counts["TN"], counts["FP"]], [counts["FN"], counts["TP"]]]
        image = axis.imshow(matrix, cmap="Blues")
        axis.set_title(tool)
        axis.set_xticks([0, 1], labels=["No detection", "Detection"])
        axis.set_yticks([0, 1], labels=["Good (safe)", "Bad (vulnerable)"])
        axis.set_xlabel("Predicted")
        axis.set_ylabel("Ground truth")
        threshold = max((value for row in matrix for value in row), default=0) / 2
        for row_index, row in enumerate(matrix):
            for column_index, value in enumerate(row):
                axis.text(
                    column_index,
                    row_index,
                    str(value),
                    ha="center",
                    va="center",
                    color="white" if value > threshold else "black",
                )
        figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    figure.suptitle("Detection confusion matrices")
    figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)


def _plot_detection_rates(summary: Mapping[str, Any], output_file: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tools = list(summary["by_tool"])
    if not tools:
        return
    metric_names = ("accuracy", "precision", "recall", "specificity")
    x_positions = list(range(len(tools)))
    width = 0.8 / len(metric_names)
    figure, axis = plt.subplots(figsize=(max(7, 1.8 * len(tools)), 5))

    for metric_index, metric in enumerate(metric_names):
        offsets = [
            x + (metric_index - (len(metric_names) - 1) / 2) * width
            for x in x_positions
        ]
        estimates = []
        lower_errors = []
        upper_errors = []
        for tool in tools:
            result = summary["by_tool"][tool]["metrics"][metric]
            estimate = result["estimate"]
            interval = result["confidence_interval"]
            estimates.append(estimate if estimate is not None else 0)
            if estimate is None or interval is None:
                lower_errors.append(0)
                upper_errors.append(0)
            else:
                lower_errors.append(max(0.0, estimate - interval["lower"]))
                upper_errors.append(max(0.0, interval["upper"] - estimate))
        axis.bar(
            offsets,
            estimates,
            width,
            label=metric.replace("_", " ").title(),
            yerr=[lower_errors, upper_errors],
            capsize=3,
        )

    axis.set_xticks(x_positions, labels=tools)
    axis.set_ylim(0, 1.05)
    axis.set_ylabel("Rate")
    axis.set_title(
        f"Detection rates with {summary['confidence_level']:.0%} Wilson intervals"
    )
    axis.legend(loc="best")
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)


def _tool_flavor_summaries(
    summary: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    return {
        f"{tool} ({flavor})": tool_summary
        for flavor, flavor_summary in summary["by_flavor"].items()
        for tool, tool_summary in flavor_summary["by_tool"].items()
    }


def _plot_performance(summary: Mapping[str, Any], output_file: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tool_summaries = _tool_flavor_summaries(summary)
    tools = list(tool_summaries)
    if not tools:
        return
    metrics_to_plot = (
        ("wall_clock_time_s", "Mean per-testcase wall-clock time (s)"),
        ("peak_rss_kb", "Mean per-testcase peak RSS (KB)"),
    )
    figure, axes = plt.subplots(1, 2, figsize=(11, 5))
    for axis, (metric, title) in zip(axes, metrics_to_plot):
        means = []
        deviations = []
        for tool in tools:
            values = tool_summaries[tool]["performance"][metric]
            means.append(values["average"] if values["average"] is not None else 0)
            deviations.append(
                values["standard_deviation"]
                if values["standard_deviation"] is not None
                else 0
            )
        axis.bar(tools, means, yerr=deviations, capsize=4, color="#4472C4")
        axis.set_title(title)
        axis.set_ylabel("Mean ± between-testcase standard deviation")
        axis.tick_params(axis="x", rotation=25)
        axis.grid(axis="y", alpha=0.25)
    figure.suptitle("Per-testcase performance")
    figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)


def _plot_repeatability(summary: Mapping[str, Any], output_file: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tool_summaries = _tool_flavor_summaries(summary)
    tools = list(tool_summaries)
    metrics_to_plot = (
        ("wall_clock_time_s", "Wall-clock time"),
        ("peak_rss_kb", "Peak RSS"),
    )
    figure, axis = plt.subplots(figsize=(max(7, 1.8 * len(tools)), 5))
    has_repeatability = any(
        tool_summaries[tool]["performance"][metric]["within_case_repeatability"][
            "coefficient_of_variation_percent"
        ]["count"]
        for tool in tools
        for metric, _ in metrics_to_plot
    )
    if not tools or not has_repeatability:
        axis.text(
            0.5,
            0.5,
            (
                "No benchmark measurements"
                if not tools
                else "No testcases have multiple valid measured runs"
            ),
            ha="center",
            va="center",
            transform=axis.transAxes,
        )
        axis.set_axis_off()
    else:
        width = 0.8 / len(metrics_to_plot)
        positions = list(range(len(tools)))
        for metric_index, (metric, label) in enumerate(metrics_to_plot):
            means = []
            lower_errors = []
            upper_errors = []
            for tool in tools:
                stats = tool_summaries[tool]["performance"][metric][
                    "within_case_repeatability"
                ]["coefficient_of_variation_percent"]
                average = stats["average"]
                interval = stats["confidence_interval"]
                means.append(average if average is not None else 0)
                if average is None or interval is None:
                    lower_errors.append(0)
                    upper_errors.append(0)
                else:
                    lower_errors.append(max(0.0, average - interval["lower"]))
                    upper_errors.append(max(0.0, interval["upper"] - average))
            offsets = [
                position + (metric_index - (len(metrics_to_plot) - 1) / 2) * width
                for position in positions
            ]
            axis.bar(
                offsets,
                means,
                width,
                yerr=[lower_errors, upper_errors],
                capsize=3,
                label=label,
            )
        axis.set_xticks(positions, labels=tools)
        axis.set_ylabel("Mean per-testcase coefficient of variation (%)")
        axis.set_title(
            f"Within-testcase repeatability with "
            f"{summary['confidence_level']:.0%} testcase-bootstrap intervals"
        )
        axis.legend(loc="best")
        axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)


def _plot_paired_overhead(
    summary: Mapping[str, Any],
    output_file: Path,
    overhead_summary: Mapping[str, Any],
    overhead_key: str,
    ylabel: str,
    chart_title: str,
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tools = [
        tool
        for tool, data in overhead_summary.items()
        if data[overhead_key]["average"] is not None
    ]
    figure, axis = plt.subplots(figsize=(max(7, 1.8 * len(tools)), 5))
    if not tools:
        axis.text(
            0.5,
            0.5,
            "No paired measurements with the native baseline",
            ha="center",
            va="center",
            transform=axis.transAxes,
        )
        axis.set_axis_off()
    else:
        averages = []
        lower_errors = []
        upper_errors = []
        for tool in tools:
            statistics = overhead_summary[tool][overhead_key]
            average = statistics["average"]
            interval = statistics["confidence_interval"]
            averages.append(average)
            if interval is None:
                lower_errors.append(0)
                upper_errors.append(0)
            else:
                lower_errors.append(max(0.0, average - interval["lower"]))
                upper_errors.append(max(0.0, interval["upper"] - average))
        axis.bar(
            tools,
            averages,
            yerr=[lower_errors, upper_errors],
            capsize=4,
            color="#ED7D31",
        )
        axis.axhline(0, color="black", linewidth=0.8)
        axis.set_ylabel(ylabel)
        axis.set_title(
            f"{chart_title} with {summary['confidence_level']:.0%} confidence intervals"
        )
        axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)


def _overhead_tool_flavor_summaries(
    summary: Mapping[str, Any], metric: str
) -> dict[str, Mapping[str, Any]]:
    result = {}
    for flavor, flavor_summary in summary["overhead_vs_native"]["by_flavor"].items():
        overhead_summary = flavor_summary[metric]["by_tool"]
        result.update(
            {
                f"{tool} ({flavor})": tool_summary
                for tool, tool_summary in overhead_summary.items()
            }
        )
    return result


def _plot_overhead_boxplot(
    summary: Mapping[str, Any],
    output_file: Path,
    metric: str,
    value_key: str,
    ylabel: str,
    title: str,
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    tool_summaries = _overhead_tool_flavor_summaries(summary, metric)
    labels = []
    values_by_tool = []
    for tool, tool_summary in tool_summaries.items():
        values = [
            testcase[value_key]
            for testcase in tool_summary["testcase_estimates"]
            if testcase[value_key] is not None
        ]
        if values:
            labels.append(tool)
            values_by_tool.append(values)

    figure, axis = plt.subplots(figsize=(max(7, 1.8 * len(labels)), 5))
    if not values_by_tool:
        axis.text(
            0.5,
            0.5,
            "No paired testcase estimates available",
            ha="center",
            va="center",
            transform=axis.transAxes,
        )
        axis.set_axis_off()
    else:
        axis.boxplot(values_by_tool, showfliers=True)
        axis.set_xticks(range(1, len(labels) + 1), labels=labels)
        if all(value > 0 for values in values_by_tool for value in values):
            axis.set_yscale("log")
        axis.set_ylabel(ylabel)
        axis.set_title(title)
        axis.tick_params(axis="x", rotation=25)
        axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)


def _plot_detection_heatmap(summary: Mapping[str, Any], output_file: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import BoundaryNorm, ListedColormap
    from matplotlib.patches import Patch

    detection_by_flavor = summary["testcase_detection"]["by_flavor"]
    tools = list(summary["by_tool"])
    case_details: dict[tuple[str, str, str, str], dict[str, Mapping[str, Any]]] = (
        defaultdict(dict)
    )
    for flavor, flavor_tools in detection_by_flavor.items():
        for tool, cases in flavor_tools.items():
            for case in cases:
                key = (
                    str(case["testcase_id"]),
                    str(case["cwe"]),
                    flavor,
                    str(case["stdin_data"]),
                )
                case_details[key][tool] = case
    ordered_cases = sorted(case_details)

    figure, axis = plt.subplots(
        figsize=(max(11, 2.5 * len(tools) + 5), max(5, 0.34 * len(ordered_cases) + 2))
    )
    if not tools or not ordered_cases:
        axis.text(
            0.5,
            0.5,
            "No testcase classifications available",
            ha="center",
            va="center",
            transform=axis.transAxes,
        )
        axis.set_axis_off()
    else:
        outcome_labels = ("TP", "FP", "TN", "FN", "N/A")
        outcome_colors = ("#70AD47", "#ED7D31", "#5B9BD5", "#C00000", "#BFBFBF")
        outcome_indices = {label: index for index, label in enumerate(outcome_labels)}
        matrix = []
        annotations = []
        for case_key in ordered_cases:
            case_outcomes = []
            case_annotations = []
            for tool in tools:
                outcome = case_details[case_key].get(tool, {}).get("classification")
                label = outcome if outcome in outcome_indices else "N/A"
                case_outcomes.append(outcome_indices[label])
                case_annotations.append(label)
            matrix.append(case_outcomes)
            annotations.append(case_annotations)

        axis.imshow(
            matrix,
            aspect="auto",
            cmap=ListedColormap(outcome_colors),
            norm=BoundaryNorm(range(len(outcome_labels) + 1), len(outcome_labels)),
        )
        axis.set_xticks(range(len(tools)), labels=tools)
        axis.set_yticks(
            range(len(ordered_cases)),
            labels=[
                f"{_short_testcase_name(case_key[0])} [{case_key[1]}, {case_key[2]}]"
                for case_key in ordered_cases
            ],
        )
        axis.set_xlabel("Tool")
        axis.set_ylabel("Testcase and flavor")
        axis.tick_params(axis="x", labelsize=10)
        axis.tick_params(axis="y", labelsize=8)
        for row_index, row in enumerate(annotations):
            for column_index, label in enumerate(row):
                axis.text(
                    column_index,
                    row_index,
                    label,
                    ha="center",
                    va="center",
                    color="white" if label == "FN" else "black",
                    fontsize=8,
                )
        figure.legend(
            handles=[
                Patch(facecolor=color, label=label)
                for label, color in zip(outcome_labels, outcome_colors)
            ],
            loc="lower center",
            ncol=len(outcome_labels),
            frameon=False,
            bbox_to_anchor=(0.6, 0.005),
        )
        axis.set_title("First-run testcase classification")
        figure.subplots_adjust(left=0.24, right=0.98, top=0.93, bottom=0.13)
    if not tools or not ordered_cases:
        figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)


def _short_testcase_name(testcase_id: str) -> str:
    filename = Path(testcase_id).name
    stem = Path(filename).stem
    if "__" in stem:
        return stem.rsplit("__", 1)[1]
    return stem


def _plot_detection_stability_heatmap(
    summary: Mapping[str, Any], output_file: Path, flavor: str
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    flavor_details = summary["testcase_detection"]["by_flavor"].get(flavor, {})
    tools = sorted(flavor_details)
    cases_by_key: dict[tuple[str, str, str], dict[str, Mapping[str, Any]]] = (
        defaultdict(dict)
    )
    for tool, cases in flavor_details.items():
        for case in cases:
            key = (
                str(case["testcase_id"]),
                str(case["cwe"]),
                str(case["stdin_data"]),
            )
            cases_by_key[key][tool] = case
    ordered_cases = sorted(cases_by_key)

    figure, axis = plt.subplots(
        figsize=(max(11, 2.1 * len(tools) + 5), max(5, 0.34 * len(ordered_cases) + 2))
    )
    if not tools or not ordered_cases:
        axis.text(
            0.5,
            0.5,
            f"No {flavor} testcase detection runs available",
            ha="center",
            va="center",
            transform=axis.transAxes,
        )
        axis.set_axis_off()
    else:
        matrix = []
        annotations = []
        for case_key in ordered_cases:
            case_rates = []
            case_annotations = []
            for tool in tools:
                case = cases_by_key[case_key].get(tool)
                rate = case.get("detection_rate") if case else None
                case_rates.append(float("nan") if rate is None else rate)
                if case is None or case["valid_executions"] == 0:
                    case_annotations.append("N/A")
                else:
                    case_annotations.append(
                        f"{case['detected_executions']}/{case['valid_executions']}"
                    )
            matrix.append(case_rates)
            annotations.append(case_annotations)

        colormap = plt.cm.viridis.copy()
        colormap.set_bad("#BFBFBF")
        image = axis.imshow(
            matrix,
            aspect="auto",
            cmap=colormap,
            vmin=0,
            vmax=1,
        )
        axis.set_xticks(range(len(tools)), labels=tools)
        axis.set_yticks(
            range(len(ordered_cases)),
            labels=[
                f"{_short_testcase_name(case[0])} [{case[1]}]" for case in ordered_cases
            ],
        )
        axis.set_xlabel("Tool")
        axis.set_ylabel("Testcase")
        axis.tick_params(axis="x", labelsize=10)
        axis.tick_params(axis="y", labelsize=8)
        for row_index, row in enumerate(annotations):
            for column_index, label in enumerate(row):
                rate = matrix[row_index][column_index]
                axis.text(
                    column_index,
                    row_index,
                    label,
                    ha="center",
                    va="center",
                    color=("white" if label != "N/A" and rate < 0.5 else "black"),
                    fontsize=8,
                )
        figure.colorbar(
            image,
            ax=axis,
            label="Fraction of valid runs with a detection",
            fraction=0.046,
            pad=0.04,
        )
        axis.set_title(f"Run-to-run detection stability ({flavor})")
        figure.subplots_adjust(left=0.24, right=0.88, top=0.93, bottom=0.10)
    if not tools or not ordered_cases:
        figure.tight_layout()
    figure.savefig(output_file, dpi=160)
    plt.close(figure)
