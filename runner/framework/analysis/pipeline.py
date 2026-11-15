"""Coordinate analysis and export of summaries and charts."""

import json
import logging
from pathlib import Path
from typing import Any

from .inputs import load_results
from .plots import (
    _overhead_tool_flavor_summaries,
    _plot_confusion_matrices,
    _plot_detection_heatmap,
    _plot_detection_rates,
    _plot_detection_stability_heatmap,
    _plot_overhead_boxplot,
    _plot_paired_overhead,
    _plot_performance,
    _plot_repeatability,
)
from .statistics import analyze_results

logger = logging.getLogger("framework.analyzer")


def generate_analysis(
    input_file: Path, output_dir: Path, confidence_level: float = 0.95
) -> dict[str, Any]:
    """Analyze a JSON or CSV report and write summary JSON plus charts."""
    rows = load_results(input_file)
    summary = analyze_results(rows, confidence_level)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_file = output_dir / "summary.json"
    with summary_file.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2, allow_nan=False)
        file.write("\n")

    Path(output_dir / "detection").mkdir(exist_ok=True)
    Path(output_dir / "performance").mkdir(exist_ok=True)
    Path(output_dir / "repeatability").mkdir(exist_ok=True)
    Path(output_dir / "wall_clock").mkdir(exist_ok=True)
    Path(output_dir / "peak_rss").mkdir(exist_ok=True)
    _plot_confusion_matrices(summary, output_dir / "confusion_matrix.png")
    _plot_detection_rates(summary, output_dir / "detection/detection_rates.png")
    _plot_performance(summary, output_dir / "performance/performance.png")
    _plot_repeatability(summary, output_dir / "repeatability/repeatability.png")
    _plot_detection_heatmap(summary, output_dir / "detection/detection_heatmap.png")
    for flavor in ("good", "bad"):
        _plot_detection_stability_heatmap(
            summary, output_dir / f"detection/detection_stability_{flavor}.png", flavor
        )
    _plot_overhead_boxplot(
        summary,
        output_dir / "wall_clock/wall_clock_slowdown_boxplot.png",
        "wall_clock_time_s",
        "slowdown_factor",
        "Median per-testcase slowdown vs. native (x)",
        "Paired wall-clock slowdown by testcase and flavor",
    )
    _plot_overhead_boxplot(
        summary,
        output_dir / "peak_rss/peak_rss_multiplier_boxplot.png",
        "peak_rss_kb",
        "memory_multiplier",
        "Median per-testcase peak RSS multiplier vs. native (x)",
        "Paired peak RSS multiplier by testcase and flavor",
    )
    _plot_paired_overhead(
        summary,
        output_dir / "wall_clock/wall_clock_overhead.png",
        _overhead_tool_flavor_summaries(summary, "wall_clock_time_s"),
        "wall_clock_overhead_percent",
        "Wall-clock overhead vs. native (%)",
        "Paired execution overhead by flavor",
    )
    _plot_paired_overhead(
        summary,
        output_dir / "peak_rss/peak_rss_overhead.png",
        _overhead_tool_flavor_summaries(summary, "peak_rss_kb"),
        "peak_rss_overhead_percent",
        "Peak RSS overhead vs. native (%)",
        "Paired peak RSS overhead by flavor",
    )
    logger.info("Analysis summary and charts saved to %s", output_dir)
    return summary
