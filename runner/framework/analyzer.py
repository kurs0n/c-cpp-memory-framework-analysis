"""Backward-compatible imports for the benchmark analysis package."""

from runner.framework.analysis import analyze_results, generate_analysis, load_results
from runner.framework.analysis.constants import (
    BOOTSTRAP_ITERATIONS,
    BOOTSTRAP_SEED,
    OUTCOMES,
    PERFORMANCE_METRICS,
)

__all__ = [
    "BOOTSTRAP_ITERATIONS",
    "BOOTSTRAP_SEED",
    "OUTCOMES",
    "PERFORMANCE_METRICS",
    "analyze_results",
    "generate_analysis",
    "load_results",
]
