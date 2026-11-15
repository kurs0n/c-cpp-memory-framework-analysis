"""Public API for benchmark result analysis."""

from .inputs import load_results
from .pipeline import generate_analysis
from .statistics import analyze_results

__all__ = ["analyze_results", "generate_analysis", "load_results"]
