"""Load and validate benchmark result exports."""

import csv
import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .constants import PERFORMANCE_METRICS


def _as_bool(value: Any, field: str, row_number: int) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "1", "yes"):
            return True
        if normalized in ("false", "0", "no"):
            return False
    raise ValueError(f"Row {row_number}: {field} must be a boolean value")


def _as_int(
    value: Any,
    field: str,
    row_number: int,
    default: int | None,
    minimum: int | None = None,
) -> int | None:
    if value in (None, ""):
        return default
    try:
        numeric_value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Row {row_number}: {field} must be an integer") from exc
    if minimum is not None and numeric_value < minimum:
        raise ValueError(f"Row {row_number}: {field} must be at least {minimum}")
    return numeric_value


def _normalize_record(record: Mapping[str, Any], row_number: int) -> dict[str, Any]:
    tool_name = record.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError(f"Row {row_number}: tool_name must be a non-empty string")

    test_case = record.get("test_case", {})
    if not isinstance(test_case, Mapping):
        raise TypeError(f"Row {row_number}: test_case must be an object")

    flavor = str(test_case.get("flavor", record.get("flavor", ""))).strip().lower()
    if flavor not in ("bad", "good"):
        raise ValueError(f"Row {row_number}: flavor must be 'bad' or 'good'")

    detected = _as_bool(record.get("detected"), "detected", row_number)
    outcome = str(record.get("outcome", "")).strip().upper()
    raw_metrics = record.get("metrics")
    if raw_metrics is None:
        raw_metrics = record
    if not isinstance(raw_metrics, Mapping):
        raise TypeError(f"Row {row_number}: metrics must be an object")

    testcase_id = test_case.get(
        "path",
        record.get("testcase_path", record.get("testcase", "")),
    )
    stdin_data = test_case.get("stdin_data", record.get("stdin_data"))
    if stdin_data is None:
        stdin_data = ""
    elif not isinstance(stdin_data, str):
        raise TypeError(f"Row {row_number}: stdin_data must be a string")

    metrics: dict[str, float | None] = {}
    for metric in PERFORMANCE_METRICS:
        value = raw_metrics.get(metric)
        if value in (None, ""):
            metrics[metric] = None
            continue
        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Row {row_number}: {metric} must be numeric") from exc
        if not math.isfinite(numeric_value) or numeric_value < 0:
            raise ValueError(
                f"Row {row_number}: {metric} must be finite and non-negative"
            )
        metrics[metric] = numeric_value

    return {
        "tool_name": tool_name.strip(),
        "cwe": str(test_case.get("cwe", record.get("cwe", "CWE-UNKNOWN"))),
        "testcase_id": str(testcase_id),
        "flavor": flavor,
        "stdin_data": stdin_data,
        "detected": detected,
        "outcome": outcome,
        "repetition": _as_int(record.get("repetition"), "repetition", row_number, 1, 0),
        "tool_order": _as_int(record.get("tool_order"), "tool_order", row_number, 1, 0),
        "planned_repetitions": _as_int(
            record.get("planned_repetitions"), "planned_repetitions", row_number, 1, 1
        ),
        "random_seed": _as_int(
            record.get("random_seed"), "random_seed", row_number, None
        ),
        "metrics": metrics,
    }


def load_results(input_file: Path) -> list[dict[str, Any]]:
    """Load and normalize benchmark results from the framework's JSON or CSV export."""
    if input_file.suffix.lower() == ".json":
        with input_file.open(encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, dict):
            data = data.get("results")
        if not isinstance(data, list):
            raise ValueError(
                "JSON input must be a result list or an object containing a 'results' list"
            )
        rows = data
    elif input_file.suffix.lower() == ".csv":
        with input_file.open(newline="", encoding="utf-8") as file:
            rows = list(csv.DictReader(file))
    else:
        raise ValueError("Input file must have a .json or .csv extension")

    normalized = []
    for row_number, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            raise TypeError(f"Row {row_number}: result must be an object")
        normalized.append(_normalize_record(row, row_number))
    return normalized
