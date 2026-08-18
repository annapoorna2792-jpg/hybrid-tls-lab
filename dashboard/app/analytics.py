from __future__ import annotations

import math
import statistics
from collections.abc import Iterable
from typing import Any


MODES = ("classical", "hybrid")
METRICS = (
    "client_tcp_us",
    "client_handshake_us",
    "server_handshake_us",
    "client_ttfb_us",
    "client_total_us",
    "bytes_sent",
    "bytes_received",
)


def percentile(values: list[float], percentile_value: float) -> float | None:
    """Return a linearly interpolated percentile for a sorted or unsorted sample."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile_value / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def describe(values: Iterable[float | int | None]) -> dict[str, float | int | None]:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return {"count": 0, "mean": None, "p50": None, "p95": None, "p99": None, "min": None, "max": None}
    return {
        "count": len(clean),
        "mean": statistics.fmean(clean),
        "p50": percentile(clean, 50),
        "p95": percentile(clean, 95),
        "p99": percentile(clean, 99),
        "min": min(clean),
        "max": max(clean),
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {"modes": {}, "comparison": {}}
    for mode in MODES:
        mode_rows = [row for row in rows if row["mode"] == mode]
        successful = [row for row in mode_rows if row["success"]]
        output["modes"][mode] = {
            "samples": len(mode_rows),
            "successes": len(successful),
            "failures": len(mode_rows) - len(successful),
            "metrics": {metric: describe(row.get(metric) for row in successful) for metric in METRICS},
        }

    classical = output["modes"]["classical"]["metrics"]
    hybrid = output["modes"]["hybrid"]["metrics"]
    for metric in METRICS:
        classical_p50 = classical[metric]["p50"]
        hybrid_p50 = hybrid[metric]["p50"]
        if classical_p50 is None or hybrid_p50 is None:
            output["comparison"][metric] = {"delta": None, "percent": None}
            continue
        delta = hybrid_p50 - classical_p50
        percent = (delta / classical_p50 * 100) if classical_p50 else None
        output["comparison"][metric] = {"delta": delta, "percent": percent}
    return output

