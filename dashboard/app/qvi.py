"""
app/qvi.py

QVI (Quantum Vulnerability Index) scoring for scan targets.

This does NOT introduce a new scoring formula. It wraps the existing
tls13 / pqc / static_rsa / weak_cipher derivation in app.tprm.derive_tier
and relabels it for the QVI Scoring Matrix page. If/when a real weighted
QVI formula (financial-data-tier x crypto-posture x regulatory-deadline)
exists, replace the body of load_targets() below with that computation —
the shape of the returned dicts should stay the same so templates don't
need to change.
"""
from __future__ import annotations

from pathlib import Path

from .tprm import load_vendors

QVI_TIER_LABELS = {
    "tier1": "QVI Tier 1 \u2014 PQ Ready",
    "tier2": "QVI Tier 2 \u2014 Conditional",
    "tier3": "QVI Tier 3 \u2014 Critical",
}


def load_targets(csv_path: Path | None = None) -> list[dict]:
    """Load scan targets with QVI tier labels applied.

    Reuses tprm.load_vendors() for the underlying TLS/PQC posture
    derivation, then adds QVI-branded fields on top:
      - "target": renamed from "vendor" (display terminology only)
      - "qvi_tier_label": QVI-branded version of "tier_label"

    tier_class ("tier1"/"tier2"/"tier3") is left unchanged so it keeps
    working as a CSS class hook and as the key for qvi_summary().
    """
    rows = load_vendors(csv_path) if csv_path else load_vendors()
    targets = []
    for row in rows:
        targets.append({
            **row,
            "target": row["vendor"],
            "qvi_tier_label": QVI_TIER_LABELS[row["tier_class"]],
        })
    return targets


def qvi_summary(targets: list[dict]) -> dict:
    """Aggregate counts used by the Overview KPI cards and QVI pie chart."""
    counts = {"tier1": 0, "tier2": 0, "tier3": 0}
    for t in targets:
        counts[t["tier_class"]] += 1
    total = len(targets)
    ready_pct = round((counts["tier1"] / total) * 100) if total else 0
    return {
        "total": total,
        "tier1": counts["tier1"],
        "tier2": counts["tier2"],
        "tier3": counts["tier3"],
        "pq_ready_pct": ready_pct,
    }
