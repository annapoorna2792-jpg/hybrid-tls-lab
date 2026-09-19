"""
app/roadmap.py

Remediation prioritization / migration roadmap.

Ranks targets by (rough) risk-reduction-per-dollar: EXPOSED targets with
a cheap remediation cost float to the top; UNCLASSIFIED targets are
called out separately since they can't be ranked responsibly without
data-owner input (sensitivity/retention) and a real cost estimate.

This is intentionally simple arithmetic, not a financial model — cost
weights (S=1, M=3, L=8 in app.hndl.REMEDIATION_COST_WEIGHT) are a rough
t-shirt-size proxy, not dollar figures. Replace with real cost estimates
once available.
"""
from __future__ import annotations

from .hndl import REMEDIATION_COST_WEIGHT

# Simple exposure-status → numeric urgency, used only for ranking within
# this stubbed model — not a validated risk score.
STATUS_WEIGHT = {
    "EXPOSED": 3,
    "LOW URGENCY — retention ends before estimated threat window": 1,
    "NOT EXPOSED — posture or sensitivity clear": 0,
}


def build_roadmap(exposure_records: list[dict]) -> dict:
    rankable = []
    unclassified = []
    for r in exposure_records:
        if "UNCLASSIFIED" in r["exposure_status"]:
            unclassified.append(r)
            continue
        cost = REMEDIATION_COST_WEIGHT.get(r["remediation_cost"] or "", None)
        urgency = STATUS_WEIGHT.get(r["exposure_status"], 0)
        if cost is None:
            unclassified.append(r)
            continue
        score = urgency / cost if cost else 0
        rankable.append({**r, "priority_score": round(score, 2), "cost_weight": cost})

    rankable.sort(key=lambda r: r["priority_score"], reverse=True)
    return {"prioritized": rankable, "needs_input": unclassified}
