"""
app/hndl.py

Harvest-Now-Decrypt-Later (HNDL) exposure engine.

HNDL logic: a target's crypto posture (from app.qvi / app.tprm) only
matters if the data it protects is (a) sensitive and (b) still
confidential when a cryptographically-relevant quantum computer (CRQC)
arrives. A weak-crypto vendor holding data with a 1-year retention window
is lower urgency than one holding 10-year KYC/AML records, because the
retention window may close before the threat materializes.

DATA REQUIREMENTS (currently unfilled):
  This module needs two inputs this codebase does not yet have:
    1. Data sensitivity classification per target (PII / PCI / etc.)
    2. Data retention lifespan per target (years data must stay confidential)
  These are read from app/data/hndl_inputs.csv, joined by target name to
  the same rows app.qvi.load_targets() returns. Until that CSV is filled
  in, every target renders as "UNCLASSIFIED" rather than a fabricated
  number — do not invent sensitivity/retention values in this module.

THREAT HORIZON:
  CRQC_ARRIVAL_YEARS_MIN/MAX below is a commonly-cited *range* in PQC
  migration literature (roughly 8-15 years from a PQC migration's start),
  not a precise prediction. Treat it as a configurable assumption, not a
  hard fact — replace with your organization's own risk-committee estimate
  if one exists.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HNDL_INPUTS_CSV = Path(__file__).parent / "data" / "hndl_inputs.csv"

# Configurable assumption — not a prediction. See module docstring.
CRQC_ARRIVAL_YEARS_MIN = 8
CRQC_ARRIVAL_YEARS_MAX = 15

REMEDIATION_COST_WEIGHT = {"S": 1, "M": 3, "L": 8}


def _current_year() -> int:
    return datetime.now(timezone.utc).year


def load_hndl_inputs(csv_path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the sensitivity/retention/cost stub CSV, keyed by target name.
    Missing file or missing rows are both fine — callers get "unclassified"
    defaults rather than an error."""
    path = csv_path or HNDL_INPUTS_CSV
    inputs: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return inputs
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            target = (row.get("target") or "").strip()
            if not target:
                continue
            retention_raw = (row.get("retention_years") or "").strip()
            inputs[target] = {
                "data_sensitivity": (row.get("data_sensitivity") or "").strip().upper() or "UNCLASSIFIED",
                "retention_years": int(retention_raw) if retention_raw.isdigit() else None,
                "remediation_cost": (row.get("remediation_cost") or "").strip().upper() or None,
            }
    return inputs


def build_exposure(targets: list[dict], hndl_inputs: dict[str, dict[str, Any]] | None = None) -> list[dict]:
    """Join QVI-scored targets (app.qvi.load_targets()) with HNDL inputs and
    compute a residual exposure record per target."""
    inputs = hndl_inputs if hndl_inputs is not None else load_hndl_inputs()
    year = _current_year()
    records = []
    for t in targets:
        stub = inputs.get(t["target"], {
            "data_sensitivity": "UNCLASSIFIED",
            "retention_years": None,
            "remediation_cost": None,
        })
        posture_at_risk = t["tier_class"] != "tier1"
        sensitivity_at_risk = stub["data_sensitivity"] not in ("UNCLASSIFIED", "NONE")

        exposure_closes_year = (year + stub["retention_years"]) if stub["retention_years"] is not None else None
        # Exposure only matters if data outlives the low end of the threat window.
        still_confidential_at_threat = (
            exposure_closes_year is not None and exposure_closes_year >= (year + CRQC_ARRIVAL_YEARS_MIN)
        )

        if stub["retention_years"] is None or stub["data_sensitivity"] == "UNCLASSIFIED":
            status = "UNCLASSIFIED — needs data owner input"
        elif posture_at_risk and sensitivity_at_risk and still_confidential_at_threat:
            status = "EXPOSED"
        elif posture_at_risk and sensitivity_at_risk and not still_confidential_at_threat:
            status = "LOW URGENCY — retention ends before estimated threat window"
        else:
            status = "NOT EXPOSED — posture or sensitivity clear"

        records.append({
            **t,
            "data_sensitivity": stub["data_sensitivity"],
            "retention_years": stub["retention_years"],
            "remediation_cost": stub["remediation_cost"],
            "exposure_closes_year": exposure_closes_year,
            "exposure_status": status,
        })
    return records


def exposure_summary(records: list[dict]) -> dict:
    exposed = sum(1 for r in records if r["exposure_status"] == "EXPOSED")
    unclassified = sum(1 for r in records if "UNCLASSIFIED" in r["exposure_status"])
    return {
        "total": len(records),
        "exposed": exposed,
        "unclassified": unclassified,
        "threat_window": f"{CRQC_ARRIVAL_YEARS_MIN}-{CRQC_ARRIVAL_YEARS_MAX} years (assumption, see docs)",
    }
