"""
app/tprm.py

Derives TPRM Tier from vendor TLS findings. Loaded once at app startup and
passed into the dashboard template context — vendor rows are never
hand-edited into dashboard.html again.
"""
import csv
import re
from pathlib import Path

VENDORS_CSV = Path(__file__).parent / "data" / "vendors.csv"


def yn(val: str) -> bool:
    return (val or "").strip().lower().startswith("y")


def derive_tier(row: dict):
    tls13 = yn(row["tls13"])
    pqc = yn(row["pqc"])
    static_rsa = yn(row["static_rsa"])
    weak_cipher = yn(row["weak_cipher"])

    if static_rsa or weak_cipher or not tls13:
        return "tier3", "Tier 3 — Remediation"
    if tls13 and pqc and not static_rsa and not weak_cipher:
        return "tier1", "Tier 1 — Ready"
    return "tier2", "Tier 2 — Conditional"


def pqc_display(pqc_raw: str, provider: str) -> str:
    pqc_raw = (pqc_raw or "").strip()
    if not yn(pqc_raw):
        return "No"
    m = re.match(r"yes\s*\((.+)\)", pqc_raw, re.IGNORECASE)
    if m:
        return f"Yes ({m.group(1)})"
    if provider and provider.strip():
        return f"Yes ({provider.strip()})"
    return "Yes"


def load_vendors(csv_path: Path = VENDORS_CSV):
    vendors = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tier_class, tier_label = derive_tier(row)
            vendors.append({
                "vendor": row["vendor"].strip(),
                "tls13": "Yes" if yn(row["tls13"]) else "No",
                "pqc": pqc_display(row["pqc"], row.get("pqc_provider", "")),
                "static_rsa": "Yes" if yn(row["static_rsa"]) else "No",
                "weak_cipher": "Yes" if yn(row["weak_cipher"]) else "No",
                "curves": row["curves"].strip(),
                "tier_class": tier_class,
                "tier_label": tier_label,
            })
    return vendors
