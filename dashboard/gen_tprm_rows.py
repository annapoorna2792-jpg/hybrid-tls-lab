#!/usr/bin/env python3
"""
gen_tprm_rows.py

Derives the TPRM Tier badge from the four underlying TLS findings columns
instead of hand-assigning it, so the tier can't drift out of sync with the
data next to it.

Usage:
    python3 gen_tprm_rows.py vendors.csv > rows.html

CSV columns expected (header row required):
    vendor,tls13,pqc,pqc_provider,static_rsa,weak_cipher,curves

Where tls13 / static_rsa / weak_cipher are "Yes"/"No", and pqc is either
"No" or "Yes (<provider>)" — if pqc starts with "Yes", pqc_provider can be
left blank and it'll be parsed out, or you can supply it separately.

Tiering rule (defensible, derived from findings — not hardcoded per vendor):
    Tier 3 — Remediation Required:
        static_rsa == Yes  OR  weak_cipher == Yes  OR  tls13 == No
    Tier 1 — Ready:
        tls13 == Yes AND pqc == Yes AND static_rsa == No AND weak_cipher == No
    Tier 2 — Conditional:
        everything else (i.e. tls13 Yes, no static RSA, no weak cipher,
        but PQC not yet supported — the only gap is future-readiness)
"""
import csv
import sys
import re


def yn(val: str) -> bool:
    return val.strip().lower().startswith("y")


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
    pqc_raw = pqc_raw.strip()
    if not yn(pqc_raw):
        return "No"
    m = re.match(r"yes\s*\((.+)\)", pqc_raw, re.IGNORECASE)
    if m:
        return f"Yes ({m.group(1)})"
    if provider.strip():
        return f"Yes ({provider.strip()})"
    return "Yes"


def render_row(row: dict) -> str:
    css_class, label = derive_tier(row)
    tls13 = "Yes" if yn(row["tls13"]) else "No"
    static_rsa = "Yes" if yn(row["static_rsa"]) else "No"
    weak_cipher = "Yes" if yn(row["weak_cipher"]) else "No"
    pqc_col = pqc_display(row["pqc"], row.get("pqc_provider", ""))
    curves = row["curves"].strip()

    return (
        f'        <tr><td>{row["vendor"].strip()}</td>'
        f'<td>{tls13}</td>'
        f'<td>{pqc_col}</td>'
        f'<td>{static_rsa}</td>'
        f'<td>{weak_cipher}</td>'
        f'<td>{curves}</td>'
        f'<td><span class="badge {css_class}">{label}</span></td></tr>'
    )


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 gen_tprm_rows.py vendors.csv", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            print(render_row(row))


if __name__ == "__main__":
    main()
