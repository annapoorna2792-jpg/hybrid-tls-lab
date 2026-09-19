"""
app/score.py

Quantum risk scoring for scan targets. Implements the weighted formula
referenced in app/qvi.py: measured crypto posture combined with regulatory
data-retention class, producing a 0-100 score and a ranked remediation order.

  F1  key exchange           0-40   no TLS 1.3 = 40, classical = 38, hybrid = 5
  F2  certificate signature  0-35   RSA = 35, ECDSA = 30, post-quantum = 3
  F3  data lifetime          0-25   by regulatory retention class
  P1  static RSA accepted     +10   loss of forward secrecy
"""
from __future__ import annotations
from pathlib import Path
import json
from .tprm import load_vendors
from .hndl import load_hndl_inputs

_CERT_CACHE = None


def _certs():
    """Certificate details live in the scan output, not in vendors.csv."""
    global _CERT_CACHE
    if _CERT_CACHE is None:
        _CERT_CACHE = {}
        for name in ("measured_scan.json", "measured_full.json"):
            f = Path(__file__).resolve().parent / "data" / name
            if not f.exists():
                continue
            try:
                doc = json.loads(f.read_text())
            except Exception:
                continue
            for rec in doc.get("results", doc if isinstance(doc, list) else []):
                lab = rec.get("label")
                cert = rec.get("certificate") or {}
                if lab:
                    _CERT_CACHE[lab] = {
                        "cert_key": cert.get("cert_key") or "",
                        "cert_sig_alg": cert.get("cert_sig_alg") or "",
                        "_tls13": rec.get("tls13"),
                        "_pqc": rec.get("pqc"),
                        "_srsa": rec.get("static_rsa"),
                    }
            if _CERT_CACHE:
                break
    return _CERT_CACHE

BANDS = [("critical", 90, 100, "Critical"), ("high", 63, 89, "High"),
         ("moderate", 0, 62, "Moderate")]


def _yes(v):
    """load_vendors() returns 'Yes'/'No' strings; 'No' is truthy in Python."""
    if isinstance(v, str):
        return v.strip().lower() in ("yes", "true", "1", "y")
    return bool(v)

def _f1(row):
    if not row.get("tls13"):
        return 40, "No TLS 1.3 - cannot negotiate a hybrid group"
    if row.get("pqc"):
        return 5, "Hybrid ML-KEM negotiated"
    return 38, "TLS 1.3, classical key exchange only"

def _f2(row):
    cert = (row.get("cert_key") or row.get("certkey") or "").upper()
    sig = (row.get("cert_sig_alg") or "").lower()
    if "dilithium" in sig or "ml-dsa" in sig or "mldsa" in sig:
        return 3, "Post-quantum certificate signature"
    if cert.startswith("EC") or "ecdsa" in sig:
        return 30, "ECDSA signature - forgeable by Shor"
    return 35, "RSA signature - forgeable by Shor"

def _f3(years, sens):
    if years is None:
        return 25, "Unclassified - scored at the highest retention tier"
    if years >= 25: return 25, f"{sens}, {years}y retention"
    if years >= 15: return 22, f"{sens}, {years}y retention"
    if years >= 8:  return 18, f"{sens}, {years}y retention"
    return 10, f"{sens}, {years}y - closes before the threat window"

def _effort(row):
    if not row.get("tls13"):
        return 3, "No TLS 1.3 - protocol modernisation"
    if not row.get("pqc"):
        return 2, "Classical key exchange - enable a hybrid group"
    if row.get("static_rsa"):
        return 1, "Static RSA accepted - configuration change"
    return 0, "No action available - post-quantum certificate not yet deployable"

def _band(total):
    for code, lo, hi, label in BANDS:
        if lo <= total <= hi:
            return code, label
    return "moderate", "Moderate"

def load_scored(csv_path: Path | None = None, hndl_path: Path | None = None) -> list[dict]:
    rows = load_vendors(csv_path) if csv_path else load_vendors()
    hndl = load_hndl_inputs(hndl_path) if hndl_path else load_hndl_inputs()
    out = []
    for row in rows:
        name = row.get("target") or row.get("vendor")
        scan = _certs().get(name, {})
        # the scan output is authoritative for posture; vendors.csv can lag behind
        row = {**row, **scan,
               "tls13": bool(scan["_tls13"]) if scan.get("_tls13") is not None else _yes(row.get("tls13")),
               "pqc": bool(scan["_pqc"]) if scan.get("_pqc") is not None else _yes(row.get("pqc")),
               "static_rsa": bool(scan["_srsa"]) if scan.get("_srsa") is not None else _yes(row.get("static_rsa")),
               "weak_cipher": _yes(row.get("weak_cipher"))}
        stub = hndl.get(name, {})
        years = stub.get("retention_years")
        sens = stub.get("data_sensitivity") or "unclassified"
        f1, f1r = _f1(row); f2, f2r = _f2(row); f3, f3r = _f3(years, sens)
        pen, penr = (10, "Static RSA accepted - no forward secrecy") if row.get("static_rsa") else (0, "")
        total = min(100, f1 + f2 + f3 + pen)
        code, label = _band(total)
        eff, egap = _effort(row)
        out.append({**row, "target": name, "f1": f1, "f1r": f1r, "f2": f2, "f2r": f2r,
                    "f3": f3, "f3r": f3r, "pen": pen, "penr": penr,
                    "total": total, "band_code": code, "band_label": label,
                    "effort": eff, "effort_reason": egap,
                    "ratio": round(total / eff, 1) if eff else 0.0,
                    "retention_years": years, "data_sensitivity": sens})
    out.sort(key=lambda r: -r["total"])
    return out

def score_summary(rows: list[dict]) -> dict:
    n = len(rows) or 1
    counts = {c: sum(1 for r in rows if r["band_code"] == c) for c, _, _, _ in BANDS}
    remediable = [r for r in rows if r["effort"] > 0]
    return {"n": len(rows), "critical": counts["critical"], "high": counts["high"],
            "moderate": counts["moderate"],
            "avg": round(sum(r["total"] for r in rows) / n),
            "min": min((r["total"] for r in rows), default=0),
            "max": max((r["total"] for r in rows), default=0),
            "pq_ready": sum(1 for r in rows if r.get("pqc")),
            "pq_cert": sum(1 for r in rows if r["f2"] <= 3),
            "static_rsa": sum(1 for r in rows if r.get("static_rsa")),
            "remediable": len(remediable), "no_action": len(rows) - len(remediable),
            "bands": [{"code": c, "label": l, "min": lo, "max": hi, "n": counts[c]}
                      for c, lo, hi, l in BANDS]}
