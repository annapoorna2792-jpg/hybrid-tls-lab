"""
app/compliance.py

Regulatory Compliance Mapper.

Requirement text and citations below are sourced (see comments per mandate).
The `check` logic only checks what the scanner already measures (TLS 1.3,
PQC negotiated, no static RSA / weak ciphers) — it is a rough technical
proxy for "would probably satisfy a PQC-related control", not a legal
compliance determination.
"""
from __future__ import annotations

from typing import Any, Callable

MANDATES: list[dict[str, Any]] = [
    {
        "id": "fips203",
        "name": "NIST FIPS 203 (ML-KEM)",
        "jurisdiction": "US / international reference standard",
        "requirement_text": (
            "FIPS 203 is NIST's Module-Lattice-Based Key-Encapsulation "
            "Mechanism Standard (published August 2024), specifying "
            "ML-KEM as the standardized post-quantum key-establishment "
            "algorithm — the successor to classical ECDH/RSA key exchange "
            "once agencies and regulated sectors begin PQC migration."
        ),
        "citation": "NIST FIPS 203 — https://csrc.nist.gov/pubs/fips/203/final",
        "check": lambda t: t["pqc"] != "No",
    },
    {
        "id": "rbi_qsafe",
        "name": "RBI Q-SAFE",
        "jurisdiction": "India / BFSI",
        "requirement_text": (
            "RBI has not issued a binding PQC mandate. On 25 May 2026 it "
            "constituted an eight-member Expert Committee for a Quantum "
            "Secure and Adaptive Financial Ecosystem (Q-SAFE), chaired by "
            "Prof. Anil Prabhakar (IIT Madras), to map the sector's "
            "cryptographic inventory (via a Cryptography Bill of "
            "Materials), assess crypto-agility, and review vendor "
            "readiness — report due within six months of its first "
            "meeting. This check is a readiness proxy against Q-SAFE's "
            "likely direction, not compliance with an existing rule."
        ),
        "citation": "RBI press release, Expert Committee for Q-SAFE (25 May 2026) — https://www.rbi.org.in",
        "check": lambda t: t["tls13"] == "Yes" and t["pqc"] != "No",
    },
    {
        "id": "eu_dora",
        "name": "EU DORA",
        "jurisdiction": "EU / financial entities & ICT third parties",
        "requirement_text": (
            "DORA (Regulation (EU) 2022/2554) has been in force since "
            "17 January 2025. Articles 28-30 require financial entities "
            "to maintain a register of ICT third-party arrangements, "
            "perform pre-contract due diligence, and include mandatory "
            "cryptography/resilience provisions in contracts with "
            "critical ICT providers — extending cryptographic assurance "
            "obligations to vendors, not just the regulated entity itself."
        ),
        "citation": "Regulation (EU) 2022/2554, Articles 28-30 — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554",
        "check": lambda t: t["tls13"] == "Yes" and t["static_rsa"] == "No" and t["weak_cipher"] == "No",
    },
]


def compute_compliance(targets: list[dict]) -> list[dict]:
    """For each target, evaluate every mandate's check() against it."""
    results = []
    for t in targets:
        mandate_results = []
        for m in MANDATES:
            try:
                passed = bool(m["check"](t))
            except Exception:
                passed = False
            mandate_results.append({
                "id": m["id"],
                "name": m["name"],
                "passed": passed,
            })
        results.append({
            "target": t.get("target", t.get("vendor")),
            "mandates": mandate_results,
        })
    return results


def compliance_summary(compliance_results: list[dict]) -> dict:
    """Aggregate pass/fail counts per mandate, plus mandate metadata for display."""
    per_mandate = {
        m["id"]: {"pass": 0, "fail": 0}
        for m in MANDATES
    }
    for r in compliance_results:
        for mr in r["mandates"]:
            key = "pass" if mr["passed"] else "fail"
            per_mandate[mr["id"]][key] += 1
    return {
        "mandates": MANDATES,
        "per_mandate": per_mandate,
    }
