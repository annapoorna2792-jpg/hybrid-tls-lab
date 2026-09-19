"""
app/cbom.py

Generates a CycloneDX v1.6 CBOM (Cryptography Bill of Materials) JSON
document per scan target.

IMPORTANT: this is a first-pass synthesis built from the same posture
fields QVI scoring uses (tls13 / pqc / curves / static_rsa / weak_cipher).
It is NOT a full static-analysis CBOM — it reflects what the scanner
observed during the handshake, not every crypto asset in the target's
stack. Treat components below as a starting schema; extend as the
scanner stage (step 1 of the pipeline) surfaces more detail.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

CYCLONEDX_SPEC_VERSION = "1.6"


def _component(name: str, asset_type: str, crypto_properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {
            "assetType": asset_type,
            **crypto_properties,
        },
    }


def build_cbom(target: dict) -> dict[str, Any]:
    """Build a CycloneDX v1.6 document for a single scanned target dict
    (as returned by app.qvi.load_targets())."""
    components: list[dict[str, Any]] = []

    components.append(_component(
        "TLS 1.3" if target["tls13"] == "Yes" else "TLS <1.3 (observed)",
        "protocol",
        {"protocolProperties": {"type": "tls", "version": "1.3" if target["tls13"] == "Yes" else "unknown"}},
    ))

    for curve in [c.strip() for c in (target.get("curves") or "").split(",") if c.strip()]:
        components.append(_component(
            curve, "related-crypto-material",
            {"relatedCryptoMaterialProperties": {"type": "key-agreement-parameter"}},
        ))

    if target["pqc"] != "No":
        kem_name = target["pqc"].replace("Yes", "").strip(" ()") or "ML-KEM (unspecified parameter set)"
        components.append(_component(
            kem_name, "algorithm",
            {"algorithmProperties": {"primitive": "kem"}},
        ))

    if target["static_rsa"] == "Yes":
        components.append(_component(
            "Static RSA key exchange (finding)", "algorithm",
            {"algorithmProperties": {"primitive": "kex"}},
        ))

    if target["weak_cipher"] == "Yes":
        components.append(_component(
            "Weak cipher suite (finding)", "algorithm",
            {"algorithmProperties": {"primitive": "cipher"}},
        ))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": target["target"]},
            "properties": [{"name": "qvi:tier", "value": target["qvi_tier_label"]}],
        },
        "components": components,
    }
