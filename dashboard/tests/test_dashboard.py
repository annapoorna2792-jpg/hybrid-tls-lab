from pathlib import Path

from fastapi.testclient import TestClient

from app.analytics import percentile, summarize
from app.main import create_app


def test_percentile_uses_linear_interpolation():
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([], 95) is None


def test_summary_compares_mode_medians():
    rows = [
        {"mode": "classical", "success": True, "client_handshake_us": 100, "server_handshake_us": 80},
        {"mode": "classical", "success": True, "client_handshake_us": 200, "server_handshake_us": 90},
        {"mode": "hybrid", "success": True, "client_handshake_us": 300, "server_handshake_us": 180},
        {"mode": "hybrid", "success": True, "client_handshake_us": 400, "server_handshake_us": 190},
    ]
    result = summarize(rows)
    assert result["modes"]["classical"]["metrics"]["client_handshake_us"]["p50"] == 150
    assert result["comparison"]["client_handshake_us"]["delta"] == 200


def test_server_and_client_measurements_merge(tmp_path: Path):
    app = create_app(tmp_path / "benchmark.db")
    client = TestClient(app)
    run = {"run_id": "run-1", "iterations": 1, "warmup": 0, "openssl_version": "OpenSSL test"}
    assert client.post("/api/runs", json=run).status_code == 201
    server = {
        "sample_id": "run-1-hybrid-1", "run_id": "run-1", "mode": "hybrid",
        "expected_group": "X25519MLKEM768", "negotiated_group": "X25519MLKEM768",
        "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "server_handshake_us": 240,
    }
    measured = {
        **{key: server[key] for key in ("sample_id", "run_id", "mode", "expected_group", "negotiated_group", "tls_version", "cipher")},
        "client_tcp_us": 30, "client_handshake_us": 300, "client_ttfb_us": 350,
        "client_total_us": 390, "bytes_sent": 1500, "bytes_received": 2300, "success": True,
    }
    assert client.post("/api/measurements/server", json=server).status_code == 201
    assert client.post("/api/measurements/client", json=measured).status_code == 201
    data = client.get("/api/dashboard?run_id=run-1").json()
    assert data["recent"][0]["server_handshake_us"] == 240
    assert data["recent"][0]["client_handshake_us"] == 300
    assert data["summary"]["modes"]["hybrid"]["successes"] == 1
    assert client.get("/").status_code == 200
    assert "X25519MLKEM768" in client.get("/").text

