from __future__ import annotations

import csv
import io
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .analytics import summarize


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class BenchmarkRepository:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS benchmark_runs (
                    id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    client_name TEXT NOT NULL DEFAULT 'openssl-client',
                    openssl_version TEXT,
                    iterations INTEGER,
                    warmup INTEGER,
                    notes TEXT
                );
                CREATE TABLE IF NOT EXISTS measurements (
                    sample_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES benchmark_runs(id),
                    mode TEXT NOT NULL CHECK(mode IN ('classical','hybrid')),
                    expected_group TEXT NOT NULL,
                    negotiated_group TEXT,
                    tls_version TEXT,
                    cipher TEXT,
                    server_handshake_us INTEGER,
                    client_tcp_us INTEGER,
                    client_handshake_us INTEGER,
                    client_ttfb_us INTEGER,
                    client_total_us INTEGER,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    success INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    server_recorded_at TEXT,
                    client_recorded_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS measurements_run_mode
                    ON measurements(run_id, mode, created_at);
                """
            )

    @staticmethod
    def _ensure_run(db: sqlite3.Connection, run_id: str) -> None:
        db.execute(
            "INSERT OR IGNORE INTO benchmark_runs(id,started_at) VALUES(?,?)",
            (run_id, iso_now()),
        )

    def create_run(self, payload: dict[str, Any]) -> None:
        with self.transaction() as db:
            db.execute(
                """INSERT INTO benchmark_runs(
                       id,started_at,client_name,openssl_version,iterations,warmup,notes
                   ) VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                       client_name=excluded.client_name,
                       openssl_version=excluded.openssl_version,
                       iterations=excluded.iterations,
                       warmup=excluded.warmup,
                       notes=excluded.notes""",
                (
                    payload["run_id"],
                    iso_now(),
                    payload.get("client_name", "openssl-client"),
                    payload.get("openssl_version"),
                    payload.get("iterations"),
                    payload.get("warmup"),
                    payload.get("notes"),
                ),
            )

    def complete_run(self, run_id: str) -> None:
        with self.transaction() as db:
            self._ensure_run(db, run_id)
            db.execute("UPDATE benchmark_runs SET completed_at=? WHERE id=?", (iso_now(), run_id))

    def record_server(self, payload: dict[str, Any]) -> None:
        with self.transaction() as db:
            self._ensure_run(db, payload["run_id"])
            now = iso_now()
            db.execute(
                """INSERT INTO measurements(
                       sample_id,run_id,mode,expected_group,negotiated_group,tls_version,cipher,
                       server_handshake_us,success,server_recorded_at,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,1,?,?)
                   ON CONFLICT(sample_id) DO UPDATE SET
                       negotiated_group=excluded.negotiated_group,
                       tls_version=excluded.tls_version,
                       cipher=excluded.cipher,
                       server_handshake_us=excluded.server_handshake_us,
                       server_recorded_at=excluded.server_recorded_at""",
                (
                    payload["sample_id"],
                    payload["run_id"],
                    payload["mode"],
                    payload["expected_group"],
                    payload.get("negotiated_group"),
                    payload.get("tls_version"),
                    payload.get("cipher"),
                    payload["server_handshake_us"],
                    now,
                    now,
                ),
            )

    def record_client(self, payload: dict[str, Any]) -> None:
        with self.transaction() as db:
            self._ensure_run(db, payload["run_id"])
            now = iso_now()
            db.execute(
                """INSERT INTO measurements(
                       sample_id,run_id,mode,expected_group,negotiated_group,tls_version,cipher,
                       client_tcp_us,client_handshake_us,client_ttfb_us,client_total_us,
                       bytes_sent,bytes_received,success,error,client_recorded_at,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(sample_id) DO UPDATE SET
                       negotiated_group=COALESCE(excluded.negotiated_group,measurements.negotiated_group),
                       tls_version=COALESCE(excluded.tls_version,measurements.tls_version),
                       cipher=COALESCE(excluded.cipher,measurements.cipher),
                       client_tcp_us=excluded.client_tcp_us,
                       client_handshake_us=excluded.client_handshake_us,
                       client_ttfb_us=excluded.client_ttfb_us,
                       client_total_us=excluded.client_total_us,
                       bytes_sent=excluded.bytes_sent,
                       bytes_received=excluded.bytes_received,
                       success=excluded.success,
                       error=excluded.error,
                       client_recorded_at=excluded.client_recorded_at""",
                (
                    payload["sample_id"],
                    payload["run_id"],
                    payload["mode"],
                    payload["expected_group"],
                    payload.get("negotiated_group"),
                    payload.get("tls_version"),
                    payload.get("cipher"),
                    payload.get("client_tcp_us"),
                    payload.get("client_handshake_us"),
                    payload.get("client_ttfb_us"),
                    payload.get("client_total_us"),
                    payload.get("bytes_sent"),
                    payload.get("bytes_received"),
                    int(bool(payload.get("success"))),
                    payload.get("error"),
                    now,
                    now,
                ),
            )

    def runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT r.*,
                          COUNT(m.sample_id) AS samples,
                          SUM(CASE WHEN m.success=1 THEN 1 ELSE 0 END) AS successes
                   FROM benchmark_runs r
                   LEFT JOIN measurements m ON m.run_id=r.id
                   GROUP BY r.id ORDER BY r.started_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def measurements(self, run_id: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM measurements"
        params: list[Any] = []
        if run_id:
            query += " WHERE run_id=?"
            params.append(run_id)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        output = [dict(row) for row in rows]
        for row in output:
            row["success"] = bool(row["success"])
        return output

    def dashboard_data(self, run_id: str | None = None) -> dict[str, Any]:
        selected_run = run_id
        available_runs = self.runs()
        if selected_run is None and available_runs:
            selected_run = available_runs[0]["id"]
        rows = self.measurements(selected_run) if selected_run else []
        return {
            "selected_run": selected_run,
            "runs": available_runs,
            "summary": summarize(rows),
            "recent": rows[:40],
        }

    def csv_export(self, run_id: str | None = None) -> str:
        rows = self.measurements(run_id)
        columns = [
            "sample_id", "run_id", "mode", "expected_group", "negotiated_group", "tls_version", "cipher",
            "server_handshake_us", "client_tcp_us", "client_handshake_us", "client_ttfb_us", "client_total_us",
            "bytes_sent", "bytes_received", "success", "error", "created_at",
        ]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

