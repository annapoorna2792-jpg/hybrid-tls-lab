from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Mode = Literal["classical", "hybrid"]


class RunCreate(BaseModel):
    run_id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.-]+$")
    client_name: str = Field(default="openssl-client", max_length=120)
    openssl_version: str | None = Field(default=None, max_length=240)
    iterations: int | None = Field(default=None, ge=1, le=1_000_000)
    warmup: int | None = Field(default=None, ge=0, le=100_000)
    notes: str | None = Field(default=None, max_length=500)


class ServerMeasurement(BaseModel):
    sample_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.-]+$")
    run_id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.-]+$")
    mode: Mode
    expected_group: str = Field(min_length=1, max_length=80)
    negotiated_group: str | None = Field(default=None, max_length=80)
    tls_version: str | None = Field(default=None, max_length=40)
    cipher: str | None = Field(default=None, max_length=100)
    server_handshake_us: int = Field(ge=0, le=120_000_000)


class ClientMeasurement(BaseModel):
    sample_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.-]+$")
    run_id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.-]+$")
    mode: Mode
    expected_group: str = Field(min_length=1, max_length=80)
    negotiated_group: str | None = Field(default=None, max_length=80)
    tls_version: str | None = Field(default=None, max_length=40)
    cipher: str | None = Field(default=None, max_length=100)
    client_tcp_us: int | None = Field(default=None, ge=0, le=120_000_000)
    client_handshake_us: int | None = Field(default=None, ge=0, le=120_000_000)
    client_ttfb_us: int | None = Field(default=None, ge=0, le=120_000_000)
    client_total_us: int | None = Field(default=None, ge=0, le=120_000_000)
    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)
    success: bool
    error: str | None = Field(default=None, max_length=1000)

