from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import BenchmarkRepository
from .schemas import ClientMeasurement, RunCreate, ServerMeasurement


BASE_DIR = Path(__file__).resolve().parent


def create_app(database_path: Path | None = None) -> FastAPI:
    repository = BenchmarkRepository(database_path or Path(os.getenv("DATABASE_PATH", "/data/benchmark.db")))
    app = FastAPI(title="Hybrid TLS Performance Lab", version="1.0.0")
    app.state.repository = repository
    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    @app.get("/healthz")
    def health() -> dict:
        return {"status": "ok", "database": str(repository.path)}

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, run_id: str | None = None):
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"title": "Performance Dashboard", "initial": repository.dashboard_data(run_id)},
        )

    @app.post("/api/runs", status_code=201)
    def create_run(payload: RunCreate) -> dict:
        repository.create_run(payload.model_dump())
        return {"ok": True, "run_id": payload.run_id}

    @app.post("/api/runs/{run_id}/complete")
    def complete_run(run_id: str) -> dict:
        repository.complete_run(run_id)
        return {"ok": True, "run_id": run_id}

    @app.post("/api/measurements/server", status_code=201)
    def server_measurement(payload: ServerMeasurement) -> dict:
        repository.record_server(payload.model_dump())
        return {"ok": True, "sample_id": payload.sample_id}

    @app.post("/api/measurements/client", status_code=201)
    def client_measurement(payload: ClientMeasurement) -> dict:
        repository.record_client(payload.model_dump())
        return {"ok": True, "sample_id": payload.sample_id}

    @app.get("/api/dashboard")
    def dashboard_data(run_id: str | None = Query(default=None)) -> JSONResponse:
        return JSONResponse(repository.dashboard_data(run_id))

    @app.get("/api/results.csv")
    def results_csv(run_id: str | None = Query(default=None)) -> Response:
        return Response(
            repository.csv_export(run_id),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="hybrid-tls-results.csv"'},
        )

    return app


app = create_app()
