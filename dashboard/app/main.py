from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import BenchmarkRepository
from .qvi import load_targets, qvi_summary
from .score import load_scored, score_summary
from .cbom import build_cbom
from .hndl import load_hndl_inputs, build_exposure, exposure_summary
from .compliance import compute_compliance, compliance_summary
from .roadmap import build_roadmap
from .schemas import ClientMeasurement, RunCreate, ServerMeasurement


BASE_DIR = Path(__file__).resolve().parent


def create_app(database_path: Path | None = None) -> FastAPI:
    repository = BenchmarkRepository(database_path or Path(os.getenv("DATABASE_PATH", "/data/benchmark.db")))
    app = FastAPI(title="Hybrid TLS Performance Lab", version="1.0.0")
    app.state.repository = repository
    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    def _page_context(request: Request, run_id: str | None, active_nav: str) -> dict:
        targets = load_targets()
        return {
            "request": request,
            "active_nav": active_nav,
            "initial": repository.dashboard_data(run_id),
            "targets": targets,
            "qvi": qvi_summary(targets),
        }

    # ---- health ----
    @app.get("/healthz")
    def health() -> dict:
        return {"status": "ok", "database": str(repository.path)}

    # ---- sidebar pages ----
    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request, run_id: str | None = None):
        return templates.TemplateResponse(
            request=request,
            name="overview.html",
            context={"title": "Overview", **_page_context(request, run_id, "overview")},
        )

    @app.get("/scanner", response_class=HTMLResponse)
    def scanner(request: Request, run_id: str | None = None):
        return templates.TemplateResponse(
            request=request,
            name="scanner.html",
            context={"title": "Scanner", **_page_context(request, run_id, "scanner")},
        )

    @app.get("/benchmark", response_class=HTMLResponse)
    def benchmark(request: Request, run_id: str | None = None):
        return templates.TemplateResponse(
            request=request,
            name="benchmark.html",
            context={"title": "Crypto Engine", **_page_context(request, run_id, "benchmark")},
        )

    @app.get("/score", response_class=HTMLResponse)
    def score_page(request: Request, run_id: str | None = None, view: str | None = None):
        rows = load_scored()
        if view == "queue":
            rows = sorted(rows, key=lambda r: -r["ratio"])
        return templates.TemplateResponse(
            request=request,
            name="score.html",
            context={**_page_context(request, run_id, "remediation" if view == "queue" else "score"),
                     "title": "Remediation Queue" if view == "queue" else "Quantum Risk Score", "targets": rows,
                     "s": score_summary(rows), "view": view},
        )


    @app.get("/migration-cost", response_class=HTMLResponse)
    def migration_cost_page(request: Request, run_id: str | None = None):
        return templates.TemplateResponse(
            request=request,
            name="migration_cost.html",
            context={**_page_context(request, run_id, "migration"),
                     "title": "Migration Cost"},
        )

    @app.get("/docs", response_class=HTMLResponse)
    def docs(request: Request, run_id: str | None = None):
        return templates.TemplateResponse(
            request=request,
            name="docs.html",
            context={"title": "Docs", **_page_context(request, run_id, "docs")},
        )

    @app.get("/hndl", response_class=HTMLResponse)
    def hndl_page(request: Request, run_id: str | None = None, scenario: str = "5y"):
        targets = load_targets()
        if scenario == "10y":
            hndl_csv = BASE_DIR / "data" / "hndl_inputs_10y.csv"
            hndl_inputs = load_hndl_inputs(hndl_csv)
            scenario_label = "Minimum regulatory floor (5y transaction & loan, 10y policy records)"
        else:
            hndl_inputs = load_hndl_inputs()
            scenario_label = "Institution-typical retention (8y transaction, 15y loan, 25y policy)"
        exposure_records = build_exposure(targets, hndl_inputs)
        return templates.TemplateResponse(
            request=request,
            name="hndl.html",
            context={
                "title": "HNDL Exposure",
                **_page_context(request, run_id, "hndl"),
                "exposure_records": exposure_records,
                "exposure": exposure_summary(exposure_records),
                "scenario": scenario,
                "scenario_label": scenario_label,
            },
        )

    @app.get("/compliance", response_class=HTMLResponse)
    def compliance_page(request: Request, run_id: str | None = None):
        targets = load_targets()
        compliance_results = compute_compliance(targets)
        return templates.TemplateResponse(
            request=request,
            name="compliance.html",
            context={
                "title": "Compliance",
                **_page_context(request, run_id, "compliance"),
                "compliance_results": compliance_results,
                "compliance": compliance_summary(compliance_results),
            },
        )

    @app.get("/roadmap", response_class=HTMLResponse)
    def roadmap_page(request: Request, run_id: str | None = None):
        targets = load_targets()
        exposure_records = build_exposure(targets)
        return templates.TemplateResponse(
            request=request,
            name="roadmap.html",
            context={
                "title": "Roadmap",
                **_page_context(request, run_id, "roadmap"),
                "roadmap": build_roadmap(exposure_records),
            },
        )

    # ---- CBOM JSON download ----
    @app.get("/api/cbom/{target_name}.json")
    def cbom_json(target_name: str) -> JSONResponse:
        targets = load_targets()
        match = next((t for t in targets if t["target"] == target_name), None)
        if match is None:
            raise HTTPException(status_code=404, detail=f"Unknown target: {target_name}")
        return JSONResponse(build_cbom(match))

    # ---- existing API, unchanged ----
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
