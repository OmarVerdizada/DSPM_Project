from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig
from risk.risk_engine import get_risk_rules
from scripts.report import generate_report

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="DSPM DLP Discovery API",
    description="Discovers sensitive data on AD file servers and produces DLP-ready risk context.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


class ConnectionRequest(BaseModel):
    server: str = Field(default="", description="AD file server hostname or IP")
    username: str = ""
    password: str = ""
    domain: str = "WORKGROUP"
    local_path: str = "test_data"
    max_depth: int = Field(default=4, ge=1, le=12)


class AssetOverride(BaseModel):
    pattern: str = Field(description="Customer-specific asset name, folder, extension, or path fragment")
    level: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    reason: str = ""


class ScanRequest(ConnectionRequest):
    save_report: bool = True
    asset_overrides: list[AssetOverride] = Field(default_factory=list)


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "dspm-discovery"}


@app.get("/api/risk-rules")
def risk_rules() -> dict:
    return {"rules": get_risk_rules()}


@app.post("/api/test-connection")
def test_connection(payload: ConnectionRequest) -> dict:
    engine = DSPMDiscoveryEngine(_to_config(payload))
    return engine.test_connection()


@app.post("/api/scan")
def scan(payload: ScanRequest) -> dict:
    engine = DSPMDiscoveryEngine(_to_config(payload))
    report = engine.run()
    data = report.to_dict()

    if payload.save_report:
        generate_report(data, BASE_DIR / "report.json")

    return data


def _to_config(payload: ConnectionRequest) -> ScanConfig:
    return ScanConfig(
        server=payload.server.strip(),
        username=payload.username.strip(),
        password=payload.password,
        domain=payload.domain.strip() or "WORKGROUP",
        local_path=payload.local_path.strip() or "test_data",
        max_depth=payload.max_depth,
        asset_overrides=[
            {
                "pattern": item.pattern.strip(),
                "level": item.level.strip().upper(),
                "reason": item.reason.strip(),
            }
            for item in getattr(payload, "asset_overrides", [])
            if item.pattern.strip()
        ],
    )
