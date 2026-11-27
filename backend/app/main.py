"""HTTP API and static dashboard.

There is no login in v0.1. The app is meant to be reachable from this computer only:
Compose publishes it on 127.0.0.1, the Host header is checked (DNS rebinding), and every
state-changing request must carry a custom header that a cross-site form cannot send (CSRF).
"""

import hashlib
import json
import re
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload, selectinload, sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .ai import AiProviderError, TriageError, get_provider, run_triage
from .config import Settings
from .db import Base, make_engine
from .enrichment import IntelError, refresh_intel
from .importer import DuplicateScanError, import_scan
from .models import STATUS_FIXED, STATUS_OPEN, AiTriage, CveIntel, Finding, FindingCve, Host, Scan
from .parsers import NessusParser, ScanParseError
from .risk import SEVERITY_LABELS, recompute_risk, score_finding

STATIC_DIR = Path(__file__).parent / "static"
UPLOAD_PATH = "/api/scans"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "vulndash"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._ ()-]")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class HostUpdate(BaseModel):
    criticality: int = Field(ge=1, le=5)


def get_db(request: Request):
    db: Session = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def _now() -> datetime:
    # Scan times in a .nessus file are scanner-local and carry no zone, so the app
    # works in naive local time throughout.
    return datetime.now()  # noqa: DTZ005


def _age_days(finding: Finding, now: datetime) -> int:
    end = finding.fixed_at if finding.status == STATUS_FIXED and finding.fixed_at else now
    return max(0, (end - finding.first_seen).days)


def _finding_row(finding: Finding, now: datetime) -> dict:
    return {
        "id": finding.id,
        "host": {
            "id": finding.host.id,
            "ip": finding.host.ip,
            "hostname": finding.host.hostname,
        },
        "plugin_id": finding.plugin_id,
        "plugin_name": finding.plugin_name,
        "severity": finding.severity,
        "severity_label": SEVERITY_LABELS.get(finding.severity, "Unknown"),
        "port": finding.port,
        "protocol": finding.protocol,
        "service": finding.service,
        "cvss_base": finding.cvss_base,
        "risk_score": finding.risk_score,
        "epss": finding.epss,
        "in_kev": finding.in_kev,
        "kev_due_date": finding.kev_due_date,
        "exploit_available": finding.exploit_available,
        "cves": [c.cve_id for c in finding.cves],
        "status": finding.status,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "fixed_at": finding.fixed_at,
        "age_days": _age_days(finding, now),
    }


def _triage_row(triage: AiTriage | None) -> dict | None:
    if triage is None:
        return None
    return {
        "provider": triage.provider,
        "model": triage.model,
        "created_at": triage.created_at,
        "result": json.loads(triage.result_json),
    }


def _latest_triage(db: Session, finding_id: int) -> AiTriage | None:
    return db.scalar(
        select(AiTriage)
        .where(AiTriage.finding_id == finding_id)
        .order_by(AiTriage.created_at.desc(), AiTriage.id.desc())
        .limit(1)
    )


def _get_finding(db: Session, finding_id: int) -> Finding:
    finding = db.scalar(
        select(Finding)
        .where(Finding.id == finding_id)
        .options(joinedload(Finding.host), selectinload(Finding.cves))
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding


def _scan_row(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "source": scan.source,
        "filename": scan.filename,
        "report_name": scan.report_name,
        "scan_time": scan.scan_time,
        "imported_at": scan.imported_at,
        "host_count": scan.host_count,
        "item_count": scan.item_count,
        "new": scan.new_count,
        "fixed": scan.fixed_count,
        "reopened": scan.reopened_count,
        "open": {
            "critical": scan.open_critical,
            "high": scan.open_high,
            "medium": scan.open_medium,
            "low": scan.open_low,
        },
    }


api = APIRouter(prefix="/api")


@api.get("/summary")
def summary(request: Request, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    now = _now()
    counts = dict(
        db.execute(
            select(Finding.severity, func.count())
            .where(Finding.status == STATUS_OPEN)
            .group_by(Finding.severity)
        ).all()
    )
    open_actionable = (Finding.status == STATUS_OPEN) & (Finding.severity > 0)
    oldest = db.scalar(
        select(func.min(Finding.first_seen)).where(
            Finding.status == STATUS_OPEN, Finding.severity >= 3
        )
    )
    last_scan = db.scalar(select(Scan).order_by(Scan.scan_time.desc(), Scan.id.desc()).limit(1))
    provider = get_provider(request.app.state.settings)
    return {
        "version": __version__,
        "open": {
            "critical": counts.get(4, 0),
            "high": counts.get(3, 0),
            "medium": counts.get(2, 0),
            "low": counts.get(1, 0),
            "info": counts.get(0, 0),
        },
        "hosts": db.scalar(select(func.count()).select_from(Host)) or 0,
        "kev_open": db.scalar(
            select(func.count()).select_from(Finding).where(open_actionable, Finding.in_kev)
        )
        or 0,
        "exploitable_open": db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(open_actionable, Finding.exploit_available)
        )
        or 0,
        "oldest_open_high_or_critical_days": (now - oldest).days if oldest else None,
        "last_scan": _scan_row(last_scan) if last_scan else None,
        "intel_updated_at": db.scalar(select(func.max(CveIntel.updated_at))),
        "ai": {
            "enabled": provider is not None,
            "provider": provider.name if provider else None,
            "model": provider.model if provider else None,
        },
    }


@api.get("/scans")
def list_scans(db: Session = Depends(get_db)) -> list[dict]:  # noqa: B008
    scans = db.scalars(select(Scan).order_by(Scan.scan_time.asc(), Scan.id.asc())).all()
    return [_scan_row(scan) for scan in scans]


@api.post("/scans", status_code=201)
def upload_scan(
    request: Request,
    file: UploadFile,
    db: Session = Depends(get_db),  # noqa: B008
) -> dict:
    settings: Settings = request.app.state.settings
    digest = hashlib.sha256()
    size = 0
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as buffer:
        while chunk := file.file.read(1024 * 1024):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"The file is larger than {settings.max_upload_mb} MB.",
                )
            digest.update(chunk)
            buffer.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="The file is empty.")
        buffer.seek(0)
        try:
            parsed = NessusParser().parse(buffer)
        except ScanParseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # The name is stored for display only. It is never used as a path.
    filename = FILENAME_SAFE.sub("_", Path(file.filename or "scan.nessus").name)[:255]
    try:
        result = import_scan(db, parsed, filename=filename, sha256=digest.hexdigest())
    except DuplicateScanError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _scan_row(result.scan)


@api.get("/hosts")
def list_hosts(db: Session = Depends(get_db)) -> list[dict]:  # noqa: B008
    counts: dict[int, dict[int, int]] = {}
    for host_id, severity, count in db.execute(
        select(Finding.host_id, Finding.severity, func.count())
        .where(Finding.status == STATUS_OPEN)
        .group_by(Finding.host_id, Finding.severity)
    ).all():
        counts.setdefault(host_id, {})[severity] = count
    max_risk = dict(
        db.execute(
            select(Finding.host_id, func.max(Finding.risk_score))
            .where(Finding.status == STATUS_OPEN)
            .group_by(Finding.host_id)
        ).all()
    )
    rows = []
    for host in db.scalars(select(Host)).all():
        by_severity = counts.get(host.id, {})
        rows.append(
            {
                "id": host.id,
                "ip": host.ip,
                "hostname": host.hostname,
                "fqdn": host.fqdn,
                "os": host.os,
                "criticality": host.criticality,
                "first_seen": host.first_seen,
                "last_seen": host.last_seen,
                "open": {
                    "critical": by_severity.get(4, 0),
                    "high": by_severity.get(3, 0),
                    "medium": by_severity.get(2, 0),
                    "low": by_severity.get(1, 0),
                },
                "max_risk": max_risk.get(host.id) or 0.0,
            }
        )
    rows.sort(key=lambda r: (-r["max_risk"], -r["open"]["critical"], -r["open"]["high"], r["ip"]))
    return rows


@api.patch("/hosts/{host_id}")
def update_host(
    host_id: int,
    body: HostUpdate,
    db: Session = Depends(get_db),  # noqa: B008
) -> dict:
    host = db.scalar(select(Host).where(Host.id == host_id).options(selectinload(Host.findings)))
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found.")
    host.criticality = body.criticality
    db.flush()
    findings = db.scalars(
        select(Finding)
        .where(Finding.host_id == host.id)
        .options(selectinload(Finding.cves), joinedload(Finding.host))
    ).all()
    recompute_risk(db, findings)
    db.commit()
    return {"id": host.id, "criticality": host.criticality, "findings_rescored": len(findings)}


@api.get("/findings")
def list_findings(
    db: Session = Depends(get_db),  # noqa: B008
    status: str = Query("open", pattern="^(open|fixed|all)$"),
    min_severity: int = Query(1, ge=0, le=4),
    host_id: int | None = None,
    kev_only: bool = False,
    q: str = Query("", max_length=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    conditions = [Finding.severity >= min_severity]
    if status != "all":
        conditions.append(Finding.status == status)
    if host_id is not None:
        conditions.append(Finding.host_id == host_id)
    if kev_only:
        conditions.append(Finding.in_kev)
    term = q.strip()
    if term:
        cve_match = select(FindingCve.finding_id).where(
            FindingCve.cve_id.icontains(term, autoescape=True)
        )
        conditions.append(
            Finding.plugin_name.icontains(term, autoescape=True) | Finding.id.in_(cve_match)
        )

    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
    findings = db.scalars(
        select(Finding)
        .where(*conditions)
        .options(joinedload(Finding.host), selectinload(Finding.cves))
        .order_by(
            Finding.risk_score.desc(),
            Finding.severity.desc(),
            Finding.first_seen.asc(),
            Finding.id.asc(),
        )
        .limit(limit)
        .offset(offset)
    ).all()
    now = _now()
    return {"total": total, "items": [_finding_row(f, now) for f in findings]}


@api.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    finding = _get_finding(db, finding_id)
    row = _finding_row(finding, _now())
    row.update(
        {
            "plugin_family": finding.plugin_family,
            "cvss_vector": finding.cvss_vector,
            "synopsis": finding.synopsis,
            "description": finding.description,
            "solution": finding.solution,
            "plugin_output": finding.plugin_output,
            "host": {
                "id": finding.host.id,
                "ip": finding.host.ip,
                "hostname": finding.host.hostname,
                "os": finding.host.os,
                "criticality": finding.host.criticality,
            },
            "risk_breakdown": score_finding(
                finding.severity,
                finding.cvss_base,
                finding.epss,
                finding.in_kev,
                finding.host.criticality,
            ).as_dict(),
            "triage": _triage_row(_latest_triage(db, finding.id)),
        }
    )
    return row


@api.post("/findings/{finding_id}/triage")
def triage_finding(
    finding_id: int,
    request: Request,
    refresh: bool = False,
    db: Session = Depends(get_db),  # noqa: B008
) -> dict:
    finding = _get_finding(db, finding_id)
    if not refresh:
        cached = _latest_triage(db, finding.id)
        if cached is not None:
            return _triage_row(cached)  # type: ignore[return-value]

    provider = getattr(request.app.state, "ai_provider", None) or get_provider(
        request.app.state.settings
    )
    if provider is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "AI triage is switched off. Set AI_PROVIDER=ollama and OLLAMA_MODEL in .env, "
                "then restart."
            ),
        )
    try:
        result, digest = run_triage(finding, provider)
    except (AiProviderError, TriageError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    triage = AiTriage(
        finding_id=finding.id,
        provider=provider.name,
        model=provider.model,
        created_at=_now(),
        prompt_sha256=digest,
        result_json=json.dumps(result),
    )
    db.add(triage)
    db.commit()
    return _triage_row(triage)  # type: ignore[return-value]


@api.post("/intel/refresh")
def refresh_threat_intel(request: Request, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    client = getattr(request.app.state, "intel_client", None)
    try:
        return refresh_intel(db, request.app.state.settings, client)
    except IntelError as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = make_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        Base.metadata.create_all(engine)
        yield
        engine.dispose()

    app = FastAPI(
        title="HomeLab Vuln Dashboard",
        version=__version__,
        lifespan=lifespan,
        # The interactive docs page loads its scripts from a public CDN, so it is opt-in.
        # With it off, the dashboard makes no third-party requests at all.
        docs_url="/api/docs" if settings.enable_api_docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method in UNSAFE_METHODS:
            if request.headers.get(CSRF_HEADER, "").lower() != CSRF_VALUE:
                return JSONResponse(
                    {"detail": f"Missing header X-Requested-With: {CSRF_VALUE}."},
                    status_code=403,
                )
            if request.url.path == UPLOAD_PATH:
                # Reject oversized uploads before the body is read.
                length = request.headers.get("content-length", "")
                if not length.isdigit():
                    return JSONResponse({"detail": "Content-Length is required."}, status_code=411)
                if int(length) > settings.max_upload_bytes + 64 * 1024:
                    return JSONResponse(
                        {"detail": f"The file is larger than {settings.max_upload_mb} MB."},
                        status_code=413,
                    )
        response = await call_next(request)
        if not request.url.path.startswith("/api/docs"):
            for name, value in SECURITY_HEADERS.items():
                response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    app.include_router(api)
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="dashboard")
    return app
