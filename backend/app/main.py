"""HTTP API and static dashboard.

There is no login. The app is meant to be reachable from this computer only: Compose
publishes it on 127.0.0.1, the Host header is checked (DNS rebinding), and every
state-changing request must carry a custom header that a cross-site form cannot send (CSRF).

Times are stored as naive UTC and sent to the browser with an explicit UTC offset.
"""

import asyncio
import gzip
import hashlib
import json
import logging
import re
import tempfile
from contextlib import asynccontextmanager, suppress
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload, selectinload, sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, history
from .ai import AiProviderError, TriageError, get_provider, run_triage
from .config import Settings
from .db import make_engine, upgrade_database, utcnow
from .enrichment import IntelError, refresh_intel
from .gmp import GmpError
from .importer import DuplicateScanError, import_scan
from .models import (
    STATUS_FIXED,
    STATUS_OPEN,
    AiTriage,
    CveIntel,
    Finding,
    FindingCve,
    Host,
    Scan,
    ScanArchive,
)
from .openvas import OpenVasError, OpenVasNotConfigured, OpenVasService, public_error
from .parsers import NessusHtmlParser, ScanParseError, parse_scan
from .risk import SEVERITY_LABELS, recompute_risk, score_finding

log = logging.getLogger("vulndash")

STATIC_DIR = Path(__file__).parent / "static"
UPLOAD_PATH = "/api/scans"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "vulndash"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._ ()-]")
SYNC_START_DELAY_SECONDS = 20

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


class NewScan(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    targets: str = Field(min_length=1, max_length=2000)
    consider_alive: bool = True
    repeat: Literal["none", "daily", "weekly"] = "none"
    start_at: datetime | None = None
    timezone: str = Field(default="UTC", max_length=64)


def get_db(request: Request):
    db: Session = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def aware(value):
    """Mark stored (naive UTC) datetimes as UTC so browsers show them in local time."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value
    if isinstance(value, date):
        return value
    if isinstance(value, dict):
        return {key: aware(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [aware(item) for item in value]
    return value


def _to_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value


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
        "source": finding.source,
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


def _brief_finding(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "plugin_name": finding.plugin_name,
        "severity": finding.severity,
        "risk_score": finding.risk_score,
        "status": finding.status,
        "port": finding.port,
        "protocol": finding.protocol,
        "host": {"id": finding.host.id, "ip": finding.host.ip, "hostname": finding.host.hostname},
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


def _scan_row(scan: Scan, point: dict | None = None, archived: bool = False) -> dict:
    stored_open = {
        "critical": scan.open_critical,
        "high": scan.open_high,
        "medium": scan.open_medium,
        "low": scan.open_low,
    }
    return {
        "id": scan.id,
        "source": scan.source,
        "origin": scan.origin,
        "filename": scan.filename,
        "report_name": scan.report_name,
        "task_name": scan.task_name,
        "external_id": scan.external_id,
        "scan_time": scan.scan_time,
        "imported_at": scan.imported_at,
        "host_count": scan.host_count,
        "item_count": scan.item_count,
        "new": scan.new_count,
        "fixed": scan.fixed_count,
        "reopened": scan.reopened_count,
        "open": point["open"] if point else stored_open,
        "risk_total": point.get("risk_total") if point else None,
        "kev_open": point.get("kev_open") if point else None,
        "has_history": scan.has_history,
        "archived": archived,
    }


def _openvas(request: Request) -> OpenVasService:
    return request.app.state.openvas


def _openvas_call(action):
    """Run an OpenVAS action and turn its failures into clear HTTP errors."""
    try:
        return action()
    except OpenVasNotConfigured as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OpenVasError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GmpError as exc:
        log.warning("OpenVAS request failed: %s", exc)
        raise HTTPException(status_code=502, detail=public_error(exc)) from exc


api = APIRouter(prefix="/api")


@api.get("/summary")
def summary(request: Request, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    now = utcnow()
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
    return aware(
        {
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
            "scan_count": db.scalar(select(func.count()).select_from(Scan)) or 0,
            "intel_updated_at": db.scalar(select(func.max(CveIntel.updated_at))),
            "ai": {
                "enabled": provider is not None,
                "provider": provider.name if provider else None,
                "model": provider.model if provider else None,
            },
            "openvas": {"configured": _openvas(request).configured},
        }
    )


@api.get("/scans")
def list_scans(db: Session = Depends(get_db)) -> list[dict]:  # noqa: B008
    points, _ = history.open_series(db)
    by_id = {p["id"]: p for p in points}
    archived = set(db.scalars(select(ScanArchive.scan_id)).all())
    scans = db.scalars(select(Scan).order_by(Scan.scan_time.asc(), Scan.id.asc())).all()
    return aware([_scan_row(s, by_id.get(s.id), s.id in archived) for s in scans])


@api.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    points, _ = history.open_series(db)
    point = next((p for p in points if p["id"] == scan_id), None)
    archived = db.scalar(select(ScanArchive.scan_id).where(ScanArchive.scan_id == scan_id))
    changes = history.scan_changes(db, scan_id)
    row = _scan_row(scan, point, archived is not None)

    def ordered(findings: list[Finding]) -> list[dict]:
        rows = [_brief_finding(f) for f in findings]
        return sorted(rows, key=lambda r: (-r["risk_score"], -r["severity"], r["plugin_name"]))

    row["changes"] = {kind: ordered(items) for kind, items in changes["groups"].items()}
    row["carried"] = ordered(changes["carried"])
    row["hosts"] = sorted(
        (
            {"id": h.id, "ip": h.ip, "hostname": h.hostname, "complete": bool(complete)}
            for h, complete in changes["hosts"]
        ),
        key=lambda r: r["ip"],
    )
    return aware(row)


@api.get("/scans/{scan_id}/report")
def download_report(scan_id: int, db: Session = Depends(get_db)) -> Response:  # noqa: B008
    archive = db.get(ScanArchive, scan_id)
    scan = db.get(Scan, scan_id)
    if archive is None or scan is None:
        raise HTTPException(status_code=404, detail="No original report is stored for this scan.")
    name = FILENAME_SAFE.sub("_", scan.filename) or f"scan-{scan_id}"
    # Sent as a plain download, never rendered: the report is untrusted content.
    return Response(
        content=gzip.decompress(archive.gzip_data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


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
            parsed = parse_scan(buffer, min_qod=settings.openvas_min_qod)
        except ScanParseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        buffer.seek(0)
        raw = buffer.read()
    media_type = "text/html" if NessusHtmlParser.looks_like(raw[:4096]) else "application/xml"

    # The name is stored for display only. It is never used as a path.
    filename = FILENAME_SAFE.sub("_", Path(file.filename or "scan.xml").name)[:255]
    try:
        result = import_scan(
            db,
            parsed,
            filename=filename,
            sha256=digest.hexdigest(),
            raw=raw,
            media_type=media_type,
        )
    except DuplicateScanError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return aware(_scan_row(result.scan, archived=True))


@api.get("/trends")
def get_trends(
    db: Session = Depends(get_db),  # noqa: B008
    days: int | None = Query(None, ge=1, le=3650),
) -> dict:
    return aware(history.trends(db, utcnow(), days))


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
    _, per_host = history.open_series(db)
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
                # Open findings after each of the last scans that covered this host.
                "history": [
                    {"scan_time": p["scan_time"], "total": sum(p["open"].values())}
                    for p in per_host.get(host.id, [])[-12:]
                ],
            }
        )
    rows.sort(key=lambda r: (-r["max_risk"], -r["open"]["critical"], -r["open"]["high"], r["ip"]))
    return aware(rows)


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
    now = utcnow()
    return aware({"total": total, "items": [_finding_row(f, now) for f in findings]})


@api.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    finding = _get_finding(db, finding_id)
    row = _finding_row(finding, utcnow())
    row.update(
        {
            "plugin_family": finding.plugin_family,
            "cvss_vector": finding.cvss_vector,
            "qod": finding.qod,
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
            "timeline": history.finding_timeline(db, finding.id),
        }
    )
    return aware(row)


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
            return aware(_triage_row(cached))

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
        created_at=utcnow(),
        prompt_sha256=digest,
        result_json=json.dumps(result),
    )
    db.add(triage)
    db.commit()
    return aware(_triage_row(triage))


@api.post("/intel/refresh")
def refresh_threat_intel(request: Request, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    client = getattr(request.app.state, "intel_client", None)
    try:
        return refresh_intel(db, request.app.state.settings, client)
    except IntelError as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------- OpenVAS ----------


@api.get("/openvas/status")
def openvas_status(request: Request) -> dict:
    return aware(_openvas(request).status())


@api.get("/openvas/tasks")
def openvas_tasks(request: Request, db: Session = Depends(get_db)) -> list[dict]:  # noqa: B008
    tasks = _openvas_call(_openvas(request).tasks)
    imported = {
        external_id
        for external_id in db.scalars(select(Scan.external_id).where(Scan.external_id.is_not(None)))
    }
    for task in tasks:
        task["last_report_imported"] = task["last_report_id"] in imported
    return aware(tasks)


@api.post("/openvas/tasks", status_code=201)
def openvas_create_scan(request: Request, body: NewScan) -> dict:
    service = _openvas(request)
    return aware(
        _openvas_call(
            lambda: service.create_scan(
                name=body.name,
                targets=body.targets,
                consider_alive=body.consider_alive,
                repeat=body.repeat,
                start_at=_to_utc(body.start_at),
                timezone=body.timezone,
            )
        )
    )


@api.post("/openvas/tasks/{task_id}/start", status_code=202)
def openvas_start_task(task_id: str, request: Request) -> dict:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", task_id):
        raise HTTPException(status_code=422, detail="Not a task ID.")
    report_id = _openvas_call(lambda: _openvas(request).start_task(task_id))
    return {"task_id": task_id, "report_id": report_id}


@api.post("/openvas/sync")
def openvas_sync(request: Request, db: Session = Depends(get_db)) -> dict:  # noqa: B008
    service = _openvas(request)
    if not service.configured:
        raise HTTPException(
            status_code=409,
            detail="OpenVAS is not connected. Import XML reports by hand, or start the "
            "dashboard with OpenVAS.",
        )
    try:
        outcome = service.run_sync(db)
    except OpenVasError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if outcome.get("error"):
        raise HTTPException(status_code=502, detail=outcome["error"])
    return aware(outcome)


# ---------- App ----------


def _sync_once(app: FastAPI) -> None:
    db = app.state.session_factory()
    try:
        outcome = app.state.openvas.run_sync(db)
        if outcome.get("imported"):
            log.info("OpenVAS sync imported %d report(s)", len(outcome["imported"]))
    except OpenVasError:
        pass  # a manual sync is already running
    except Exception:  # keep the loop alive whatever happens
        log.exception("OpenVAS sync failed")
    finally:
        db.close()


async def _sync_loop(app: FastAPI, minutes: int) -> None:
    await asyncio.sleep(SYNC_START_DELAY_SECONDS)
    while True:
        await asyncio.to_thread(_sync_once, app)
        await asyncio.sleep(minutes * 60)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = make_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        upgrade_database(engine)
        task = None
        if app.state.openvas.configured and settings.openvas_sync_minutes > 0:
            task = asyncio.create_task(_sync_loop(app, settings.openvas_sync_minutes))
        yield
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
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
    app.state.openvas = OpenVasService(settings)

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
