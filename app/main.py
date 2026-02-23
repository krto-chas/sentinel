from pathlib import Path, PurePosixPath
from collections import deque
from threading import Lock
from time import monotonic
from hashlib import sha256
from datetime import UTC, datetime, timedelta
import asyncio
import json
import logging
import os
import re
from urllib import request

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.db import get_db, ensure_upload_indexes
from app.models import UploadRecord
from app.scanner import scan_bytes
from app.routers import threats
from app.services.threat_intel import run_threat_intel_update_job, setup_database_indexes
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger("sentinel")

app = FastAPI(title="Sentinel Upload API")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.include_router(threats.router)

ALLOWED_CONTENT_TYPES = {
    # Text
    "text/plain",
    "text/markdown",
    "text/csv",
    # Images
    "image/png",
    "image/jpeg",
    # PDF
    "application/pdf",
    # Microsoft Office
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    # LibreOffice / OpenDocument
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
}

ALLOWED_EXTENSIONS: dict[str, set[str]] = {
    "text/plain": {".txt", ".text", ".log"},
    "text/markdown": {".md", ".markdown"},
    "text/csv": {".csv"},
    "image/png": {".png"},
    "image/jpeg": {".jpg", ".jpeg"},
    "application/pdf": {".pdf"},
    # Microsoft Office
    "application/msword": {".doc"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.ms-excel": {".xls"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "application/vnd.ms-powerpoint": {".ppt"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {".pptx"},
    # LibreOffice / OpenDocument
    "application/vnd.oasis.opendocument.text": {".odt"},
    "application/vnd.oasis.opendocument.spreadsheet": {".ods"},
    "application/vnd.oasis.opendocument.presentation": {".odp"},
}

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
MAX_FILENAME_LENGTH = 255
SAFE_FILENAME_RE = re.compile(r"^[\w\-. ]+$")


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except ValueError:
        return default


RATE_LIMIT_UPLOADS_PER_MINUTE = _env_int("UPLOAD_RATE_LIMIT_PER_MINUTE", 10)
RATE_LIMIT_WINDOW_SECONDS = _env_int("UPLOAD_RATE_LIMIT_WINDOW_SECONDS", 60)

_rate_limit_lock = Lock()
_upload_request_times: dict[str, deque[float]] = {}

DEFAULT_UPLOAD_LIST_LIMIT = _env_int("UPLOAD_LIST_LIMIT_DEFAULT", 25)
MAX_UPLOAD_LIST_LIMIT = _env_int("UPLOAD_LIST_LIMIT_MAX", 100)
CISA_KEV_URL = os.getenv(
    "CISA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
CISA_KEV_USER_AGENT = os.getenv(
    "CISA_KEV_USER_AGENT",
    "SentinelUploadAPI/1.0 (Sidestep Error; contact: sidestep@secion.se)",
)
CISA_KEV_TIMEOUT_SECONDS = float(os.getenv("CISA_KEV_TIMEOUT_SECONDS", "8"))
CISA_KEV_MIN_SECONDS_BETWEEN_CALLS = max(10, _env_int("CISA_KEV_MIN_SECONDS_BETWEEN_CALLS", 300))
CISA_KEV_CACHE_TTL_SECONDS = max(
    CISA_KEV_MIN_SECONDS_BETWEEN_CALLS, _env_int("CISA_KEV_CACHE_TTL_SECONDS", 300)
)
_kev_lock = Lock()
_kev_cached_payload: dict | None = None
_kev_cached_at_monotonic = 0.0
_kev_last_attempt_monotonic = 0.0


def enforce_upload_rate_limit(client_id: str):
    now = monotonic()
    with _rate_limit_lock:
        # Cleanup: remove entries for clients with no recent activity
        stale = [
            cid for cid, ts in _upload_request_times.items()
            if not ts or now - ts[-1] >= RATE_LIMIT_WINDOW_SECONDS
        ]
        for cid in stale:
            del _upload_request_times[cid]

        timestamps = _upload_request_times.setdefault(client_id, deque())
        while timestamps and now - timestamps[0] >= RATE_LIMIT_WINDOW_SECONDS:
            timestamps.popleft()

        if len(timestamps) >= RATE_LIMIT_UPLOADS_PER_MINUTE:
            logger.warning("Rate limit exceeded for client %s", client_id)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: max {RATE_LIMIT_UPLOADS_PER_MINUTE} uploads per minute",
            )

        timestamps.append(now)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.on_event("startup")
async def startup():
    try:
        await ensure_upload_indexes()
    except Exception:
        # App should stay available even if DB indexes can't be ensured at startup.
        logger.exception("Failed to ensure MongoDB indexes on startup")
    
    # Start Threat Intel Scheduler
    try:
        setup_database_indexes()
        scheduler = BackgroundScheduler()
        scheduler.add_job(run_threat_intel_update_job, 'date') # Run immediately
        scheduler.add_job(run_threat_intel_update_job, 'interval', minutes=15)
        scheduler.start()
        app.state.scheduler = scheduler
    except Exception:
        logger.exception("Failed to initialize Threat Intel service")

@app.on_event("shutdown")
def shutdown():
    if hasattr(app.state, 'scheduler'):
        app.state.scheduler.shutdown()


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


def sanitize_filename(raw: str | None) -> str:
    """Validate and sanitize an uploaded filename."""
    if not raw:
        raise HTTPException(status_code=400, detail="Filename is required")

    # Strip path components (defence against path-traversal)
    name = PurePosixPath(raw).name
    # Also handle Windows-style backslash paths
    name = name.split("\\")[-1]

    if not name or name in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    if len(name) > MAX_FILENAME_LENGTH:
        raise HTTPException(status_code=400, detail="Filename too long")

    if not SAFE_FILENAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail="Filename contains invalid characters",
        )

    return name


def validate_content_type(filename: str, claimed_type: str | None) -> str:
    """Verify that the claimed content-type matches the file extension."""
    if claimed_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=415, detail="Unsupported file type")

    ext = PurePosixPath(filename).suffix.lower()
    allowed_exts = ALLOWED_EXTENSIONS.get(claimed_type, set())
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=415,
            detail=f"File extension '{ext}' does not match content type '{claimed_type}'",
        )

    return claimed_type


def compute_risk(
    filename: str,
    content: bytes,
    scan_status: str,
    scan_engine: str,
    scan_detail: str,
) -> tuple[int, str, list[str]]:
    score = 0
    reasons: list[str] = []

    lowered = filename.lower()
    if scan_status == "malicious":
        score = 100
        reasons.append("Malicious signature or pattern detected")
    elif scan_status == "error":
        score = 80
        reasons.append("Scanner error (fail-closed policy)")
    else:
        score = 10
        reasons.append("No malicious signature detected")

    if "fallback: ClamAV unavailable" in scan_detail:
        score = max(score, 25)
        reasons.append("Fallback scanner used because ClamAV was unavailable")

    if any(token in lowered for token in ("eicar", "malicious", "payload", "shell")):
        score = max(score, 70)
        reasons.append("Suspicious filename pattern")

    if len(content) >= 5 * 1024 * 1024:
        score = min(100, score + 5)
        reasons.append("Large file size raises inspection risk")

    if scan_engine == "mock" and scan_status == "clean":
        reasons.append("Mock engine result should be treated as lower confidence")

    if score >= 70:
        decision = "rejected"
    elif score >= 30:
        decision = "review"
    else:
        decision = "accepted"

    return score, decision, reasons


def _record_timestamp(record: dict) -> datetime | None:
    created_at = record.get("created_at")
    if isinstance(created_at, datetime):
        return created_at if created_at.tzinfo else created_at.replace(tzinfo=UTC)

    object_id = record.get("_id")
    generation_time = getattr(object_id, "generation_time", None)
    if isinstance(generation_time, datetime):
        return generation_time if generation_time.tzinfo else generation_time.replace(tzinfo=UTC)

    return None


def _build_summary(items: list[dict]) -> dict:
    now = datetime.now(UTC)
    window_24h = now - timedelta(hours=24)
    window_7d = now - timedelta(days=7)

    def summarize(records: list[dict]) -> dict:
        total = len(records)
        accepted = sum(1 for item in records if item.get("status") == "accepted")
        rejected = sum(1 for item in records if item.get("status") == "rejected")
        review = sum(1 for item in records if item.get("decision") == "review")
        deduplicated = sum(1 for item in records if item.get("deduplicated") is True)
        avg_risk = (
            round(sum(int(item.get("risk_score", 0)) for item in records) / total, 1)
            if total else 0.0
        )
        rejection_rate = round((rejected / total) * 100, 1) if total else 0.0
        return {
            "total_uploads": total,
            "accepted": accepted,
            "rejected": rejected,
            "review": review,
            "deduplicated": deduplicated,
            "avg_risk_score": avg_risk,
            "rejection_rate_percent": rejection_rate,
        }

    oldest = datetime.min.replace(tzinfo=UTC)
    items_24h = [
        item for item in items
        if (_record_timestamp(item) or oldest) >= window_24h
    ]
    items_7d = [
        item for item in items
        if (_record_timestamp(item) or oldest) >= window_7d
    ]

    top_types: dict[str, int] = {}
    for item in items_7d:
        ctype = item.get("content_type") or "unknown"
        top_types[ctype] = top_types.get(ctype, 0) + 1
    top_content_types = sorted(
        [{"content_type": k, "count": v} for k, v in top_types.items()],
        key=lambda row: row["count"],
        reverse=True,
    )[:3]

    return {
        "last_24h": summarize(items_24h),
        "last_7d": summarize(items_7d),
        "all_time": summarize(items),
        "top_content_types_7d": top_content_types,
    }


def _parse_kev_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def _fetch_kev_summary_remote() -> dict:
    req = request.Request(
        CISA_KEV_URL,
        headers={
            "User-Agent": CISA_KEV_USER_AGENT,
            "Accept": "application/json",
        },
    )
    with request.urlopen(req, timeout=CISA_KEV_TIMEOUT_SECONDS) as response:
        payload = response.read().decode("utf-8")
    data = json.loads(payload)
    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("Unexpected CISA KEV response shape")

    now = datetime.now(UTC)
    cutoff_30d = now - timedelta(days=30)
    normalized = []
    for item in vulnerabilities:
        normalized.append(
            {
                "cve": item.get("cveID", ""),
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "date_added": item.get("dateAdded", ""),
                "description": item.get("shortDescription", ""),
                "ransomware_use": item.get("knownRansomwareCampaignUse", ""),
            }
        )

    normalized.sort(key=lambda row: row["date_added"], reverse=True)
    added_last_30d = sum(
        1
        for item in vulnerabilities
        if (_parse_kev_date(item.get("dateAdded")) or datetime.min.replace(tzinfo=UTC)) >= cutoff_30d
    )

    return {
        "source": "CISA KEV",
        "fetched_at": now.isoformat(),
        "total_known_exploited_cves": len(vulnerabilities),
        "added_last_30_days": added_last_30d,
        "latest": normalized[:8],
    }


@app.post("/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    client_ip = request.client.host if request.client else "unknown"
    enforce_upload_rate_limit(client_ip)

    filename = sanitize_filename(file.filename)
    content_type = validate_content_type(filename, file.content_type)

    # Early rejection based on Content-Length header (before reading body)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    # Read with a limit to avoid unbounded memory usage
    content = await file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    file_sha256 = sha256(content).hexdigest()

    db = None
    try:
        db = get_db()
        existing = await db.uploads.find_one(
            {"sha256": file_sha256},
            {
                "_id": 0,
                "scan_status": 1,
                "scan_engine": 1,
                "scan_detail": 1,
                "risk_score": 1,
                "decision": 1,
                "status": 1,
                "risk_reasons": 1,
            },
        )
        if existing:
            dedup_record = UploadRecord(
                filename=filename,
                sha256=file_sha256,
                content_type=content_type,
                status=existing.get("status", "accepted"),
                decision=existing.get("decision", "accepted"),
                risk_score=int(existing.get("risk_score", 0)),
                risk_reasons=existing.get("risk_reasons", ["Matched previous file hash"]),
                scan_status=existing.get("scan_status", "clean"),
                scan_engine=existing.get("scan_engine", "unknown"),
                scan_detail=existing.get("scan_detail", "Matched previous file hash"),
                deduplicated=True,
            )
            await db.uploads.insert_one(dedup_record.model_dump())
            return {
                "filename": filename,
                "sha256": file_sha256,
                "content_type": content_type,
                "status": dedup_record.status,
                "decision": dedup_record.decision,
                "risk_score": dedup_record.risk_score,
                "risk_reasons": dedup_record.risk_reasons,
                "scan_status": dedup_record.scan_status,
                "scan_engine": dedup_record.scan_engine,
                "scan_detail": dedup_record.scan_detail,
                "deduplicated": True,
                "db_status": "stored",
            }
    except Exception:
        logger.exception("Failed to check deduplication for %s", filename)
        db = None

    scan = scan_bytes(filename, content)
    risk_score, decision, risk_reasons = compute_risk(
        filename=filename,
        content=content,
        scan_status=scan.status,
        scan_engine=scan.engine,
        scan_detail=scan.detail,
    )
    # Keep fail-closed status behavior for compatibility with existing clients.
    status = "accepted" if scan.status == "clean" else "rejected"

    if scan.status != "clean":
        logger.warning(
            "Upload rejected: file=%s scan_status=%s engine=%s score=%s decision=%s detail=%s",
            filename, scan.status, scan.engine, risk_score, decision, scan.detail,
        )
    else:
        logger.info(
            "Upload accepted: file=%s engine=%s score=%s decision=%s",
            filename, scan.engine, risk_score, decision,
        )

    record = UploadRecord(
        filename=filename,
        sha256=file_sha256,
        content_type=content_type,
        status=status,
        decision=decision,
        risk_score=risk_score,
        risk_reasons=risk_reasons,
        scan_status=scan.status,
        scan_engine=scan.engine,
        scan_detail=scan.detail,
        deduplicated=False,
    )

    db_status = "skipped"
    try:
        if db is None:
            db = get_db()
        await db.uploads.insert_one(record.model_dump())
        db_status = "stored"
    except Exception:
        logger.exception("Failed to store upload record for %s", filename)
        db_status = "unavailable"

    return {
        "filename": filename,
        "sha256": file_sha256,
        "content_type": content_type,
        "status": status,
        "decision": decision,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "scan_status": scan.status,
        "scan_engine": scan.engine,
        "scan_detail": scan.detail,
        "deduplicated": False,
        "db_status": db_status,
    }


@app.get("/uploads")
async def list_uploads(limit: int = DEFAULT_UPLOAD_LIST_LIMIT):
    try:
        safe_limit = max(1, min(limit, MAX_UPLOAD_LIST_LIMIT))
        db = get_db()
        cursor = db.uploads.find({}, {"_id": 0}).sort("_id", -1).limit(safe_limit)
        items = [item async for item in cursor]
        return {"items": items}
    except Exception:
        logger.exception("Failed to list uploads from database")
        raise HTTPException(status_code=503, detail="Database unavailable")


@app.get("/metrics/summary")
async def metrics_summary(limit: int = 1000):
    try:
        db = get_db()
        cursor = db.uploads.find(
            {},
            {
                "_id": 1,
                "created_at": 1,
                "status": 1,
                "decision": 1,
                "deduplicated": 1,
                "risk_score": 1,
                "content_type": 1,
            },
        ).sort("_id", -1).limit(limit)
        items = [item async for item in cursor]
        return _build_summary(items)
    except Exception:
        logger.exception("Failed to build metrics summary")
        raise HTTPException(status_code=503, detail="Database unavailable")


@app.get("/external/threats/kev-summary")
async def kev_summary():
    global _kev_last_attempt_monotonic, _kev_cached_payload, _kev_cached_at_monotonic
    now = monotonic()
    with _kev_lock:
        cached = _kev_cached_payload
        is_fresh = cached and (now - _kev_cached_at_monotonic) <= CISA_KEV_CACHE_TTL_SECONDS
        should_wait = (now - _kev_last_attempt_monotonic) < CISA_KEV_MIN_SECONDS_BETWEEN_CALLS
        if is_fresh or (should_wait and cached):
            return cached
        _kev_last_attempt_monotonic = now

    try:
        payload = await asyncio.to_thread(_fetch_kev_summary_remote)
        with _kev_lock:
            _kev_cached_payload = payload
            _kev_cached_at_monotonic = monotonic()
        return payload
    except Exception:
        logger.exception("Failed to fetch CISA KEV summary")
        with _kev_lock:
            cached = _kev_cached_payload
        if cached:
            fallback = dict(cached)
            fallback["warning"] = "CISA KEV unavailable; serving cached data"
            return fallback
        raise HTTPException(status_code=503, detail="CISA KEV unavailable")
