from pathlib import Path, PurePosixPath
from collections import deque
from threading import Lock
from time import monotonic
import logging
import os
import re

from fastapi import Depends, FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.auth import require_auth
from app.db import get_db
from app.models import UploadRecord
from app.scanner import scan_bytes

logger = logging.getLogger("sentinel")

app = FastAPI(title="Sentinel Upload API")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

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


@app.post("/upload")
async def upload(request: Request, file: UploadFile = File(...), _auth=Depends(require_auth)):
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

    scan = scan_bytes(filename, content)
    # Fail-closed: scanner errors are treated as rejected uploads.
    status = "accepted" if scan.status == "clean" else "rejected"

    if scan.status != "clean":
        logger.warning(
            "Upload rejected: file=%s scan_status=%s engine=%s detail=%s",
            filename, scan.status, scan.engine, scan.detail,
        )
    else:
        logger.info("Upload accepted: file=%s engine=%s", filename, scan.engine)

    record = UploadRecord(
        filename=filename,
        content_type=content_type,
        status=status,
        scan_status=scan.status,
        scan_engine=scan.engine,
        scan_detail=scan.detail,
    )

    db_status = "skipped"
    try:
        db = get_db()
        await db.uploads.insert_one(record.model_dump())
        db_status = "stored"
    except Exception:
        logger.exception("Failed to store upload record for %s", filename)
        db_status = "unavailable"

    return {
        "filename": filename,
        "content_type": content_type,
        "status": status,
        "scan_status": scan.status,
        "scan_engine": scan.engine,
        "scan_detail": scan.detail,
        "db_status": db_status,
    }


@app.get("/uploads")
async def list_uploads(limit: int = 50, _auth=Depends(require_auth)):
    try:
        db = get_db()
        cursor = db.uploads.find({}, {"_id": 0}).sort("_id", -1).limit(limit)
        items = [item async for item in cursor]
        return {"items": items}
    except Exception:
        logger.exception("Failed to list uploads from database")
        raise HTTPException(status_code=503, detail="Database unavailable")
