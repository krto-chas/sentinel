from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.db import get_db
from app.models import UploadRecord

app = FastAPI(title="Sentinel Upload API")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

ALLOWED_CONTENT_TYPES = {
    "text/plain",
    "text/markdown",
    "application/pdf",
    "image/png",
    "image/jpeg",
}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=415, detail="Unsupported file type")

    record = UploadRecord(
        filename=file.filename,
        content_type=file.content_type,
        status="accepted",
    )

    db_status = "skipped"
    try:
        db = get_db()
        await db.uploads.insert_one(record.model_dump())
        db_status = "stored"
    except Exception:
        # Allow uploads even if DB is not configured or available.
        db_status = "unavailable"

    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "status": "accepted",
        "db_status": db_status,
    }


@app.get("/uploads")
async def list_uploads(limit: int = 50):
    try:
        db = get_db()
        cursor = db.uploads.find({}, {"_id": 0}).sort("_id", -1).limit(limit)
        items = [item async for item in cursor]
        return {"items": items}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")
